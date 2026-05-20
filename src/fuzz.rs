//! Fuzz mode — host × wordlist Cartesian probe.
//!
//! Triggered when the user passes `-path / --paths <wordlist>` on the CLI.
//! Architecture:
//!
//! 1. Per-host pre-flight probe (random 32-hex path) → fingerprint stored in
//!    a `WildcardMap`. Subsequent fuzz hits matching the same fingerprint
//!    are flagged `is_wildcard:true` and (under `strict` policy) suppressed.
//! 2. Fan out the (host × path) Cartesian product to a bounded pool of
//!    workers (`Semaphore(threads)`).
//! 3. Each worker:
//!      - acquires a per-host rate-limit slot (no-op when `--rate-limit 0`)
//!      - picks a wreq pool slot (real-browser TLS + matching UA family)
//!      - issues a single GET with `redirect::Policy::none()` — 3xx is a
//!        finding, not something to chase
//!      - reads ≤256 KB body, extracts title, computes snippet_md5 of body[:200]
//!      - applies wildcard suppression + status-code match-filter
//!      - writes one `FuzzRecord` JSONL line
//!
//! The wreq client pool is REUSED from enrich mode (`probe::init_pool`) — no
//! second client is spun up. The `.redirect(Policy::none())` per-request
//! override on `RequestBuilder` keeps enrich-mode's hop-chasing semantics
//! untouched.

use anyhow::{Context, Result};
use chrono::SecondsFormat;
use futures::stream::{FuturesUnordered, StreamExt};
use md5::{Digest, Md5};
use serde::Serialize;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use wreq::redirect::Policy;

use crate::probe;
use crate::wildcard::{WildcardMap, WildcardSig};

/// Max bytes read from the wire per fuzz probe. Same cap as retroh4ck-prober
/// v0.1.0 — keeps memory bounded under high concurrency on misbehaving
/// targets that stream giant 200s.
const BODY_READ_CAP: usize = 256 * 1024;

/// Max title text length (chars, not bytes). Matches retroh4ck-prober v0.1.0
/// SPEC §"Title field" — keeps long pages from blowing the JSONL line size.
const TITLE_MAX_CHARS: usize = 300;

/// Title regex is run against at most this many bytes of the body — plenty
/// for any sane `<title>` and keeps the per-probe parse cost bounded.
const TITLE_SCAN_CAP: usize = 64 * 1024;

/// Pre-built prober tag (`"httpxer/0.3.0"` etc.). Embedded once at compile
/// time so the output schema's `prober` field doesn't require an env lookup
/// on every record.
const PROBER_TAG: &str = concat!("httpxer/", env!("CARGO_PKG_VERSION"));

/// JSONL record emitted by fuzz mode. Field names + order match
/// retroh4ck-prober v0.1.0 output so existing downstream parsers continue
/// to work without modification.
///
/// Loadbearing field rules (from SPEC §"Output JSONL — must match httpx exactly"):
///   - `status_code` (NOT `status`) — int
///   - `content_type` (NOT `mime`)
///   - `body_preview` — HTML-entity-encoded (so `html.unescape()` round-trips
///     downstream regex matching)
///   - `webserver` AND `server` both present — ProjectDiscovery httpx emits
///     both keys; some consumers read one, some the other
#[derive(Debug, Serialize)]
struct FuzzRecord {
    url: String,
    input: String,
    path: String,
    host: String,
    status_code: u16,
    content_length: i64,
    content_type: String,
    title: String,
    location: String,
    server: String,
    webserver: String,
    body_preview: String,
    tech: Vec<String>,
    method: &'static str,
    is_wildcard: bool,
    wildcard_policy: String,
    via_proxy: bool,
    attempts: u32,
    elapsed_ms: u64,
    snippet_md5: String,
    tls_impersonation: String,
    user_agent: String,
    cf_challenge: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    timestamp: String,
    prober: &'static str,
}

/// Per-(host,path) work item.
struct ProbeItem {
    host_input: String, // e.g. "https://target.com" or "target.com"
    host: String,       // bare hostname, used as the WildcardMap key
    path: String,
}

/// All fuzz-mode configuration unfurled from CLI flags.
///
/// `wildcard_policy` and `timeout_ms` are kept in this struct (rather than
/// inlined at the call site) so future extensions to fuzz mode have a
/// single place to plug new knobs. They are intentionally not read in the
/// current call path — `wildcard_policy` is passed separately to `run()`
/// for clearer ownership, and `timeout_ms` is baked into the wreq pool
/// before this struct is constructed.
#[allow(dead_code)]
pub struct FuzzCfg {
    pub match_codes: Vec<u16>,
    pub body_preview_bytes: usize,
    pub wildcard_policy: WildcardPolicy,
    pub include_errors: bool,
    pub retries: u32,
    pub via_proxy: bool, // true iff --proxy was set
    pub threads: usize,
    pub timeout_ms: u64,
    pub rate_limit_rps: f64,
}

/// Wildcard-handling policy. `strict` (default) suppresses any record whose
/// `(content_length, content_type, snippet_md5)` matches the per-host
/// wildcard fingerprint. `mark` emits the record but tags `is_wildcard:true`
/// so a downstream filter can drop or keep it. `off` skips wildcard
/// pre-flight entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WildcardPolicy {
    Strict,
    Mark,
    Off,
}

impl WildcardPolicy {
    pub fn from_cli(s: &str, no_wildcard: bool) -> Result<Self> {
        if no_wildcard {
            return Ok(WildcardPolicy::Off);
        }
        match s.to_ascii_lowercase().as_str() {
            "strict" => Ok(WildcardPolicy::Strict),
            "mark" => Ok(WildcardPolicy::Mark),
            "off" => Ok(WildcardPolicy::Off),
            other => anyhow::bail!(
                "invalid --wildcard-policy '{}' (want strict|mark|off)",
                other
            ),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            WildcardPolicy::Strict => "strict",
            WildcardPolicy::Mark => "mark",
            WildcardPolicy::Off => "off",
        }
    }
}

/// Read a path-wordlist file. Empty / commented lines dropped. Each entry
/// normalised to a leading-slash form so `"admin"` becomes `"/admin"` and
/// `"//admin"` collapses to `"/admin"`.
pub fn read_words(path: &str) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let f = std::fs::File::open(path).with_context(|| format!("open wordlist {}", path))?;
    for line in BufReader::new(f).lines().flatten() {
        let normalised = normalize_path(&line);
        if normalised.is_empty() || normalised == "/" {
            // skip blank / pure-slash entries; the wildcard probe owns "/"
            continue;
        }
        if seen.insert(normalised.clone()) {
            out.push(normalised);
        }
    }
    if out.is_empty() {
        anyhow::bail!("wordlist {} produced zero usable entries", path);
    }
    Ok(out)
}

/// `"foo"` → `"/foo"`, `"//foo"` → `"/foo"`, `""` → `""`. Trims whitespace.
/// Donor logic — ported verbatim from retroh4ck-prober/src/util.rs so paths
/// produced by both binaries are byte-identical given the same wordlist.
fn normalize_path(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        return String::new();
    }
    if s.starts_with('#') {
        return String::new();
    }
    let bytes = s.as_bytes();
    if bytes[0] == b'/' {
        let mut i = 0usize;
        while i < bytes.len() && bytes[i] == b'/' {
            i += 1;
        }
        if i > 1 {
            return format!("/{}", &s[i..]);
        }
        s.to_string()
    } else {
        format!("/{}", s)
    }
}

/// Random hex path of length `n`, prefixed with `/`. Used by the wildcard
/// detector to ask the server "do you 200 for ANY path?".
fn random_hex_path(n: usize) -> String {
    let mut out = String::with_capacity(n + 1);
    out.push('/');
    for _ in 0..n {
        let nibble = fastrand::u8(0..16);
        let c = if nibble < 10 {
            (b'0' + nibble) as char
        } else {
            (b'a' + (nibble - 10)) as char
        };
        out.push(c);
    }
    out
}

/// HTML-entity-encode body preview the same way retroh4ck-prober v0.1.0 does.
/// Order matters — `&` must be replaced FIRST. Otherwise the entities we
/// introduce (`&#34;`, `&lt;`, `&gt;`) get their leading `&` re-encoded.
fn html_escape_body_preview(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            other => out.push(other),
        }
    }
    out
}

/// Squash internal whitespace into single spaces and trim ends, stopping
/// after `max_chars`. Donor logic — keeps title formatting stable.
fn squash_whitespace(input: &str, max_chars: usize) -> String {
    let trimmed = input.trim();
    let mut out = String::with_capacity(trimmed.len().min(max_chars * 4));
    let mut prev_space = false;
    let mut chars_emitted = 0usize;
    for ch in trimmed.chars() {
        if chars_emitted >= max_chars {
            break;
        }
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
                chars_emitted += 1;
            }
        } else {
            out.push(ch);
            prev_space = false;
            chars_emitted += 1;
        }
    }
    out
}

/// Case-insensitive `<title>` extraction, scans at most 64 KB, caps at 300
/// whitespace-squashed chars. Returns `""` when no title is found.
fn extract_title(body: &[u8]) -> String {
    let end = body.len().min(TITLE_SCAN_CAP);
    let text = String::from_utf8_lossy(&body[..end]);
    // Same regex as donor — `(?is)` for case-insensitive + dotall.
    use once_cell::sync::OnceCell;
    use regex::Regex;
    static RE: OnceCell<Regex> = OnceCell::new();
    let re = RE.get_or_init(|| Regex::new(r"(?is)<title[^>]*>([\s\S]*?)</title>").unwrap());
    if let Some(cap) = re.captures(&text) {
        if let Some(m) = cap.get(1) {
            return squash_whitespace(m.as_str(), TITLE_MAX_CHARS);
        }
    }
    String::new()
}

/// ISO-8601 UTC timestamp with millisecond precision, `Z` suffix. Matches
/// retroh4ck-prober v0.1.0's `chrono::Utc::now().to_rfc3339_opts(Millis, true)`.
fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Trim error strings to first 120 chars, replace newlines with spaces. Same
/// as donor's `util::short_err`.
fn short_err(s: &str) -> String {
    let mut buf: String = s.chars().take(120).collect();
    if buf.contains('\n') || buf.contains('\r') {
        buf = buf.replace('\n', " ").replace('\r', " ");
    }
    buf
}

/// Parsed (and shaped) response — the intermediate form between the wire
/// response and the JSONL record.
struct ParsedResp {
    status: u16,
    content_length: i64,
    content_type: String,
    title: String,
    location: String,
    server: String,
    body_preview_for_output: String,
    snippet_md5: String,
}

/// Per-host rate limiter — wraps `governor`. Off when `rps == 0.0`.
mod ratelimit {
    use governor::{
        clock::DefaultClock,
        state::{InMemoryState, NotKeyed},
        Quota, RateLimiter,
    };
    use std::collections::HashMap;
    use std::num::NonZeroU32;
    use std::sync::Arc;
    use tokio::sync::Mutex as TMutex;

    type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

    pub struct HostRateLimiter {
        rps: u32,
        map: TMutex<HashMap<String, Arc<Limiter>>>,
    }

    impl HostRateLimiter {
        pub fn new(rps_f64: f64) -> Self {
            // Round to nearest u32; clamp to a sane upper bound. 0.0 → 0
            // → disabled.
            let rps = if rps_f64 <= 0.0 {
                0
            } else {
                rps_f64.round().clamp(1.0, 100_000.0) as u32
            };
            Self {
                rps,
                map: TMutex::new(HashMap::new()),
            }
        }

        pub fn enabled(&self) -> bool {
            self.rps > 0
        }

        pub async fn acquire(&self, host: &str) {
            if !self.enabled() {
                return;
            }
            let limiter = {
                let mut map = self.map.lock().await;
                if let Some(l) = map.get(host) {
                    l.clone()
                } else {
                    let q = Quota::per_second(
                        NonZeroU32::new(self.rps).unwrap_or(NonZeroU32::new(1).unwrap()),
                    );
                    let l = Arc::new(RateLimiter::direct(q));
                    map.insert(host.to_string(), l.clone());
                    l
                }
            };
            limiter.until_ready().await;
        }
    }
}

/// Issue ONE GET against `url` using the existing httpxer wreq pool, with
/// redirects DISABLED for this request (3xx is a finding, not a chase).
/// Returns the parsed response on success, or an error string otherwise.
/// Reads at most `BODY_READ_CAP` bytes of body — beyond that we drop the
/// connection.
async fn dispatch_one(
    url: &str,
    body_preview_bytes: usize,
) -> Result<(ParsedResp, &'static str, String), String> {
    let slot = probe::pick_pool_slot()
        .ok_or_else(|| "probe pool not initialised".to_string())?;
    let resp = slot
        .client
        .get(url)
        // Per-request override — keeps the SHARED enrich pool's default
        // policy (`limited(10)`) untouched while making this single
        // request return 3xx unchased.
        .redirect(Policy::none())
        .header("Accept-Language", slot.accept_lang)
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        )
        .send()
        .await
        .map_err(|e| short_err(&e.to_string()))?;

    let status = resp.status().as_u16();

    // Headers — case-insensitive lookup of the four we care about.
    let mut content_type = String::new();
    let mut header_cl: Option<i64> = None;
    let mut location = String::new();
    let mut server = String::new();
    let mut ua_echo = String::new(); // not actually echoed — we set it below
    for (k, v) in resp.headers().iter() {
        let lk = k.as_str().to_ascii_lowercase();
        let vs = match v.to_str() {
            Ok(s) => s,
            Err(_) => continue,
        };
        match lk.as_str() {
            "content-type" if content_type.is_empty() => content_type = vs.to_string(),
            "content-length" if header_cl.is_none() => {
                if let Ok(n) = vs.parse::<i64>() {
                    header_cl = Some(n);
                }
            }
            "location" if location.is_empty() => location = vs.to_string(),
            "server" if server.is_empty() => server = vs.to_string(),
            _ => {}
        }
    }
    let _ = &mut ua_echo; // silence unused-but-set warning if the compiler complains

    // Body — streamed, capped at BODY_READ_CAP.
    let mut body_bytes: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut resp_mut = resp;
    while let Ok(Some(chunk)) = resp_mut.chunk().await {
        let remaining = BODY_READ_CAP.saturating_sub(body_bytes.len());
        if remaining == 0 {
            break;
        }
        if chunk.len() > remaining {
            body_bytes.extend_from_slice(&chunk[..remaining]);
            break;
        }
        body_bytes.extend_from_slice(&chunk);
    }
    let body_len = body_bytes.len();
    let content_length: i64 = header_cl.unwrap_or(body_len as i64);

    // snippet_md5 = md5(body[:200])
    let snip_end = body_len.min(200);
    let mut hasher = Md5::new();
    hasher.update(&body_bytes[..snip_end]);
    let snippet_md5 = hex::encode(hasher.finalize());

    let title = extract_title(&body_bytes);

    // Body preview for the output JSONL: first N bytes lossy → entity-encode.
    let preview_end = body_len.min(body_preview_bytes);
    let preview_raw = String::from_utf8_lossy(&body_bytes[..preview_end]).into_owned();
    let body_preview_for_output = html_escape_body_preview(&preview_raw);

    Ok((
        ParsedResp {
            status,
            content_length,
            content_type,
            title,
            location,
            server,
            body_preview_for_output,
            snippet_md5,
        },
        slot.tag,
        ua_string(slot.tag),
    ))
}

/// Public for `main()` — same signature dispatch_one returns, used by the
/// wildcard pre-flight probe.
async fn wildcard_preflight(host_input: &str, body_preview_bytes: usize) -> Option<WildcardSig> {
    let url = format!("{}{}", host_input, random_hex_path(32));
    let (parsed, _tag, _ua) = match dispatch_one(&url, body_preview_bytes).await {
        Ok(v) => v,
        Err(_) => return None,
    };
    // Match donor: only 200-399 with body counts as a wildcard fingerprint.
    if !matches!(parsed.status, 200..=399) {
        return None;
    }
    if parsed.content_length == 0 || parsed.snippet_md5.is_empty() {
        return None;
    }
    Some(WildcardSig {
        content_length: parsed.content_length,
        content_type: parsed.content_type,
        snippet_md5: parsed.snippet_md5,
    })
}

/// Best-effort UA reconstruction from the TLS profile tag — for the
/// `user_agent` JSONL field. wreq-util's Emulation already sets a matching
/// real-browser UA on every request; this mirror is for output transparency
/// (downstream consumers want to see what UA was sent).
///
/// We map TLS profile family → a representative UA of that family. Exact
/// version-per-version UA echoing would require introspecting the wreq
/// request after build, which isn't part of the public wreq 5.3 API. The
/// family-level match is sufficient for fingerprint correlation downstream.
fn ua_string(tag: &str) -> String {
    if tag.starts_with("chrome-137") {
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36".to_string();
    }
    if tag.starts_with("chrome-136") {
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36".to_string();
    }
    if tag.starts_with("chrome-135") {
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36".to_string();
    }
    if tag.starts_with("chrome-133") {
        return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36".to_string();
    }
    if tag.starts_with("chrome-131") {
        return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string();
    }
    if tag.starts_with("firefox-139") {
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0".to_string();
    }
    if tag.starts_with("firefox-136") {
        return "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0".to_string();
    }
    if tag.starts_with("firefox-133") {
        return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0".to_string();
    }
    if tag.starts_with("safari-ios-18") {
        return "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1".to_string();
    }
    if tag.starts_with("safari-ios-17") {
        return "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1".to_string();
    }
    if tag.starts_with("safari-18.5") {
        return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15".to_string();
    }
    if tag.starts_with("safari-18.3") {
        return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15".to_string();
    }
    if tag.starts_with("safari-18.2") {
        return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15".to_string();
    }
    if tag.starts_with("edge-134") {
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0".to_string();
    }
    if tag.starts_with("edge-131") {
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0".to_string();
    }
    if tag.starts_with("firefox-android-135") {
        return "Mozilla/5.0 (Android 14; Mobile; rv:135.0) Gecko/135.0 Firefox/135.0".to_string();
    }
    // Vanilla / unknown tag — empty.
    String::new()
}

/// Cloudflare-challenge detection — ported from donor `cf.rs` (lighter than
/// the full struct; we only need the boolean flag for the output field).
fn cf_challenge(status: u16, server: &str, body_head: &str) -> bool {
    let server_is_cf = server.to_ascii_lowercase().contains("cloudflare");
    let chal_403 = status == 403
        && server_is_cf
        && (body_head.contains("cf-chl-bypass") || body_head.contains("__cf_chl_jschl_tk__"));
    let chal_503 = status == 503
        && body_head.contains("Just a moment...")
        && body_head.contains("cf-error-details");
    chal_403 || chal_503
}

/// Build the URL-form of a hostname. Mirrors retroh4ck-prober's `input`
/// (scheme+netloc). Tries https first; if the caller supplies a URL we
/// keep it verbatim.
fn host_to_input(host: &str) -> String {
    if host.starts_with("http://") || host.starts_with("https://") {
        host.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", host)
    }
}

/// Strip scheme + path so `https://target.com/foo` → `target.com`.
fn bare_host(s: &str) -> String {
    let stripped = s
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let end = stripped
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(stripped.len());
    stripped[..end].to_string()
}

/// Fuzz-mode orchestrator. Drives wildcard pre-flight + the host×path
/// Cartesian probe + JSONL output.
///
/// `hosts` / `words` come pre-deduped from the input pipeline. `args` is
/// the parsed CLI — we read only the fuzz-specific flags out of it via the
/// caller-built `FuzzCfg`.
pub async fn run(
    hosts: &[String],
    words: &[String],
    cfg: FuzzCfg,
    output_path: &str,
    no_resume: bool,
    wildcard_policy: WildcardPolicy,
) -> Result<()> {
    // ── Resume guard: drop overwrite on --no-resume; otherwise we always
    //    truncate (fuzz mode resumes by re-running, not by partial JSONL
    //    skip — the donor never implemented mid-run resume and we keep the
    //    same semantics for output-schema parity).
    if no_resume {
        let _ = std::fs::remove_file(output_path);
    }

    let out_file = Arc::new(Mutex::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(output_path)
            .with_context(|| format!("open output {}", output_path))?,
    ));

    let total_probes = hosts.len() * words.len();
    eprintln!(
        "[+] fuzz: {} hosts × {} paths = {} probes (threads={}, retries={}, wildcard={})",
        hosts.len(),
        words.len(),
        total_probes,
        cfg.threads,
        cfg.retries,
        wildcard_policy.as_str(),
    );

    // ── Wildcard pre-flight per host (unless `off`). Sequential — most runs
    //    have <50 hosts and we want the fingerprints printed before fuzz
    //    starts hammering paths.
    let mut wildcard_map = WildcardMap::new();
    if !matches!(wildcard_policy, WildcardPolicy::Off) {
        for h in hosts.iter() {
            let input = host_to_input(h);
            let host = bare_host(&input);
            if let Some(sig) = wildcard_preflight(&input, cfg.body_preview_bytes).await {
                eprintln!(
                    "  [wildcard] {} cl={} md5={}",
                    host, sig.content_length, sig.snippet_md5
                );
                wildcard_map.insert(host, sig);
            }
        }
        if wildcard_map.is_empty() {
            eprintln!("[+] wildcard pre-flight: no fingerprints recorded");
        }
    }
    let wildcards = Arc::new(wildcard_map);

    // ── Concurrency + rate limiter ─────────────────────────────────────
    let sem = Arc::new(Semaphore::new(cfg.threads.max(1)));
    let limiter = Arc::new(ratelimit::HostRateLimiter::new(cfg.rate_limit_rps));
    let cfg = Arc::new(cfg);
    let wildcard_policy_arc = Arc::new(wildcard_policy);

    let started = Instant::now();
    let mut tasks: FuturesUnordered<tokio::task::JoinHandle<()>> = FuturesUnordered::new();
    // Snapshot the spawn-backlog cap before the loop — `cfg` gets moved into
    // each spawned future, so we can't reach into it from the outer loop.
    let spawn_backlog_cap = cfg.threads * 4;

    for h in hosts.iter() {
        let input = host_to_input(h);
        let host = bare_host(&input);
        for path in words.iter() {
            let item = ProbeItem {
                host_input: input.clone(),
                host: host.clone(),
                path: path.clone(),
            };
            let sem = sem.clone();
            let limiter = limiter.clone();
            let cfg = cfg.clone();
            let wildcards = wildcards.clone();
            let out_file = out_file.clone();
            let policy = wildcard_policy_arc.clone();

            // Acquire BEFORE spawn — keeps the FuturesUnordered set bounded
            // to the semaphore size + the number of pending awaits, instead
            // of allocating one tokio::task per (host,path) eagerly.
            let permit = sem.acquire_owned().await.ok();

            tasks.push(tokio::spawn(async move {
                let _p = permit;
                if limiter.enabled() {
                    limiter.acquire(&item.host_input).await;
                }
                run_probe(item, &cfg, &wildcards, &out_file, *policy).await;
            }));

            // Throttle the spawn queue if we hit a backlog of completed
            // tasks — drain a few so we don't grow unboundedly when paths
            // outnumber the concurrency by 100x.
            while tasks.len() > spawn_backlog_cap {
                tasks.next().await;
            }
        }
    }

    // Drain.
    let mut completed = 0usize;
    while tasks.next().await.is_some() {
        completed += 1;
        if completed % 200 == 0 || completed == total_probes {
            eprintln!("  [fuzz {}/{}]", completed, total_probes);
        }
    }

    {
        let mut f = out_file.lock().await;
        let _ = f.flush();
    }
    let elapsed = started.elapsed().as_secs_f64();
    eprintln!(
        "[+] fuzz done: {} probes in {:.2}s ({:.0} rps avg) → {}",
        total_probes,
        elapsed,
        (total_probes as f64) / elapsed.max(0.001),
        output_path,
    );
    Ok(())
}

/// One (host, path) probe end-to-end.
async fn run_probe(
    item: ProbeItem,
    cfg: &FuzzCfg,
    wildcards: &Arc<WildcardMap>,
    out_file: &Arc<Mutex<std::fs::File>>,
    wildcard_policy: WildcardPolicy,
) {
    let url = format!("{}{}", item.host_input, item.path);

    let started = Instant::now();
    let mut attempts: u32 = 0;
    let mut last_err: Option<String> = None;
    let max_attempts = cfg.retries.saturating_add(1).max(1);

    let mut parsed_opt: Option<ParsedResp> = None;
    let mut tls_tag: &'static str = "vanilla";
    let mut ua_used: String = String::new();

    while attempts < max_attempts {
        attempts += 1;
        match dispatch_one(&url, cfg.body_preview_bytes).await {
            Ok((parsed, tag, ua)) => {
                parsed_opt = Some(parsed);
                tls_tag = tag;
                ua_used = ua;
                break;
            }
            Err(e) => {
                last_err = Some(e);
                if attempts < max_attempts {
                    // Backoff between retries — same 50 ms as enrich-mode
                    // `http_probe_with_retry`.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
    let elapsed_ms = started.elapsed().as_millis() as u64;

    let policy_str = wildcard_policy.as_str().to_string();

    match parsed_opt {
        Some(parsed) => {
            // Wildcard check before status filter.
            let mut is_wildcard = false;
            if !matches!(wildcard_policy, WildcardPolicy::Off)
                && wildcards.matches(
                    &item.host,
                    parsed.content_length,
                    &parsed.content_type,
                    &parsed.snippet_md5,
                )
            {
                is_wildcard = true;
            }

            // Status-code filter.
            if !cfg.match_codes.contains(&parsed.status) {
                return;
            }

            // Strict wildcard suppression.
            if is_wildcard && matches!(wildcard_policy, WildcardPolicy::Strict) {
                return;
            }

            let cf = cf_challenge(parsed.status, &parsed.server, &parsed.body_preview_for_output);

            let rec = FuzzRecord {
                url: url.clone(),
                input: item.host_input.clone(),
                path: item.path.clone(),
                host: item.host.clone(),
                status_code: parsed.status,
                content_length: parsed.content_length,
                content_type: parsed.content_type,
                title: parsed.title,
                location: parsed.location,
                server: parsed.server.clone(),
                webserver: parsed.server,
                body_preview: parsed.body_preview_for_output,
                tech: Vec::new(),
                method: "GET",
                is_wildcard,
                wildcard_policy: policy_str,
                via_proxy: cfg.via_proxy,
                attempts,
                elapsed_ms,
                snippet_md5: parsed.snippet_md5,
                tls_impersonation: tls_tag.to_string(),
                user_agent: ua_used,
                cf_challenge: cf,
                error: None,
                timestamp: now_iso8601(),
                prober: PROBER_TAG,
            };
            write_record(out_file, &rec).await;
        }
        None => {
            if !cfg.include_errors {
                return;
            }
            let rec = FuzzRecord {
                url: url.clone(),
                input: item.host_input.clone(),
                path: item.path.clone(),
                host: item.host.clone(),
                status_code: 0,
                content_length: -1,
                content_type: String::new(),
                title: String::new(),
                location: String::new(),
                server: String::new(),
                webserver: String::new(),
                body_preview: String::new(),
                tech: Vec::new(),
                method: "GET",
                is_wildcard: false,
                wildcard_policy: policy_str,
                via_proxy: cfg.via_proxy,
                attempts,
                elapsed_ms,
                snippet_md5: String::new(),
                tls_impersonation: tls_tag.to_string(),
                user_agent: ua_used,
                cf_challenge: false,
                error: last_err,
                timestamp: now_iso8601(),
                prober: PROBER_TAG,
            };
            write_record(out_file, &rec).await;
        }
    }
}

async fn write_record(out_file: &Arc<Mutex<std::fs::File>>, rec: &FuzzRecord) {
    let line = match serde_json::to_string(rec) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut f = out_file.lock().await;
    let _ = writeln!(*f, "{}", line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_basic() {
        assert_eq!(normalize_path(""), "");
        assert_eq!(normalize_path("admin"), "/admin");
        assert_eq!(normalize_path("/admin"), "/admin");
        assert_eq!(normalize_path("//admin"), "/admin");
        assert_eq!(normalize_path("///admin/x"), "/admin/x");
        assert_eq!(normalize_path("  /env  "), "/env");
        assert_eq!(normalize_path("# comment"), "");
    }

    #[test]
    fn random_hex_path_well_formed() {
        for _ in 0..16 {
            let p = random_hex_path(32);
            assert_eq!(p.len(), 33);
            assert!(p.starts_with('/'));
            assert!(p[1..]
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }

    #[test]
    fn html_escape_order_matters() {
        assert_eq!(html_escape_body_preview("<a>"), "&lt;a&gt;");
        assert_eq!(html_escape_body_preview("\"foo\""), "&#34;foo&#34;");
        assert_eq!(html_escape_body_preview("a & b"), "a &amp; b");
        assert_eq!(
            html_escape_body_preview("<p class=\"x\">&"),
            "&lt;p class=&#34;x&#34;&gt;&amp;"
        );
    }

    #[test]
    fn bare_host_strips_scheme_and_path() {
        assert_eq!(bare_host("https://x.com/foo"), "x.com");
        assert_eq!(bare_host("http://x.com:8080/abc"), "x.com:8080");
        assert_eq!(bare_host("https://x.com"), "x.com");
        assert_eq!(bare_host("x.com"), "x.com");
    }

    #[test]
    fn host_to_input_adds_https() {
        assert_eq!(host_to_input("target.com"), "https://target.com");
        assert_eq!(host_to_input("https://target.com"), "https://target.com");
        assert_eq!(host_to_input("https://target.com/"), "https://target.com");
        assert_eq!(host_to_input("http://target.com:8080"), "http://target.com:8080");
    }

    #[test]
    fn wildcard_policy_parsing() {
        assert_eq!(
            WildcardPolicy::from_cli("strict", false).unwrap(),
            WildcardPolicy::Strict
        );
        assert_eq!(
            WildcardPolicy::from_cli("mark", false).unwrap(),
            WildcardPolicy::Mark
        );
        assert_eq!(
            WildcardPolicy::from_cli("off", false).unwrap(),
            WildcardPolicy::Off
        );
        // --no-wildcard overrides
        assert_eq!(
            WildcardPolicy::from_cli("strict", true).unwrap(),
            WildcardPolicy::Off
        );
        assert!(WildcardPolicy::from_cli("bogus", false).is_err());
    }

    #[test]
    fn fuzz_record_serialises_with_donor_field_names() {
        let rec = FuzzRecord {
            url: "https://x.com/a".into(),
            input: "https://x.com".into(),
            path: "/a".into(),
            host: "x.com".into(),
            status_code: 200,
            content_length: 42,
            content_type: "text/plain".into(),
            title: "T".into(),
            location: "".into(),
            server: "nginx".into(),
            webserver: "nginx".into(),
            body_preview: "&#34;ok&#34;".into(),
            tech: vec![],
            method: "GET",
            is_wildcard: false,
            wildcard_policy: "strict".into(),
            via_proxy: false,
            attempts: 1,
            elapsed_ms: 5,
            snippet_md5: "abc".into(),
            tls_impersonation: "chrome-131".into(),
            user_agent: "ua".into(),
            cf_challenge: false,
            error: None,
            timestamp: "2026-05-20T12:00:00.000Z".into(),
            prober: PROBER_TAG,
        };
        let s = serde_json::to_string(&rec).unwrap();
        assert!(s.contains("\"status_code\":200"));
        assert!(s.contains("\"content_type\":\"text/plain\""));
        assert!(s.contains("\"body_preview\":\"&#34;ok&#34;\""));
        assert!(s.contains("\"input\":\"https://x.com\""));
        assert!(s.contains("\"webserver\":\"nginx\""));
        assert!(s.contains("\"server\":\"nginx\""));
        assert!(s.contains("\"tls_impersonation\":\"chrome-131\""));
        assert!(s.contains("\"prober\":\"httpxer/"));
    }

    #[test]
    fn cf_challenge_detection() {
        assert!(!cf_challenge(200, "nginx", "<html>ok</html>"));
        assert!(cf_challenge(
            403,
            "cloudflare",
            "<html>cf-chl-bypass</html>"
        ));
        assert!(cf_challenge(
            503,
            "cloudflare",
            "<html>Just a moment... cf-error-details</html>"
        ));
        // 403 + cf body marker but server NOT cloudflare → not a challenge.
        assert!(!cf_challenge(403, "nginx", "<html>cf-chl-bypass</html>"));
    }
}
