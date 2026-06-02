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
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use wreq::redirect::Policy;

use crate::probe;
use crate::wildcard::{self, WildcardMap, WildcardSig};

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

/// One-shot guard for the JSONL writer error log — we surface the first
/// `writeln!` failure to stderr so a disk-full scenario doesn't silently
/// eat records, but stay quiet thereafter so the log isn't drowned.
static WRITE_ERR_LOGGED: AtomicBool = AtomicBool::new(false);

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

    // ── v0.3.7 additions (recursion + crawl provenance) ────────────────
    // All three are `skip_serializing_if`-gated so depth-0 wordlist hits
    // remain byte-compatible with the v0.3.6 schema.
    /// Round / recursion depth — 0 for the initial host × wordlist pass.
    #[serde(skip_serializing_if = "is_u8_zero", default)]
    depth: u8,
    /// Probe origin tag. Empty at depth 0. One of: "wordlist",
    /// "recursion", "crawl-html", "crawl-robots", "crawl-sitemap".
    #[serde(skip_serializing_if = "String::is_empty", default)]
    source: String,
    /// Parent directory or response URL this probe was derived from.
    /// Empty at depth 0.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    parent_url: String,
}

fn is_u8_zero(v: &u8) -> bool {
    *v == 0
}

/// Per-(host,path) work item. Carries v0.4.0 recursion/crawl provenance
/// so the resulting FuzzRecord can be tagged with depth + source +
/// parent_url for downstream consumers.
struct ProbeItem {
    host_input: String, // e.g. "https://target.com" or "target.com"
    host: String,       // bare hostname, used as the WildcardMap key
    path: String,
    /// Round / recursion depth — 0 for the initial host × wordlist pass.
    depth: u8,
    /// Probe origin tag. Empty at depth 0. One of: "wordlist" (depth 0),
    /// "recursion" (re-fuzz under discovered dir), "crawl-html",
    /// "crawl-robots", "crawl-sitemap".
    source: String,
    /// Parent URL this probe was derived from. Empty at depth 0.
    parent_url: String,
}

/// Discovery emitted from a worker after a successful probe. Picked up
/// by the multi-round orchestrator to seed the next round's frontier.
/// v0.4.0 — needed for recursion + crawl orchestration.
#[derive(Debug)]
enum Discovery {
    /// 301/302/307/308 with Location parity check passed (or 200 +
    /// Index-of marker, or 403 opt-in) → directory worth re-fuzzing
    /// the wordlist under in the next round.
    Directory {
        canonical_url: String,
        host: String,
        depth: u8,
        parent: String,
    },
    /// Link extracted from the response body by `crawl::extract_urls`
    /// (HTML / robots.txt / sitemap.xml). Already absolute + in-scope.
    Link {
        canonical_url: String,
        source: String,
        depth: u8,
        parent: String,
    },
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
    /// Status codes to EXCLUDE from output even when they're in match_codes.
    /// Default `[429, 503]` — transient overload codes that rarely indicate
    /// real findings. Empty = exclude nothing.
    pub exclude_codes: Vec<u16>,
    pub body_preview_bytes: usize,
    pub wildcard_policy: WildcardPolicy,
    /// Wildcard pre-flight sample count. v0.3.7 default 3; all must agree
    /// on `(content_length, content_type, snippet_md5)` to trust the
    /// fingerprint. Disagreement → mark dir path-sensitive → skip recursion.
    pub wildcard_samples: u8,
    pub include_errors: bool,
    pub retries: u32,
    pub via_proxy: bool, // true iff --proxy was set
    pub threads: usize,
    pub timeout_ms: u64,
    pub rate_limit_rps: f64,
    // ── Recursion (v0.3.7) ─────────────────────────────────────────────
    /// Max recursion depth. 0 = off (backwards compatible with v0.3.6).
    pub recursion_depth: u8,
    pub recurse_on_200: bool,
    pub recurse_on_403: bool,
    pub max_dirs_per_host: usize,
    pub max_probes_per_host: usize,
    /// Self-similarity window for loop detection (default 2). 0 = disabled.
    pub similarity_window: usize,
    // ── Crawl (v0.3.7) ─────────────────────────────────────────────────
    pub crawl_enabled: bool,
    pub crawl_depth: u8,
    pub crawl_robots: bool,
    pub crawl_sitemap: bool,
    pub max_links_per_page: usize,
    pub scope_hosts: Vec<String>,
    /// Built-in + user-overridden subdirectory exclude list (lowercased).
    pub exclude_subdirs: std::collections::HashSet<String>,
    /// How exclude entries match — segment (default) or substring (v0.3.10).
    pub exclude_mode: crate::recurse::ExcludeMode,
    /// Exact content-lengths to drop from output (v0.3.10 — dirsearch
    /// `--exclude-sizes` parity). Empty = no size filter.
    pub exclude_sizes: Vec<i64>,
    // ── Misc behavior (v0.3.7) ─────────────────────────────────────────
    /// Follow redirects within fuzz probes (default off — 3xx is a finding).
    /// Auto-on when crawl_enabled (crawl needs terminal URL + body).
    pub fuzz_follow_redirects: bool,
    /// Cookie header to attach to every request (initial-state seed).
    /// Built from `--cookie name=value` entries.
    pub initial_cookie_header: Option<String>,
    /// Additional headers from `--header`/`--bearer`. Empty when no auth.
    pub extra_headers: Vec<(String, String)>,
    /// Output file format (v0.3.13). `Json` = current behavior;
    /// `Plain` = dirsearch-style `STATUS  SIZE  URL` per line.
    pub output_format: OutputFormat,
    /// Print findings live to stderr during the scan in dirsearch-style
    /// format (v0.3.13). True by default; disable for clean log scraping.
    pub live_findings: bool,
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
    for line in BufReader::new(f).lines().map_while(Result::ok) {
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

/// Format a byte size as a compact human string: 146B, 1KB, 1.2MB, 3.4GB.
/// Negative → "--" (the marker for error records with no body).
/// Used by both the live findings display and `--format plain`.
fn format_size(bytes: i64) -> String {
    if bytes < 0 {
        return "--".to_string();
    }
    let b = bytes as f64;
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    if b < KB {
        format!("{}B", bytes)
    } else if b < MB {
        format!("{:.0}KB", b / KB)
    } else if b < GB {
        format!("{:.1}MB", b / MB)
    } else {
        format!("{:.1}GB", b / GB)
    }
}

/// Output format for `-o` file + live terminal findings (v0.3.13).
/// - `Json` (default): one FuzzRecord JSON object per line — full data,
///   downstream-parsable.
/// - `Plain`: dirsearch-style `STATUS  SIZE  URL` per line — human-
///   readable, much smaller files.
/// Auto-detected from the `-o` file extension when `--format` isn't passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Plain,
}

impl OutputFormat {
    pub fn from_cli(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "json" | "jsonl" => Ok(Self::Json),
            "plain" | "txt" => Ok(Self::Plain),
            other => anyhow::bail!(
                "invalid --format '{}' (want json|jsonl|plain|txt)",
                other
            ),
        }
    }

    /// Auto-detect output format from `-o` file extension.
    /// `.json` / `.jsonl` → Json; `.txt` → Plain. Anything else → Json (safe).
    pub fn from_path(path: &str) -> Self {
        let lc = path.to_ascii_lowercase();
        if lc.ends_with(".txt") {
            Self::Plain
        } else {
            Self::Json
        }
    }
}

/// Dirsearch-style single-line finding format. Used for BOTH live
/// terminal display (TTY-gated, ANSI-colored) and `--format plain`
/// file output (no ANSI). Empty when status is 0 (network error
/// emit-errors path) so the table stays aligned at width.
fn format_finding_line(status: u16, content_length: i64, url: &str, color: bool) -> String {
    let size = format_size(content_length);
    if color {
        // Status code color cues — same palette as dirsearch / ffuf:
        let color_code = match status {
            200..=299 => "\x1b[32m",       // green
            300..=399 => "\x1b[33m",       // yellow
            401 | 403 => "\x1b[36m",       // cyan (auth-walled)
            400 | 402 | 404..=499 => "\x1b[35m", // magenta (other 4xx)
            500..=599 => "\x1b[31m",       // red (server error)
            _ => "",
        };
        let reset = if color_code.is_empty() { "" } else { "\x1b[0m" };
        format!("{}{:>3}{} {:>7}  {}", color_code, status, reset, size, url)
    } else {
        format!("{:>3} {:>7}  {}", status, size, url)
    }
}

/// Format a seconds count as a compact human-readable ETA used by the
/// v0.3.12 live progress bar: `5s`, `1m30s`, `2h15m4s`. Zero → "0s".
fn format_eta(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{}m{}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    } else if secs >= 60 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

/// Choose hex-character counts for `n` pre-flight samples — varied so
/// the v0.3.9 Layer 2 detector can compute the linear `CL = k × path_len
/// + base` slope. Each sample gets a different `hex_len` ⇒ different
/// `path_len`. Pattern: 16, 32, 64, 24, 48 (then repeats).
fn pick_hex_lens(n: usize) -> Vec<usize> {
    const POOL: &[usize] = &[16, 32, 64, 24, 48];
    (0..n).map(|i| POOL[i % POOL.len()]).collect()
}

/// Decoded byte length of a URL path — counts `%XX` triplets as one byte
/// (matches what any RFC-3986-compliant server sees after percent-
/// decoding). Necessary for Layer 2's CL formula match, because aiohttp
/// / nginx / IIS / etc. echo the DECODED path in path-echo bodies; counting
/// the encoded length would inflate `expected_CL` and push real findings
/// outside the tolerance window. Caught 37 spurious FPs in the v0.3.9
/// benchmark before this fix.
///
/// Inline (no `percent_encoding` dep) — strictly an ASCII byte-count, no
/// UTF-8 normalization. The hot path runs once per probe, must be cheap.
fn decoded_path_len(path: &str) -> usize {
    let bytes = path.as_bytes();
    let mut len = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            len += 1;
            i += 3;
        } else {
            len += 1;
            i += 1;
        }
    }
    len
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
        buf = buf.replace(['\n', '\r'], " ");
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
    /// Raw response body (UTF-8 lossy, ≤256 KB). Used by v0.4.0 crawl
    /// for HTML link extraction. Empty when the body was empty or when
    /// crawl is disabled (caller decides whether to populate via the
    /// `keep_raw_body` param to `dispatch_one`).
    raw_body: String,
}

/// Per-host rate limiter — wraps `governor`. Off when `rps == 0.0`.
///
/// Supports fractional rps (e.g. `--rate-limit 0.1` = one request every 10s)
/// via `Quota::with_period`. The previous integer-rounded path silently
/// promoted any 0 < rps < 0.5 to disabled and 0.5 ≤ rps < 1.5 to exactly
/// 1 rps, which surprised users with sub-1 limits.
mod ratelimit {
    use governor::{
        clock::DefaultClock,
        state::{InMemoryState, NotKeyed},
        Quota, RateLimiter,
    };
    use std::collections::HashMap;
    use std::num::NonZeroU32;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex as TMutex;

    type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

    pub struct HostRateLimiter {
        quota: Option<Quota>,
        map: TMutex<HashMap<String, Arc<Limiter>>>,
    }

    impl HostRateLimiter {
        pub fn new(rps_f64: f64) -> Self {
            let quota = if rps_f64 <= 0.0 {
                None
            } else if rps_f64 >= 1.0 {
                let n = rps_f64.round().min(100_000.0) as u32;
                NonZeroU32::new(n).map(Quota::per_second)
            } else {
                // Fractional rps — one token every (1/rps) seconds. Cap the
                // period at 1 h so 0.0001-style inputs don't construct a
                // multi-day quota by accident.
                let period_secs = (1.0_f64 / rps_f64).min(3600.0);
                Quota::with_period(Duration::from_secs_f64(period_secs))
            };
            Self {
                quota,
                map: TMutex::new(HashMap::new()),
            }
        }

        pub fn enabled(&self) -> bool {
            self.quota.is_some()
        }

        pub async fn acquire(&self, host: &str) {
            let Some(quota) = self.quota else { return };
            let limiter = {
                let mut map = self.map.lock().await;
                if let Some(l) = map.get(host) {
                    l.clone()
                } else {
                    let l = Arc::new(RateLimiter::direct(quota));
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
    host_key: &str,
    body_preview_bytes: usize,
    extra_headers: &[(String, String)],
    initial_cookie_header: Option<&str>,
    follow_redirects: bool,
) -> Result<(ParsedResp, &'static str, String), String> {
    // Pin one TLS profile per host so the wildcard fingerprint computed at
    // pre-flight (snippet_md5 etc.) matches what the actual fuzz probes
    // against the same host see — random per-request rotation made the
    // signatures diverge on UA-varying servers.
    let slot = probe::pick_pool_slot_for(host_key)
        .ok_or_else(|| "probe pool not initialised".to_string())?;
    // Redirect policy: per-request override. Crawl mode wants the terminal
    // body (so we can parse links from the final landing page); fuzz mode
    // default keeps 3xx as a finding.
    let redirect_policy = if follow_redirects {
        Policy::limited(10)
    } else {
        Policy::none()
    };
    let mut req = slot
        .client
        .get(url)
        .redirect(redirect_policy)
        .header("Accept-Language", slot.accept_lang)
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        );
    // Auth headers — user-supplied via -H / --bearer. Validated at CLI
    // parse so the per-request attach is safe.
    for (n, v) in extra_headers {
        req = req.header(n.as_str(), v.as_str());
    }
    // Initial cookie seed — user-supplied via --cookie. Once wreq's
    // cookie_store is enabled the response Set-Cookie persists for follow-up
    // requests to the same domain. (v0.3.7 ships header-attach only;
    // cookie_store wiring lands in v0.3.8 when the pool builder gets a
    // .cookie_store(true) toggle.)
    if let Some(c) = initial_cookie_header {
        req = req.header("Cookie", c);
    }
    let resp = req.send().await.map_err(|e| short_err(&e.to_string()))?;

    let status = resp.status().as_u16();

    // Headers — case-insensitive lookup of the four we care about.
    let mut content_type = String::new();
    let mut header_cl: Option<i64> = None;
    let mut location = String::new();
    let mut server = String::new();
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
    // v0.4.0 — raw body for crawl link extraction. Lossy UTF-8 decode of
    // the FULL body_bytes (already capped at BODY_READ_CAP / 256 KB).
    // ~1.3× the cost of body_preview_for_output; acceptable given the
    // crawl feature this enables. When `--crawl` is off, the orchestrator
    // ignores this field — pre-v0.4.0 memory profile unchanged.
    let raw_body = String::from_utf8_lossy(&body_bytes).into_owned();

    let ua = ua_string(slot.tag);
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
            raw_body,
        },
        slot.tag,
        ua,
    ))
}

/// Run ONE wildcard pre-flight probe with a random hex path of the given
/// length. Returns a `ProbeSample` for the v0.3.9 layered detector, or
/// `None` when the probe didn't yield a usable body (status outside
/// 200-399 / empty body / network error).
///
/// `hex_len` is the number of random hex characters in the path AFTER
/// the leading `/` — caller varies this (typically 16, 32, 64) so the
/// returned samples have different path lengths, which lets `detect()`
/// compute the Layer 2 linear slope for path-echo servers.
async fn wildcard_preflight_sample(
    host_input: &str,
    body_preview_bytes: usize,
    extra_headers: &[(String, String)],
    initial_cookie_header: Option<&str>,
    hex_len: usize,
) -> Option<crate::wildcard::ProbeSample> {
    let path = random_hex_path(hex_len); // e.g. "/abc...xyz"
    let url = format!("{}{}", host_input, path);
    // Pre-flight ALWAYS uses follow_redirects=false: a 3xx to e.g. /login
    // would otherwise let the wildcard fingerprint reflect the login page
    // instead of the catchall.
    let (parsed, _tag, _ua) = match dispatch_one(
        &url,
        host_input,
        body_preview_bytes,
        extra_headers,
        initial_cookie_header,
        false,
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return None,
    };
    // Match donor: only 200-399 with body counts.
    if !matches!(parsed.status, 200..=399) {
        return None;
    }
    if parsed.content_length == 0 || parsed.snippet_md5.is_empty() {
        return None;
    }
    Some(crate::wildcard::ProbeSample {
        status: parsed.status,
        content_length: parsed.content_length,
        content_type: parsed.content_type,
        snippet_md5: parsed.snippet_md5,
        path_len: path.len(),
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
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0"
            .to_string();
    }
    if tag.starts_with("firefox-136") {
        return "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0"
            .to_string();
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
    let end = stripped.find(['/', '?', '#']).unwrap_or(stripped.len());
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

    // v0.4.0 — the deferred-since-v0.3.7 recursion + crawl orchestration
    // is now wired. The `[!]` warning that used to print here is gone.

    // ── Two-layer wildcard pre-flight per host (v0.3.7 + v0.3.9).
    //    Probes N random hex paths with VARYING lengths (16/32/64 chars)
    //    so the detector can compute BOTH:
    //      Layer 1 — static catchall (all bodies identical) — defeats
    //        single-sample by requiring N-way agreement on (CL, CT, md5).
    //      Layer 2 — path-echo / dynamic-CL (body length scales with path
    //        length: CL = k × path_len + base) — defeats path-echo servers
    //        that dirsearch / feroxbuster's K=1 heuristic catches but
    //        our v0.3.7 multi-sample alone missed. v0.3.9 addition.
    //    Disagreement on BOTH layers = path-sensitive server → no
    //    suppression, stderr warning.
    let mut wildcard_map = WildcardMap::new();
    if !matches!(wildcard_policy, WildcardPolicy::Off) {
        let n_samples = cfg.wildcard_samples.max(1) as usize;
        // Varying hex lengths give the Layer 2 slope detector different
        // x-values. With n_samples=3 we use [16, 32, 64]; with other N
        // we round-robin / extend the pattern.
        let hex_lens = pick_hex_lens(n_samples);
        for h in hosts.iter() {
            let input = host_to_input(h);
            let host = bare_host(&input);
            let mut samples: Vec<crate::wildcard::ProbeSample> =
                Vec::with_capacity(n_samples);
            for &hex_len in &hex_lens {
                if let Some(sample) = wildcard_preflight_sample(
                    &input,
                    cfg.body_preview_bytes,
                    &cfg.extra_headers,
                    cfg.initial_cookie_header.as_deref(),
                    hex_len,
                )
                .await
                {
                    samples.push(sample);
                }
            }
            match wildcard::detect(&samples, 10) {
                Some(sig) if sig.k.is_some() => {
                    eprintln!(
                        "  [wildcard L2] {} k={} base={} (path-echo detected; {}/{} samples)",
                        host,
                        sig.k.unwrap(),
                        sig.base.unwrap(),
                        samples.len(),
                        n_samples
                    );
                    wildcard_map.insert(input, sig);
                }
                Some(sig) if sig.content_length < 0 => {
                    eprintln!(
                        "  [wildcard L1] {} prefix-only md5={} ({}/{} samples agreed)",
                        host,
                        sig.snippet_md5,
                        samples.len(),
                        n_samples
                    );
                    wildcard_map.insert(input, sig);
                }
                Some(sig) => {
                    eprintln!(
                        "  [wildcard L1] {} cl={} md5={} ({}/{} samples agreed)",
                        host,
                        sig.content_length,
                        sig.snippet_md5,
                        samples.len(),
                        n_samples
                    );
                    wildcard_map.insert(input, sig);
                }
                None if samples.len() < n_samples => {
                    // Some probes failed entirely (404 / timeout / not 2xx-3xx).
                    // Common case for well-behaved targets that 404 random
                    // paths. NOT path-sensitive — just no wildcard to record.
                }
                None => {
                    // All samples returned but BOTH layers disagreed → truly
                    // path-sensitive. NO suppression (would over-suppress
                    // real findings). Stderr warning for user awareness.
                    eprintln!(
                        "  [wildcard] {} → path-sensitive (L1 + L2 both rejected); \
                         emitting all findings, recursion skipped here",
                        host
                    );
                }
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

    // v0.3.12 — live progress bar. Workers atomically bump `completed`
    // when each probe finishes; a separate ticker task reads it every
    // 100 ms and redraws the progress line. Counter is needed because
    // the in-loop `while tasks.len() > spawn_backlog_cap` drains tasks
    // DURING the spawn loop — the post-spawn drain only sees the final
    // ~backlog_cap tasks, so the earlier code's drain-counting strategy
    // never saw the bulk of completions.
    let completed_counter = Arc::new(AtomicUsize::new(0));
    let progress_done = Arc::new(AtomicBool::new(false));
    let is_tty = std::io::stderr().is_terminal();
    // Debug print removed v0.3.12 — kept the comment as a marker.
    let progress_task = {
        let counter = completed_counter.clone();
        let done = progress_done.clone();
        let total = total_probes;
        let started_at = started;
        tokio::spawn(async move {
            use std::io::Write as _;
            loop {
                if done.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                let completed = counter.load(Ordering::Relaxed);
                if is_tty {
                    let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
                    let rps = completed as f64 / elapsed;
                    let pct = (completed as f64 * 100.0 / total.max(1) as f64) as u32;
                    let eta_secs = if rps > 0.0 {
                        ((total.saturating_sub(completed)) as f64 / rps) as u64
                    } else {
                        0
                    };
                    let mut stderr = std::io::stderr();
                    let _ = write!(
                        stderr,
                        "\r\x1b[K  [{}/{}] {}% | {:.0} rps | eta {}",
                        completed, total, pct, rps, format_eta(eta_secs)
                    );
                    let _ = stderr.flush();
                } else {
                    // Piped runs — batched line per 500 completions.
                    // (Was per-200 in v0.3.7 drain-loop counter; the
                    // ticker-task variant uses 500 so the cadence
                    // matches a TTY's ~100 ms refresh visually.)
                    if completed > 0 && completed % 500 == 0 {
                        eprintln!("  [fuzz {}/{}]", completed, total);
                    }
                }
            }
        })
    };

    // ── v0.4.0: multi-round orchestrator setup ────────────────────────
    // The single-pass spawn loop becomes ROUND 0 of a multi-round loop.
    // Workers send discoveries (new dirs / crawled URLs) to disc_tx;
    // after each round drains, the orchestrator collects them, dedups
    // via `visited`, runs wildcard pre-flight for new dirs, and seeds
    // the next round. Loops up to max(recursion_depth, crawl_depth).
    let (disc_tx, mut disc_rx) =
        tokio::sync::mpsc::unbounded_channel::<Discovery>();
    // Visited set — canonical URLs we've already PROBED (or are about to).
    // Insert-and-check is atomic via Mutex; HashSet for O(1) lookup.
    let visited: Arc<tokio::sync::Mutex<HashSet<String>>> =
        Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    // Seed visited with the round-0 host × wordlist set so crawl-extracted
    // links matching existing wordlist probes don't double-fire.
    {
        let mut v = visited.lock().await;
        for h in hosts.iter() {
            let input = host_to_input(h);
            for path in words.iter() {
                let url = format!("{}{}", input.trim_end_matches('/'), path);
                v.insert(crate::recurse::canonical_url_key(&url));
            }
        }
    }
    // Per-host budgets (max_dirs, max_probes) prevent recursion blowup.
    let host_budgets: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Arc<crate::recurse::HostBudget>>>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let max_round_depth = std::cmp::max(
        cfg.recursion_depth as usize,
        if cfg.crawl_enabled { cfg.crawl_depth as usize } else { 0 },
    );
    if max_round_depth > 0 {
        eprintln!(
            "[+] multi-round mode: depth={} (recursion={}, crawl={})",
            max_round_depth, cfg.recursion_depth,
            if cfg.crawl_enabled { cfg.crawl_depth as i16 } else { 0i16 }
        );
    }

    // ── ROUND 0: hosts × wordlist (the existing single-pass loop) ─────
    for h in hosts.iter() {
        let input = host_to_input(h);
        let host = bare_host(&input);
        for path in words.iter() {
            let item = ProbeItem {
                host_input: input.clone(),
                host: host.clone(),
                path: path.clone(),
                depth: 0,
                source: String::new(),
                parent_url: String::new(),
            };
            let sem = sem.clone();
            let limiter = limiter.clone();
            let cfg = cfg.clone();
            let wildcards = wildcards.clone();
            let out_file = out_file.clone();
            let policy = wildcard_policy_arc.clone();
            let counter = completed_counter.clone();
            let disc = disc_tx.clone();

            // Acquire BEFORE spawn — keeps the FuturesUnordered set bounded
            // to the semaphore size + the number of pending awaits, instead
            // of allocating one tokio::task per (host,path) eagerly.
            let permit = sem.acquire_owned().await.ok();

            tasks.push(tokio::spawn(async move {
                let _p = permit;
                if limiter.enabled() {
                    limiter.acquire(&item.host_input).await;
                }
                run_probe(item, &cfg, &wildcards, &out_file, *policy, &disc).await;
                counter.fetch_add(1, Ordering::Relaxed);
            }));

            // Throttle the spawn queue if we hit a backlog of completed
            // tasks — drain a few so we don't grow unboundedly when paths
            // outnumber the concurrency by 100x.
            while tasks.len() > spawn_backlog_cap {
                tasks.next().await;
            }
        }
    }

    // Drain round-0 tasks. Workers update the atomic counter; the
    // ticker task reads it.
    while tasks.next().await.is_some() {}

    // ── v0.4.0: multi-round drain ─────────────────────────────────────
    // After round 0 completes, collect Discovery messages (dirs from
    // recursion + URLs from crawl extraction). For each new dir, run
    // the multi-sample wildcard pre-flight. Then spawn another round
    // of probes. Loop up to `max_round_depth`. Visited set prevents
    // duplicate probes across rounds.
    if max_round_depth > 0 {
        for round in 1..=max_round_depth {
            // Drain everything that's currently in the channel.
            // (try_recv until empty — non-blocking; workers already
            // finished so no more messages are coming for this round.)
            let mut new_dirs: Vec<(String, String, u8, String)> = Vec::new(); // (url, host, depth, parent)
            let mut new_urls: Vec<(String, String, u8, String)> = Vec::new(); // (url, source, depth, parent)
            while let Ok(d) = disc_rx.try_recv() {
                match d {
                    Discovery::Directory { canonical_url, host, depth, parent } => {
                        if (depth as usize) <= round {
                            new_dirs.push((canonical_url, host, depth, parent));
                        }
                    }
                    Discovery::Link { canonical_url, source, depth, parent } => {
                        if (depth as usize) <= round {
                            new_urls.push((canonical_url, source, depth, parent));
                        }
                    }
                }
            }
            // Dedupe via visited set + apply per-host budgets.
            let mut frontier_dirs: Vec<(String, String, u8, String)> = Vec::new();
            let mut frontier_urls: Vec<(String, String, u8, String)> = Vec::new();
            {
                let mut v = visited.lock().await;
                let mut budgets = host_budgets.lock().await;
                for (canon, host, depth, parent) in new_dirs {
                    if !v.insert(canon.clone()) { continue; }
                    let budget = budgets.entry(host.clone()).or_insert_with(|| {
                        Arc::new(crate::recurse::HostBudget::new(
                            cfg.max_probes_per_host,
                            cfg.max_dirs_per_host,
                        ))
                    });
                    if !budget.try_inc_dir() { continue; }
                    frontier_dirs.push((canon, host, depth, parent));
                }
                for (canon, source, depth, parent) in new_urls {
                    if !v.insert(canon.clone()) { continue; }
                    // Crawl URLs don't consume the dir budget; they're
                    // single-shot probes, not new fuzz-prefixes.
                    frontier_urls.push((canon, source, depth, parent));
                }
            }
            if frontier_dirs.is_empty() && frontier_urls.is_empty() {
                eprintln!("[+] round {}: no new discoveries — done", round);
                break;
            }
            eprintln!(
                "[+] round {}: fuzz {} discovered dirs + probe {} crawl-extracted URLs",
                round, frontier_dirs.len(), frontier_urls.len()
            );
            // Multi-sample wildcard pre-flight for each NEW dir.
            // Skip when wildcard policy is off OR when this dir already
            // has a fingerprint inherited from its parent host_input.
            // (We don't have an Arc<Mutex<WildcardMap>> for live mutation
            // — for v0.4.0 MVP we just reuse the round-0 wildcard map.
            // Per-dir pre-flight refinement lands in v0.4.1.)

            // Spawn probes for new dirs × wordlist + new URLs.
            for (dir_url, host, depth, parent) in &frontier_dirs {
                for path in words.iter() {
                    let full_url = format!("{}{}", dir_url.trim_end_matches('/'), path);
                    // Visited check on the full probe URL — skip if some
                    // other dir's expansion already covers it.
                    {
                        let mut v = visited.lock().await;
                        if !v.insert(crate::recurse::canonical_url_key(&full_url)) {
                            continue;
                        }
                    }
                    let item = ProbeItem {
                        host_input: dir_url.trim_end_matches('/').to_string(),
                        host: host.clone(),
                        path: path.clone(),
                        depth: *depth,
                        source: "recursion".to_string(),
                        parent_url: parent.clone(),
                    };
                    let sem_c = sem.clone();
                    let limiter_c = limiter.clone();
                    let cfg_c = cfg.clone();
                    let wildcards_c = wildcards.clone();
                    let out_file_c = out_file.clone();
                    let policy_c = wildcard_policy_arc.clone();
                    let counter_c = completed_counter.clone();
                    let disc_c = disc_tx.clone();
                    let permit = sem_c.acquire_owned().await.ok();
                    tasks.push(tokio::spawn(async move {
                        let _p = permit;
                        if limiter_c.enabled() {
                            limiter_c.acquire(&item.host_input).await;
                        }
                        run_probe(item, &cfg_c, &wildcards_c, &out_file_c, *policy_c, &disc_c).await;
                        counter_c.fetch_add(1, Ordering::Relaxed);
                    }));
                    while tasks.len() > spawn_backlog_cap {
                        tasks.next().await;
                    }
                }
            }
            // Crawl-extracted URLs: each is a single-shot probe at the
            // resolved URL (no wordlist expansion — these are concrete
            // endpoints discovered from a response body).
            for (link_url, source, depth, parent) in &frontier_urls {
                // Split into (host_input, path) for the worker.
                let (host_input, path, host) = match url::Url::parse(link_url) {
                    Ok(u) => {
                        let scheme = u.scheme().to_string();
                        let h = u.host_str().unwrap_or("").to_string();
                        let port = u.port().map(|p| format!(":{}", p)).unwrap_or_default();
                        let host_input = format!("{}://{}{}", scheme, h, port);
                        let path = format!("{}{}", u.path(),
                            u.query().map(|q| format!("?{}", q)).unwrap_or_default());
                        (host_input, path, h)
                    }
                    Err(_) => continue,
                };
                let item = ProbeItem {
                    host_input,
                    host,
                    path,
                    depth: *depth,
                    source: source.clone(),
                    parent_url: parent.clone(),
                };
                let sem_c = sem.clone();
                let limiter_c = limiter.clone();
                let cfg_c = cfg.clone();
                let wildcards_c = wildcards.clone();
                let out_file_c = out_file.clone();
                let policy_c = wildcard_policy_arc.clone();
                let counter_c = completed_counter.clone();
                let disc_c = disc_tx.clone();
                let permit = sem_c.acquire_owned().await.ok();
                tasks.push(tokio::spawn(async move {
                    let _p = permit;
                    if limiter_c.enabled() {
                        limiter_c.acquire(&item.host_input).await;
                    }
                    run_probe(item, &cfg_c, &wildcards_c, &out_file_c, *policy_c, &disc_c).await;
                    counter_c.fetch_add(1, Ordering::Relaxed);
                }));
                while tasks.len() > spawn_backlog_cap {
                    tasks.next().await;
                }
            }
            // Drain this round before moving to next.
            while tasks.next().await.is_some() {}
        }
    }
    // Close the discovery channel so any remaining workers don't block.
    drop(disc_tx);

    // Signal ticker to stop and let it draw the final 100%-complete line.
    progress_done.store(true, Ordering::Relaxed);
    let _ = progress_task.await;
    if is_tty {
        // Final redraw at 100% before the newline (ticker may have
        // exited before catching the very-last counter increment).
        use std::io::Write as _;
        let final_completed = completed_counter.load(Ordering::Relaxed);
        let elapsed = started.elapsed().as_secs_f64().max(0.001);
        let rps = final_completed as f64 / elapsed;
        let mut stderr = std::io::stderr();
        let _ = write!(
            stderr,
            "\r\x1b[K  [{}/{}] 100% | {:.0} rps | eta 0s",
            final_completed, total_probes, rps
        );
        let _ = stderr.flush();
        // Newline so the "[+] fuzz done" line doesn't get appended onto
        // the progress bar (which never had a \n).
        eprintln!();
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
    disc_tx: &tokio::sync::mpsc::UnboundedSender<Discovery>,
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
        match dispatch_one(
            &url,
            &item.host_input,
            cfg.body_preview_bytes,
            &cfg.extra_headers,
            cfg.initial_cookie_header.as_deref(),
            cfg.fuzz_follow_redirects,
        )
        .await
        {
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
            // Wildcard check before status filter. Key matches the
            // pre-flight insertion above: full host_input, not bare host.
            // v0.3.9: pass `probe_path_len` so Layer 2 (path-echo) can
            // verify `CL ≈ k × path_len + base`.
            //
            // Strip query + fragment from the path AND percent-decode it
            // before measuring length — servers echoing the path back
            // ALMOST ALWAYS reflect only the URL path component (not the
            // query) and reflect it DECODED (`/%2e%2e/admin` is rendered
            // as `/../admin` = 9 bytes vs 18 raw). Counting raw encoded
            // length inflates the expected CL and pushes real findings
            // outside the tolerance window. Caught 244 FPs total in the
            // v0.3.9 path_echo benchmark before this two-step fix.
            let probe_path_only = item
                .path
                .split(|c| c == '?' || c == '#')
                .next()
                .unwrap_or(&item.path);
            let probe_path_len = decoded_path_len(probe_path_only);
            let mut is_wildcard = false;
            if !matches!(wildcard_policy, WildcardPolicy::Off)
                && wildcards.matches(
                    &item.host_input,
                    parsed.content_length,
                    &parsed.content_type,
                    &parsed.snippet_md5,
                    probe_path_len,
                )
            {
                is_wildcard = true;
            }

            // Status-code filter (include then exclude).
            if !cfg.match_codes.contains(&parsed.status) {
                return;
            }
            // v0.3.7 — `--exclude` filter (default `429,503`; user can
            // override). Applied AFTER match-codes so the user can express
            // both inclusion and exclusion in the same scan.
            if cfg.exclude_codes.contains(&parsed.status) {
                return;
            }
            // v0.3.10 — `--exclude-sizes` filter. Exact content-length
            // match (dirsearch parity). Combined with --exclude-root-size
            // this lets the user drop fake-200 catchall pages by their
            // homepage size without relying on the wildcard detector.
            if !cfg.exclude_sizes.is_empty()
                && cfg.exclude_sizes.contains(&parsed.content_length)
            {
                return;
            }

            // Strict wildcard suppression.
            if is_wildcard && matches!(wildcard_policy, WildcardPolicy::Strict) {
                return;
            }

            let cf = cf_challenge(
                parsed.status,
                &parsed.server,
                &parsed.body_preview_for_output,
            );

            // v0.4.0 — clone fields that the discovery block (below)
            // also needs to read. ParsedResp gets fully consumed by the
            // FuzzRecord move otherwise.
            let rec = FuzzRecord {
                url: url.clone(),
                input: item.host_input.clone(),
                path: item.path.clone(),
                host: item.host.clone(),
                status_code: parsed.status,
                content_length: parsed.content_length,
                content_type: parsed.content_type.clone(),
                title: parsed.title.clone(),
                location: parsed.location.clone(),
                server: parsed.server.clone(),
                webserver: parsed.server.clone(),
                body_preview: parsed.body_preview_for_output.clone(),
                tech: Vec::new(),
                method: "GET",
                is_wildcard,
                wildcard_policy: policy_str,
                via_proxy: cfg.via_proxy,
                attempts,
                elapsed_ms,
                snippet_md5: parsed.snippet_md5.clone(),
                tls_impersonation: tls_tag.to_string(),
                user_agent: ua_used,
                cf_challenge: cf,
                error: None,
                timestamp: now_iso8601(),
                prober: PROBER_TAG,
                depth: item.depth,
                source: item.source.clone(),
                parent_url: item.parent_url.clone(),
            };
            write_record(out_file, &rec, cfg.output_format, cfg.live_findings).await;

            // ── v0.4.0: emit discoveries for multi-round orchestrator ─
            // Only emit when we're NOT already at the deepest round —
            // otherwise discoveries would be dropped anyway. Check both
            // recursion + crawl independently.
            let next_depth = item.depth.saturating_add(1);
            if cfg.recursion_depth > 0 && next_depth <= cfg.recursion_depth {
                if let Some(dir_url) = crate::recurse::detect_directory(
                    &url,
                    parsed.status,
                    &parsed.location,
                    &parsed.body_preview_for_output,
                    cfg.recurse_on_200,
                    cfg.recurse_on_403,
                ) {
                    let _ = disc_tx.send(Discovery::Directory {
                        canonical_url: crate::recurse::canonical_url_key(&dir_url),
                        host: item.host.clone(),
                        depth: next_depth,
                        parent: url.clone(),
                    });
                }
            }
            if cfg.crawl_enabled && next_depth <= cfg.crawl_depth {
                let crawl_cfg = crate::crawl::CrawlCfg {
                    crawl_robots: cfg.crawl_robots,
                    crawl_sitemap: cfg.crawl_sitemap,
                    max_links_per_page: cfg.max_links_per_page,
                    scope_hosts: cfg.scope_hosts.clone(),
                };
                let links = crate::crawl::extract_urls(
                    &parsed.raw_body,
                    &parsed.content_type,
                    &url,
                    &crawl_cfg,
                );
                let source_tag = if url.ends_with("/robots.txt") {
                    "crawl-robots"
                } else if url.ends_with("/sitemap.xml") {
                    "crawl-sitemap"
                } else {
                    "crawl-html"
                };
                for link in links {
                    let _ = disc_tx.send(Discovery::Link {
                        canonical_url: crate::recurse::canonical_url_key(&link),
                        source: source_tag.to_string(),
                        depth: next_depth,
                        parent: url.clone(),
                    });
                }
            }
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
                depth: item.depth,
                source: item.source.clone(),
                parent_url: item.parent_url.clone(),
            };
            write_record(out_file, &rec, cfg.output_format, cfg.live_findings).await;
        }
    }
}

/// v0.3.13 — write a record in the chosen format AND optionally print
/// the dirsearch-style live finding line to stderr. Called by every
/// emitted probe (after wildcard + status-code + size filters pass).
///
/// Live-print is TTY-gated when `is_tty=true` it uses ANSI color cues
/// per HTTP status class (green 2xx / yellow 3xx / cyan 401-403 / etc).
/// `eprintln!` is line-atomic so concurrent worker prints don't
/// interleave mid-line, and `\r\x1b[K` clears the progress bar line so
/// the next ticker redraw lands cleanly below the finding.
async fn write_record(
    out_file: &Arc<Mutex<std::fs::File>>,
    rec: &FuzzRecord,
    format: OutputFormat,
    live: bool,
) {
    // ── 1. Live findings to stderr (UX) ──────────────────────────────
    // Compute is_tty per-call. `IsTerminal::is_terminal()` is a cheap
    // ioctl(TIOCGWINSZ)-style check — sub-microsecond, fine to call
    // once per emitted record.
    let is_tty = std::io::stderr().is_terminal();
    if live && rec.status_code != 0 {
        let line = format_finding_line(rec.status_code, rec.content_length, &rec.url, is_tty);
        if is_tty {
            // \r\x1b[K wipes the progress bar before our line lands; the
            // ticker's next ~100 ms tick redraws the bar below.
            eprintln!("\r\x1b[K{}", line);
        } else {
            eprintln!("{}", line);
        }
    }

    // ── 2. File output in chosen format ──────────────────────────────
    let line = match format {
        OutputFormat::Json => match serde_json::to_string(rec) {
            Ok(s) => s,
            Err(_) => return,
        },
        OutputFormat::Plain => {
            // Plain mode strips the heavy body_preview / VIEWSTATE blob
            // entirely. One line per finding: STATUS SIZE URL.
            format_finding_line(rec.status_code, rec.content_length, &rec.url, false)
        }
    };
    let mut f = out_file.lock().await;
    if let Err(e) = writeln!(*f, "{}", line) {
        if !WRITE_ERR_LOGGED.swap(true, Ordering::Relaxed) {
            eprintln!(
                "[!] fuzz: output write failed: {} (further write errors will be silent)",
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_eta_picks_compact_unit() {
        assert_eq!(format_eta(0), "0s");
        assert_eq!(format_eta(5), "5s");
        assert_eq!(format_eta(59), "59s");
        assert_eq!(format_eta(60), "1m0s");
        assert_eq!(format_eta(90), "1m30s");
        assert_eq!(format_eta(3599), "59m59s");
        assert_eq!(format_eta(3600), "1h0m0s");
        assert_eq!(format_eta(8104), "2h15m4s");
    }

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
        assert_eq!(
            host_to_input("http://target.com:8080"),
            "http://target.com:8080"
        );
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
            depth: 0,
            source: String::new(),
            parent_url: String::new(),
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

    /// Regression: `--rate-limit 0.1` used to round to 0, then clamp to 1
    /// rps. The new fractional-rps path must report enabled() = true so the
    /// user's intent is honored.
    #[test]
    fn host_rate_limiter_supports_fractional_rps() {
        use super::ratelimit::HostRateLimiter;
        assert!(!HostRateLimiter::new(0.0).enabled(), "0.0 = disabled");
        assert!(!HostRateLimiter::new(-1.0).enabled(), "negative = disabled");
        assert!(HostRateLimiter::new(0.1).enabled(), "0.1 rps must enable");
        assert!(HostRateLimiter::new(0.5).enabled(), "0.5 rps must enable");
        assert!(HostRateLimiter::new(1.0).enabled(), "1 rps must enable");
        assert!(HostRateLimiter::new(50.0).enabled(), "50 rps must enable");
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
