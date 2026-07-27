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
use crate::wildcard::{self, WildcardMap};

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
    /// v0.4.9 — full response headers, emitted only under `--response-headers`
    /// (empty otherwise → skipped, so default records stay byte-compatible).
    /// JSON object: lowercase keys, duplicate headers folded with ", ".
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "serialize_response_headers",
        default
    )]
    response_headers: Vec<(String, String)>,
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
    /// v0.4.5 — set to the winning technique (e.g. "X-Original-URL") when this
    /// record is a CONFIRMED 401/403 bypass. `skip_serializing_if` keeps the
    /// JSON byte-compatible for the common (non-bypass) case.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    bypass: Option<String>,
}

fn is_u8_zero(v: &u8) -> bool {
    *v == 0
}

/// Serialize captured response headers as a JSON object (v0.4.9). Keys are
/// already lowercased at capture; duplicate header names (e.g. multiple
/// `set-cookie`) are folded into one `", "`-joined value, first-seen order
/// preserved. Chosen over an array of pairs so downstream `jq`
/// (`.response_headers["content-security-policy"]`) stays trivial.
pub(crate) fn serialize_response_headers<S>(
    headers: &[(String, String)],
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    let mut order: Vec<&str> = Vec::new();
    let mut folded: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    for (k, v) in headers {
        match folded.get_mut(k.as_str()) {
            Some(existing) => {
                existing.push_str(", ");
                existing.push_str(v);
            }
            None => {
                order.push(k.as_str());
                folded.insert(k.as_str(), v.clone());
            }
        }
    }
    let mut m = s.serialize_map(Some(order.len()))?;
    for k in order {
        m.serialize_entry(k, &folded[k])?;
    }
    m.end()
}

/// Per-(host,path) work item. Carries v0.4.0 recursion/crawl provenance
/// so the resulting FuzzRecord can be tagged with depth + source +
/// parent_url for downstream consumers.
#[derive(Clone)]
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
    /// v0.4.5 — auto-recurse into directory-shaped 401/403 dirs (no flag;
    /// smart default) so accessible children behind a protected parent
    /// (e.g. /api=401 → /api/actuator=200) aren't missed. The 401/403 itself
    /// is never emitted; bounded by `max_dirs_per_host`.
    pub recurse_on_auth: bool,
    /// v0.4.5 — native, content-confirmed 401/403 bypass engine (auto-on;
    /// `--safe` sets this false). Bounded per host by `bypass::PER_HOST_PATH_BUDGET`.
    pub bypass_enabled: bool,
    /// Recursion breadth cap — how many DISCOVERED directories per host get
    /// re-fuzzed. Each dir costs a full wordlist pass, so this (with `-R`) is
    /// what actually bounds a recursive scan. v0.4.10 removed the companion
    /// `max_probes_per_host`, which was never enforced.
    pub max_dirs_per_host: usize,
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
    /// v0.4.9 — `--response-headers`: attach the full response header set to
    /// each emitted record (JSON `response_headers` object) and print it under
    /// each live finding on the terminal. Off by default (keeps output small).
    pub response_headers: bool,
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
pub fn read_words(path_spec: &str) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    // v0.4.5 — count comma-separated files so we can emit a per-file load log
    // (transparency for multi-dictionary runs like `-w a.txt,b.txt,c.txt`).
    let file_specs: Vec<&str> = path_spec
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let multi = file_specs.len() > 1;
    for single_path in &file_specs {
        let before = out.len();
        let f = std::fs::File::open(single_path)
            .with_context(|| format!("open wordlist {}", single_path))?;
        let mut in_file = 0usize;
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let normalised = normalize_path(&line);
            if normalised.is_empty() || normalised == "/" {
                continue;
            }
            in_file += 1;
            if seen.insert(normalised.clone()) {
                out.push(normalised);
            }
        }
        if multi {
            // Per-file: entries in the file and how many were NEW (post-dedupe).
            eprintln!(
                "  [wordlist] {} : {} paths (+{} new)",
                single_path,
                in_file,
                out.len() - before
            );
        }
    }
    if out.is_empty() {
        anyhow::bail!(
            "wordlist(s) {} produced zero usable entries",
            path_spec
        );
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
/// v0.5.0 — `--no-color` / `NO_COLOR`. Previously `--no-color` was documented
/// as a no-op claiming "stderr is already plain text, no ANSI" — untrue: the
/// findings lines, progress bar and catchall notices all emit ANSI. Now it
/// genuinely suppresses every escape sequence.
static NO_COLOR: AtomicBool = AtomicBool::new(false);

/// Disable all ANSI output (called once at startup from `--no-color`, or when
/// the conventional `NO_COLOR` env var is set).
pub fn set_no_color() {
    NO_COLOR.store(true, Ordering::Relaxed);
}

/// True when ANSI escapes are permitted: a TTY and colour not disabled.
pub(crate) fn color_ok(is_tty: bool) -> bool {
    is_tty && !NO_COLOR.load(Ordering::Relaxed)
}

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
    /// v0.4.9 — ALL response headers, lowercased names, in wire order with
    /// duplicates preserved. Always captured; only surfaced (JSON + terminal)
    /// when `--response-headers` is set.
    headers: Vec<(String, String)>,
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

    // Headers — case-insensitive lookup of the four we care about, PLUS a
    // full ordered capture (v0.4.9) for `--response-headers`. Names lowercased
    // (HTTP header names are case-insensitive; lowercasing makes `jq`/grep
    // queries deterministic); order + duplicates (e.g. multiple Set-Cookie)
    // preserved. Cheap — we already walk every header here.
    let mut content_type = String::new();
    let mut header_cl: Option<i64> = None;
    let mut location = String::new();
    let mut server = String::new();
    let mut headers: Vec<(String, String)> = Vec::new();
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
        headers.push((lk, vs.to_string()));
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
            headers,
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
/// v0.4.5 — realistic-shape decoy pre-flight paths. The comcast-style catchall
/// fires on dictionary-looking filenames (`.conf`/`.config`/`.git`), so probing
/// only random hex can under-sample its behavior. These random-prefixed
/// (non-existent) decoys make detection see the same catchall the wordlist hits.
fn decoy_preflight_paths() -> Vec<String> {
    let r = || {
        let mut s = String::with_capacity(8);
        for _ in 0..8 {
            let n = fastrand::u8(0..16);
            s.push(if n < 10 {
                (b'0' + n) as char
            } else {
                (b'a' + (n - 10)) as char
            });
        }
        s
    };
    vec![
        format!("/{}.conf", r()),
        format!("/{}.config", r()),
        format!("/{}.log", r()),
        format!("/{}.env", r()),
        format!("/{}/.git/HEAD", r()),
    ]
}

/// Run ONE wildcard pre-flight probe against an explicit `path`. Returns a
/// `ProbeSample` for the layered detector, or `None` when the probe didn't
/// yield a usable body (status outside 200-399 / empty body / network error).
async fn wildcard_preflight_probe(
    host_input: &str,
    body_preview_bytes: usize,
    extra_headers: &[(String, String)],
    initial_cookie_header: Option<&str>,
    path: &str,
) -> Option<crate::wildcard::ProbeSample> {
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
        // v0.4.5: carry the body so the content-aware Layer 1b can fingerprint
        // by normalized content (already captured by dispatch_one — no extra IO).
        raw_body: parsed.raw_body,
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
    let s = if host.starts_with("http://") || host.starts_with("https://") {
        host.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", host)
    };
    // v0.4.7 — drop the scheme's DEFAULT port. Crawl/recursion can surface both
    // `https://x.com` and `https://x.com:443`; keeping them distinct split the
    // wildcard fingerprint AND the per-host budgets, so the same host got
    // fingerprinted twice and spent two bypass budgets. Non-default ports
    // (`:8080`) are preserved — those are genuinely distinct endpoints.
    let (scheme, rest) = if let Some(r) = s.strip_prefix("https://") {
        ("https://", r)
    } else if let Some(r) = s.strip_prefix("http://") {
        ("http://", r)
    } else {
        return s;
    };
    let default_port = if scheme == "https://" { ":443" } else { ":80" };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    match authority.strip_suffix(default_port) {
        Some(a) => format!("{}{}{}", scheme, a, tail),
        None => s,
    }
}

/// Strip scheme + path so `https://target.com/foo` → `target.com`. The scheme's
/// default port is dropped too (v0.4.7) so `x.com` and `x.com:443` are ONE host
/// for the per-host budgets, bypass budget and the output `host` field.
fn bare_host(s: &str) -> String {
    let (default_port, stripped) = if let Some(r) = s.strip_prefix("https://") {
        (":443", r)
    } else if let Some(r) = s.strip_prefix("http://") {
        (":80", r)
    } else {
        ("", s)
    };
    let end = stripped.find(['/', '?', '#']).unwrap_or(stripped.len());
    let hostport = &stripped[..end];
    if !default_port.is_empty() {
        if let Some(h) = hostport.strip_suffix(default_port) {
            return h.to_string();
        }
    }
    hostport.to_string()
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

    // v0.4.8 — total is a LIVE counter, not a fixed round-0 estimate. Recursion
    // (`-r`) and crawl (`--crawl`) enqueue MORE probes as they discover dirs /
    // URLs, so a static `hosts × words` denominator made the progress bar sail
    // past 100% (e.g. 359%). Seed with the round-0 cartesian count; each probe a
    // later round actually spawns bumps it, so the bar stays ≤100% (it dips when
    // a new round adds work — honest recursive-scan behaviour).
    let initial_total = hosts.len() * words.len();
    let total_probes = Arc::new(AtomicUsize::new(initial_total));
    eprintln!(
        "[+] fuzz: {} hosts × {} paths = {} probes (threads={}, retries={}, wildcard={})",
        hosts.len(),
        words.len(),
        initial_total,
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
            // v0.4.5 — build hex + realistic-decoy pre-flight paths and probe
            // them CONCURRENTLY (was sequential): wall-clock = slowest single
            // probe, not the sum. Decoys make detection see the same catchall
            // the dictionary hits (extension-sensitive servers).
            let mut paths: Vec<String> =
                hex_lens.iter().map(|&n| random_hex_path(n)).collect();
            paths.extend(decoy_preflight_paths());
            let total_preflight = paths.len();
            let futs = paths.iter().map(|p| {
                wildcard_preflight_probe(
                    &input,
                    cfg.body_preview_bytes,
                    &cfg.extra_headers,
                    cfg.initial_cookie_header.as_deref(),
                    p,
                )
            });
            let samples: Vec<crate::wildcard::ProbeSample> =
                futures::future::join_all(futs)
                    .await
                    .into_iter()
                    .flatten()
                    .collect();
            match wildcard::detect(&samples, 10) {
                Some(sig) if sig.k.is_some() => {
                    eprintln!(
                        "  [wildcard L2] {} k={} base={} (path-echo detected; {}/{} samples)",
                        host,
                        sig.k.unwrap(),
                        sig.base.unwrap(),
                        samples.len(),
                        total_preflight
                    );
                    wildcard_map.insert(input, sig);
                }
                Some(sig) if sig.content_length < 0 => {
                    eprintln!(
                        "  [wildcard L1] {} prefix-only md5={} ({}/{} samples agreed)",
                        host,
                        sig.snippet_md5,
                        samples.len(),
                        total_preflight
                    );
                    wildcard_map.insert(input, sig);
                }
                Some(sig) if sig.snippet_md5.is_empty() => {
                    eprintln!(
                        "  [wildcard L1b] {} cl={} content-aware ({}/{} samples agreed on normalized body)",
                        host,
                        sig.content_length,
                        samples.len(),
                        total_preflight
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
                        total_preflight
                    );
                    wildcard_map.insert(input, sig);
                }
                None if samples.len() < total_preflight => {
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
    // v0.4.6 — per-directory catchall cache, learned live during the run (both
    // detectors write here). Budget scales with host count.
    let catchall = Arc::new(Mutex::new(CatchallCache::new(hosts.len())));

    // ── Concurrency + rate limiter ─────────────────────────────────────
    let sem = Arc::new(Semaphore::new(cfg.threads.max(1)));
    let limiter = Arc::new(ratelimit::HostRateLimiter::new(cfg.rate_limit_rps));
    let cfg = Arc::new(cfg);
    let wildcard_policy_arc = Arc::new(wildcard_policy);

    // v0.4.5 — wreq pool-panic resilience. Counters track how many probes hit
    // the wreq 5.3 connection-pool assertion race (pool.rs:651) and were
    // retried / ultimately lost. Quiet the (benign, retried) pool assertion on
    // stderr so it doesn't look like a crash; all other panics print normally.
    let panic_retries = Arc::new(AtomicUsize::new(0));
    let panic_failed = Arc::new(AtomicUsize::new(0));
    {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let from_wreq_pool = info
                .location()
                .map(|l| l.file().contains("pool.rs"))
                .unwrap_or(false);
            if from_wreq_pool {
                return; // caught + retried by run_probe_resilient
            }
            default_hook(info);
        }));
    }

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
        let total = total_probes.clone();
        let started_at = started;
        tokio::spawn(async move {
            use std::io::Write as _;
            loop {
                if done.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                let completed = counter.load(Ordering::Relaxed);
                let total_now = total.load(Ordering::Relaxed);
                if is_tty {
                    let elapsed = started_at.elapsed().as_secs_f64().max(0.001);
                    let rps = completed as f64 / elapsed;
                    let pct = (completed as f64 * 100.0 / total_now.max(1) as f64) as u32;
                    let eta_secs = if rps > 0.0 {
                        ((total_now.saturating_sub(completed)) as f64 / rps) as u64
                    } else {
                        0
                    };
                    let mut stderr = std::io::stderr();
                    let _ = write!(
                        stderr,
                        "\r\x1b[K  [{}/{}] {}% | {:.0} rps | eta {}",
                        completed, total_now, pct, rps, format_eta(eta_secs)
                    );
                    let _ = stderr.flush();
                } else {
                    // Piped runs — batched line per 500 completions.
                    // (Was per-200 in v0.3.7 drain-loop counter; the
                    // ticker-task variant uses 500 so the cadence
                    // matches a TTY's ~100 ms refresh visually.)
                    if completed > 0 && completed % 500 == 0 {
                        eprintln!("  [fuzz {}/{}]", completed, total_now);
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
            let catchall = catchall.clone();
            let out_file = out_file.clone();
            let policy = wildcard_policy_arc.clone();
            let counter = completed_counter.clone();
            let disc = disc_tx.clone();
            let pretries = panic_retries.clone();
            let pfailed = panic_failed.clone();

            // Acquire BEFORE spawn — keeps the FuturesUnordered set bounded
            // to the semaphore size + the number of pending awaits, instead
            // of allocating one tokio::task per (host,path) eagerly.
            let permit = sem.acquire_owned().await.ok();

            tasks.push(tokio::spawn(async move {
                let _p = permit;
                if limiter.enabled() {
                    limiter.acquire(&item.host_input).await;
                }
                run_probe_resilient(
                    item, &cfg, &wildcards, &catchall, &out_file, *policy, &disc, &pretries,
                    &pfailed,
                )
                .await;
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
                        Arc::new(crate::recurse::HostBudget::new(cfg.max_dirs_per_host))
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
            // Per-directory catchall detection now happens LIVE inside
            // `run_probe` via the hybrid `CatchallCache` (v0.4.6): each new
            // prefix's shell is learned on demand (frequency + sibling-probe,
            // content-aware) as its paths are probed, so recursed dirs no longer
            // depend on the round-0 host map alone. No per-round pre-flight here.

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
                    let catchall_c = catchall.clone();
                    let out_file_c = out_file.clone();
                    let policy_c = wildcard_policy_arc.clone();
                    let counter_c = completed_counter.clone();
                    let disc_c = disc_tx.clone();
                    let pretries_c = panic_retries.clone();
                    let pfailed_c = panic_failed.clone();
                    // Count this recursion probe into the live denominator.
                    total_probes.fetch_add(1, Ordering::Relaxed);
                    let permit = sem_c.acquire_owned().await.ok();
                    tasks.push(tokio::spawn(async move {
                        let _p = permit;
                        if limiter_c.enabled() {
                            limiter_c.acquire(&item.host_input).await;
                        }
                        run_probe_resilient(
                            item, &cfg_c, &wildcards_c, &catchall_c, &out_file_c, *policy_c,
                            &disc_c, &pretries_c, &pfailed_c,
                        )
                        .await;
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
                let catchall_c = catchall.clone();
                let out_file_c = out_file.clone();
                let policy_c = wildcard_policy_arc.clone();
                let counter_c = completed_counter.clone();
                let disc_c = disc_tx.clone();
                let pretries_c = panic_retries.clone();
                let pfailed_c = panic_failed.clone();
                // Count this crawl probe into the live denominator.
                total_probes.fetch_add(1, Ordering::Relaxed);
                let permit = sem_c.acquire_owned().await.ok();
                tasks.push(tokio::spawn(async move {
                    let _p = permit;
                    if limiter_c.enabled() {
                        limiter_c.acquire(&item.host_input).await;
                    }
                    run_probe_resilient(
                        item, &cfg_c, &wildcards_c, &catchall_c, &out_file_c, *policy_c,
                        &disc_c, &pretries_c, &pfailed_c,
                    )
                    .await;
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
        let final_total = total_probes.load(Ordering::Relaxed);
        let elapsed = started.elapsed().as_secs_f64().max(0.001);
        let rps = final_completed as f64 / elapsed;
        let mut stderr = std::io::stderr();
        let _ = write!(
            stderr,
            "\r\x1b[K  [{}/{}] 100% | {:.0} rps | eta 0s",
            final_completed, final_total, rps
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
    let executed = total_probes.load(Ordering::Relaxed);
    eprintln!(
        "[+] fuzz done: {} probes in {:.2}s ({:.0} rps avg) → {}",
        executed,
        elapsed,
        (executed as f64) / elapsed.max(0.001),
        output_path,
    );
    // v0.4.5 — honest accounting of the wreq pool-panic race (if any fired).
    let pr = panic_retries.load(Ordering::Relaxed);
    let pf = panic_failed.load(Ordering::Relaxed);
    if pr > 0 {
        eprintln!(
            "[+] connection-pool resilience: {} probe(s) hit the wreq pool race and were retried; {} still failed after retry",
            pr, pf
        );
    }
    Ok(())
}

/// One (host, path) probe end-to-end.
/// v0.4.5 — try the conservative 401/403 bypass battery (bypass::variants).
/// Returns `(technique, response, url)` on the FIRST content-confirmed bypass:
/// a **2xx with a non-empty body** whose NORMALIZED content differs from the
/// original block page AND doesn't match the host catchall. Stops at the first
/// win. Never emits a fake-200 (the content + wildcard checks are the guard).
///
/// v0.4.7 — 3xx and empty bodies are NO LONGER accepted. Both guards were
/// vacuous for redirects: a path-mutation like `/admin/..;/` is normalized by
/// most servers to `..` and 302s to the PARENT directory, and that redirect
/// carries a 0-byte body which trivially "differs" from the block page. Real
/// scans showed `/files/admin/ 403` → `/files/admin/..;/ 302 (0B, Location:
/// /files/)` reported as a bypass — while `/files/` was itself 403, and even a
/// NON-EXISTENT dir produced the same 302. No access was ever gained. A genuine
/// bypass (e.g. a server that treats `..;` literally) returns the protected
/// CONTENT: 2xx with a body. Requiring that kills the whole false-positive
/// class without losing a real win.
async fn attempt_auth_bypass(
    item: &ProbeItem,
    original: &ParsedResp,
    cfg: &FuzzCfg,
    wildcards: &Arc<WildcardMap>,
) -> Option<(String, ParsedResp, String)> {
    let orig_norm =
        crate::wildcard::md5_hex(&crate::wildcard::normalize_snippet(&original.raw_body));
    for v in crate::bypass::variants(&item.path) {
        let url = format!("{}{}", item.host_input, v.path);
        // Merge the user's -H headers with this technique's headers.
        let mut headers = cfg.extra_headers.clone();
        headers.extend(v.headers.iter().cloned());
        let Ok((p, _tag, _ua)) = dispatch_one(
            &url,
            &item.host_input,
            cfg.body_preview_bytes,
            &headers,
            cfg.initial_cookie_header.as_deref(),
            false,
        )
        .await
        else {
            continue;
        };
        // Must have actually gotten through AND returned content. 3xx is not a
        // bypass (a redirect hands you no protected data — and for path
        // mutations it usually just resolves one directory UP), and an empty
        // body can't be content-confirmed against anything.
        if !matches!(p.status, 200..=299) || p.raw_body.is_empty() {
            continue;
        }
        // Content must DIFFER from the original 401/403 block page (else the
        // server just returned the same wall with a different status).
        let norm = crate::wildcard::md5_hex(&crate::wildcard::normalize_snippet(&p.raw_body));
        if norm == orig_norm {
            continue;
        }
        // Must not be the host catchall (no fake-200s).
        let plen = decoded_path_len(v.path.split(['?', '#']).next().unwrap_or(&v.path));
        if wildcards.matches_body(
            &item.host_input,
            p.content_length,
            &p.content_type,
            &p.snippet_md5,
            plen,
            &p.raw_body,
        ) {
            continue;
        }
        return Some((v.label.to_string(), p, url));
    }
    None
}

// ── v0.4.6 — per-directory (prefix-routed) catchall suppression ───────────
// Some gateways route each top-level path prefix to a DIFFERENT micro-frontend,
// each returning its OWN constant-size catchall shell for every sub-path
// (e.g. /crm/*=1232B, /core/*=2783B, /sso/*=1560B on one real target). The
// host-level pre-flight probes random paths only at `/`, so it learns just the
// ROOT shell — every per-prefix catchall then sails through strict suppression.
// This cache learns each prefix's shell on demand via TWO cooperating detectors
// and suppresses content-matching hits (never size-only → real pages survive).

/// Distinct paths that must return the identical normalized shell before the
/// zero-traffic frequency detector promotes it to a catchall.
const FREQ_PROMOTE_K: usize = 3;
/// CL slack (bytes) for the frequency detector — a true per-prefix shell is
/// near-constant size; wider drift means "not the same shell", don't count.
const FREQ_CL_TOL: i64 = 24;
/// Per-host cap on distinct parents the sibling-probe detector may sample,
/// bounding added traffic / WAF exposure on huge wordlists.
const MAX_CATCHALL_PARENTS_PER_HOST: usize = 256;

/// Frequency-detector bucket: the set of DISTINCT paths that returned a given
/// `(content_type, normalized_body_hash)`, plus a representative sig to promote.
#[derive(Default)]
struct FreqEntry {
    paths: std::collections::HashSet<String>,
    sig: Option<crate::wildcard::WildcardSig>,
}

/// Live, shared per-run cache for per-directory catchall detection.
#[derive(Default)]
struct CatchallCache {
    /// Confirmed catchall sigs (from BOTH detectors). Checked content-aware.
    learned: Vec<crate::wildcard::WildcardSig>,
    /// (content_type, normalized_snippet_md5) → distinct paths seen + a sig.
    freq: std::collections::HashMap<(String, String), FreqEntry>,
    /// Parents already sibling-sampled (probed to completion / no-catchall).
    probed_parents: std::collections::HashSet<String>,
    /// Parents whose sibling-probe is IN FLIGHT right now. Concurrent hits under
    /// the same parent wait on this instead of leaking (v0.4.6 race close).
    inflight: std::collections::HashSet<String>,
    /// Remaining sibling-probe budget for this run.
    parents_budget: usize,
}

/// True if any learned catchall sig content-matches this response. Shared by
/// steps (a) and the wait-loop so the check stays identical everywhere.
fn any_learned_matches(
    learned: &[crate::wildcard::WildcardSig],
    parsed: &ParsedResp,
    probe_path_len: usize,
) -> bool {
    learned.iter().any(|s| {
        s.matches_probe(
            parsed.content_length,
            &parsed.content_type,
            &parsed.snippet_md5,
            probe_path_len,
            &parsed.raw_body,
        )
    })
}

impl CatchallCache {
    fn new(host_count: usize) -> Self {
        Self {
            parents_budget: MAX_CATCHALL_PARENTS_PER_HOST.saturating_mul(host_count.max(1)),
            ..Default::default()
        }
    }

    /// Detector A (frequency, zero traffic). Record one 2xx response's
    /// normalized shell under `(ct, norm_hash)`. Returns `Some(sig)` the moment
    /// this hit is the K-th DISTINCT path sharing that shell at a near-constant
    /// CL — a newly confirmed catchall — and pushes it into `learned` (deduped).
    /// A materially different CL under the same normalized prefix is rejected so
    /// real varying-size endpoints can't inflate a bucket.
    fn note_frequency(
        &mut self,
        ct: &str,
        norm_hash: &str,
        cl: i64,
        path: &str,
    ) -> Option<crate::wildcard::WildcardSig> {
        let entry = self
            .freq
            .entry((ct.to_string(), norm_hash.to_string()))
            .or_default();
        match &entry.sig {
            Some(s) if (s.content_length - cl).abs() > FREQ_CL_TOL => return None,
            None => {
                entry.sig = Some(crate::wildcard::WildcardSig {
                    content_length: cl,
                    content_type: ct.to_string(),
                    snippet_md5: String::new(),
                    k: None,
                    base: None,
                    tolerance: 10,
                    normalized_snippet_md5: norm_hash.to_string(),
                });
            }
            _ => {}
        }
        entry.paths.insert(path.to_string());
        if entry.paths.len() < FREQ_PROMOTE_K {
            return None;
        }
        let sig = entry.sig.clone()?;
        let dup = self.learned.iter().any(|s| {
            s.content_type == sig.content_type
                && s.normalized_snippet_md5 == sig.normalized_snippet_md5
        });
        if !dup {
            self.learned.push(sig.clone());
        }
        Some(sig)
    }
}

/// Reduce a full URL to its immediate parent prefix (the directory containing
/// the probed path): `https://h/crm/api/v1/auth` → `https://h/crm/api/v1`;
/// `https://h/crm` and `https://h/` → `https://h`. Query/fragment stripped.
fn parent_prefix(url: &str) -> String {
    let (base, path) = match url.find("://") {
        Some(i) => {
            let after = i + 3;
            match url[after..].find('/') {
                Some(j) => (&url[..after + j], &url[after + j..]),
                None => return url.to_string(),
            }
        }
        None => return url.to_string(),
    };
    let path = path.split(|c| c == '?' || c == '#').next().unwrap_or(path);
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) | None => base.to_string(),
        Some(k) => format!("{}{}", base, &trimmed[..k]),
    }
}

/// Hybrid per-directory catchall test. Returns `true` if this 2xx response is a
/// per-prefix catchall shell that should be SUPPRESSED (and not recursed).
/// Never holds the cache lock across the network probe.
async fn catchall_suppresses(
    item: &ProbeItem,
    parsed: &ParsedResp,
    probe_path_len: usize,
    cfg: &FuzzCfg,
    cache: &Arc<Mutex<CatchallCache>>,
) -> bool {
    // Only content-bearing 2xx shells; redirects/empties are out of scope.
    if !matches!(parsed.status, 200..=299) || parsed.raw_body.is_empty() {
        return false;
    }

    // (a) Match against already-learned sigs (content-aware, zero probes).
    {
        let c = cache.lock().await;
        if any_learned_matches(&c.learned, parsed, probe_path_len) {
            return true;
        }
    }

    // (b) Sibling-probe (Detector B): the FIRST hit under a new parent probes
    //     two random siblings to confirm the shell; concurrent hits under the
    //     same parent WAIT for that probe (never leak) rather than emitting.
    let full_url = format!("{}{}", item.host_input, item.path);
    let parent = parent_prefix(&full_url);
    enum Role {
        Probe,
        Wait,
        Skip,
    }
    let role = {
        let mut c = cache.lock().await;
        if c.inflight.contains(&parent) {
            Role::Wait
        } else if !c.probed_parents.contains(&parent) && c.parents_budget > 0 {
            c.probed_parents.insert(parent.clone());
            c.parents_budget -= 1;
            c.inflight.insert(parent.clone());
            Role::Probe
        } else {
            Role::Skip
        }
    };
    match role {
        Role::Probe => {
            // Two random siblings, probed CONCURRENTLY (wall-clock = one probe,
            // not two) so waiters under the same parent unblock fast.
            let spaths: Vec<String> = [16usize, 32usize]
                .iter()
                .map(|&n| random_hex_path(n)) // "/<hex>" → sibling of parent
                .collect();
            let futs = spaths.iter().map(|p| {
                wildcard_preflight_probe(
                    &parent,
                    cfg.body_preview_bytes,
                    &cfg.extra_headers,
                    cfg.initial_cookie_header.as_deref(),
                    p,
                )
            });
            let samples: Vec<crate::wildcard::ProbeSample> =
                futures::future::join_all(futs).await.into_iter().flatten().collect();
            // Require ≥2 agreeing samples so a single random 200 (a real page)
            // can't be mistaken for a catchall.
            let learned_sig = if samples.len() >= 2 {
                crate::wildcard::detect(&samples, 10)
            } else {
                None
            };
            // Clear in-flight AND publish the sig in ONE critical section, so a
            // waiter never sees "not in-flight" without also seeing the sig.
            {
                let mut c = cache.lock().await;
                c.inflight.remove(&parent);
                if let Some(sig) = &learned_sig {
                    eprintln!(
                        "  [catchall] {} cl={} content-aware (sibling-probe)",
                        parent, sig.content_length
                    );
                    c.learned.push(sig.clone());
                }
            }
            if let Some(sig) = learned_sig {
                if sig.matches_probe(
                    parsed.content_length,
                    &parsed.content_type,
                    &parsed.snippet_md5,
                    probe_path_len,
                    &parsed.raw_body,
                ) {
                    return true;
                }
            }
        }
        Role::Wait => {
            // Poll until the in-flight sibling-probe lands (learned a sig we
            // match → suppress) or clears without one (real dir → emit). The
            // prober's remove+publish is atomic, so this never leaks. Budget
            // covers one probe timeout + margin so a slow probe can't force an
            // early give-up (which would leak the shell).
            let max_polls = (cfg.timeout_ms / 10).max(50) as usize + 50;
            for _ in 0..max_polls {
                {
                    let c = cache.lock().await;
                    if any_learned_matches(&c.learned, parsed, probe_path_len) {
                        return true;
                    }
                    if !c.inflight.contains(&parent) {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        Role::Skip => {}
    }

    // (c) Frequency (Detector A, zero traffic): count this normalized shell;
    //     promote once K distinct paths share it at a near-constant CL.
    let norm_hash = crate::wildcard::md5_hex(&crate::wildcard::normalize_snippet(&parsed.raw_body));
    let mut c = cache.lock().await;
    if let Some(sig) = c.note_frequency(
        &parsed.content_type,
        &norm_hash,
        parsed.content_length,
        &item.path,
    ) {
        eprintln!(
            "  [catchall] {} cl={} content-aware ({} paths, frequency)",
            parent, sig.content_length, FREQ_PROMOTE_K
        );
        return true;
    }
    false
}

/// Wraps `run_probe` so a panic mid-probe never crashes the run or silently
/// drops the result. v0.4.5: the wreq 5.3 connection-pool has an
/// `assert!(...is_pending())` race (pool.rs:651) that can fire under high
/// concurrency to one host. We catch the unwind and retry the probe once;
/// counters feed an honest end-of-run summary. The panic happens during the
/// request (before any output lock), so a retry is clean.
#[allow(clippy::too_many_arguments)]
async fn run_probe_resilient(
    item: ProbeItem,
    cfg: &FuzzCfg,
    wildcards: &Arc<WildcardMap>,
    catchall: &Arc<Mutex<CatchallCache>>,
    out_file: &Arc<Mutex<std::fs::File>>,
    wildcard_policy: WildcardPolicy,
    disc_tx: &tokio::sync::mpsc::UnboundedSender<Discovery>,
    panic_retries: &AtomicUsize,
    panic_failed: &AtomicUsize,
) {
    use futures::FutureExt as _;
    let item_retry = item.clone();
    let r = std::panic::AssertUnwindSafe(run_probe(
        item,
        cfg,
        wildcards,
        catchall,
        out_file,
        wildcard_policy,
        disc_tx,
    ))
    .catch_unwind()
    .await;
    if r.is_err() {
        panic_retries.fetch_add(1, Ordering::Relaxed);
        let r2 = std::panic::AssertUnwindSafe(run_probe(
            item_retry,
            cfg,
            wildcards,
            catchall,
            out_file,
            wildcard_policy,
            disc_tx,
        ))
        .catch_unwind()
        .await;
        if r2.is_err() {
            panic_failed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn run_probe(
    item: ProbeItem,
    cfg: &FuzzCfg,
    wildcards: &Arc<WildcardMap>,
    catchall: &Arc<Mutex<CatchallCache>>,
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
                && wildcards.matches_body(
                    &item.host_input,
                    parsed.content_length,
                    &parsed.content_type,
                    &parsed.snippet_md5,
                    probe_path_len,
                    &parsed.raw_body,
                )
            {
                is_wildcard = true;
            }

            // v0.4.6 — per-directory (prefix-routed) catchall suppression.
            // The host-level check above only knows the ROOT shell; this learns
            // each path-prefix's OWN catchall on demand (frequency + sibling
            // probe, content-aware) so gateways that route /crm, /core, /sso …
            // to different constant-size shells don't flood. Skipped when the
            // host layer already flagged it, when policy is Off, or on non-2xx.
            if !is_wildcard
                && !matches!(wildcard_policy, WildcardPolicy::Off)
                && catchall_suppresses(&item, &parsed, probe_path_len, cfg, catchall).await
            {
                is_wildcard = true;
            }

            // v0.4.5 — strict wildcard suppression FIRST: a catchall match is
            // neither emitted NOR recursed. Moved above discovery so a wildcard
            // never spawns recursion.
            if is_wildcard && matches!(wildcard_policy, WildcardPolicy::Strict) {
                return;
            }

            // ── Recursion discovery — HOISTED above the emit filter (v0.4.5) ──
            // Runs regardless of `match_codes`, so directory-shaped 401/403
            // dirs are descended into WITHOUT being emitted (your "no 401
            // noise"), and accessible children (e.g. /api/actuator) still
            // surface. 200/3xx directory detection is unchanged. Bounded by
            // --max-dirs-per-host in the orchestrator.
            let next_depth = item.depth.saturating_add(1);
            if cfg.recursion_depth > 0 && next_depth <= cfg.recursion_depth {
                if let Some(dir_url) = crate::recurse::detect_directory(
                    &url,
                    parsed.status,
                    &parsed.location,
                    &parsed.body_preview_for_output,
                    cfg.recurse_on_200,
                    cfg.recurse_on_403,
                    cfg.recurse_on_auth,
                ) {
                    let _ = disc_tx.send(Discovery::Directory {
                        canonical_url: crate::recurse::canonical_url_key(&dir_url),
                        host: item.host.clone(),
                        depth: next_depth,
                        parent: url.clone(),
                    });
                }
            }

            // ── Native 401/403 bypass (v0.4.5, auto-on unless --safe) ─────────
            // On a forbidden response, try the conservative bypass battery.
            // Confirmed wins are emitted as their own record tagged `bypass`;
            // the raw 401/403 is NOT emitted (it's filtered below). Per-host
            // budget bounds traffic.
            if cfg.bypass_enabled
                && matches!(parsed.status, 401 | 403)
                && crate::bypass::charge_host(&item.host)
            {
                if let Some((technique, bp, bp_url)) =
                    attempt_auth_bypass(&item, &parsed, cfg, wildcards).await
                {
                    eprintln!(
                        "  [bypass] {} {}→{} via {}",
                        bp_url, parsed.status, bp.status, technique
                    );
                    let cf = cf_challenge(bp.status, &bp.server, &bp.body_preview_for_output);
                    let rec = FuzzRecord {
                        url: bp_url,
                        input: item.host_input.clone(),
                        path: item.path.clone(),
                        host: item.host.clone(),
                        status_code: bp.status,
                        content_length: bp.content_length,
                        content_type: bp.content_type.clone(),
                        title: bp.title.clone(),
                        location: bp.location.clone(),
                        server: bp.server.clone(),
                        webserver: bp.server.clone(),
                        body_preview: bp.body_preview_for_output.clone(),
                        response_headers: if cfg.response_headers {
                            bp.headers.clone()
                        } else {
                            Vec::new()
                        },
                        tech: Vec::new(),
                        method: "GET",
                        is_wildcard: false,
                        wildcard_policy: policy_str.clone(),
                        via_proxy: cfg.via_proxy,
                        attempts,
                        elapsed_ms,
                        snippet_md5: bp.snippet_md5.clone(),
                        tls_impersonation: tls_tag.to_string(),
                        user_agent: ua_used.clone(),
                        cf_challenge: cf,
                        error: None,
                        timestamp: now_iso8601(),
                        prober: PROBER_TAG,
                        depth: item.depth,
                        source: "bypass".to_string(),
                        parent_url: url.clone(),
                        bypass: Some(technique),
                    };
                    write_record(out_file, &rec, cfg.output_format, cfg.live_findings).await;
                }
            }

            // ── Emit filters (gate OUTPUT only; discovery already done) ───────
            // Status-code filter (include then exclude).
            if !cfg.match_codes.contains(&parsed.status) {
                return;
            }
            // v0.3.7 — `--exclude` filter (default `429,503`).
            if cfg.exclude_codes.contains(&parsed.status) {
                return;
            }
            // v0.3.10 — `--exclude-sizes` exact content-length match.
            if !cfg.exclude_sizes.is_empty()
                && cfg.exclude_sizes.contains(&parsed.content_length)
            {
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
                response_headers: if cfg.response_headers {
                    parsed.headers.clone()
                } else {
                    Vec::new()
                },
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
                bypass: None,
            };
            write_record(out_file, &rec, cfg.output_format, cfg.live_findings).await;

            // ── v0.4.5: crawl-link discovery. (Directory/recursion discovery
            // was hoisted ABOVE the emit filter so 401/403 dirs recurse
            // without being emitted; it reused `next_depth` computed there.)
            // Crawl runs only on emitted, status-matched pages.
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
                response_headers: Vec::new(), // no response on a connect error
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
                bypass: None,
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
        let line =
            format_finding_line(rec.status_code, rec.content_length, &rec.url, color_ok(is_tty));
        if is_tty {
            // \r\x1b[K wipes the progress bar before our line lands; the
            // ticker's next ~100 ms tick redraws the bar below.
            eprintln!("\r\x1b[K{}", line);
        } else {
            eprintln!("{}", line);
        }
        // v0.4.9 — `--response-headers`: dump the header set under the finding.
        // Non-empty only when the flag is set (populated at record build).
        if !rec.response_headers.is_empty() {
            for (k, v) in &rec.response_headers {
                if color_ok(is_tty) {
                    // dim grey so headers don't drown the finding lines.
                    eprintln!("\r\x1b[K      \x1b[2m{}: {}\x1b[0m", k, v);
                } else if is_tty {
                    eprintln!("\r\x1b[K      {}: {}", k, v);
                } else {
                    eprintln!("      {}: {}", k, v);
                }
            }
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

    // ── v0.4.6 per-directory catchall helpers ────────────────────────────

    #[test]
    fn parent_prefix_strips_last_segment() {
        assert_eq!(
            parent_prefix("https://h.com/crm/api/v1/auth"),
            "https://h.com/crm/api/v1"
        );
        // one-segment path → host root
        assert_eq!(parent_prefix("https://h.com/crm"), "https://h.com");
        // trailing slash → parent is host root
        assert_eq!(parent_prefix("https://h.com/crm/"), "https://h.com");
        // root and bare host → host root
        assert_eq!(parent_prefix("https://h.com/"), "https://h.com");
        assert_eq!(parent_prefix("https://h.com"), "https://h.com");
        // query/fragment ignored
        assert_eq!(
            parent_prefix("https://h.com/a/b?x=1#y"),
            "https://h.com/a"
        );
    }

    #[test]
    fn frequency_promotes_only_at_k_distinct_paths() {
        let mut c = CatchallCache::new(1);
        // Two distinct paths of the same shell → not yet a catchall.
        assert!(c.note_frequency("text/html", "hashA", 1232, "/crm/a").is_none());
        assert!(c.note_frequency("text/html", "hashA", 1232, "/crm/b").is_none());
        // The K-th (3rd) distinct path promotes it.
        let sig = c
            .note_frequency("text/html", "hashA", 1230, "/crm/c")
            .expect("promotes at K distinct paths");
        assert_eq!(sig.normalized_snippet_md5, "hashA");
        assert!(sig.snippet_md5.is_empty(), "content-aware sig (no exact md5)");
        // A repeat of an already-seen path must NOT advance the count.
        let mut c2 = CatchallCache::new(1);
        assert!(c2.note_frequency("text/html", "h", 500, "/x").is_none());
        assert!(c2.note_frequency("text/html", "h", 500, "/x").is_none());
        assert!(c2.note_frequency("text/html", "h", 500, "/x").is_none());
    }

    #[test]
    fn frequency_rejects_material_cl_drift_and_different_content() {
        let mut c = CatchallCache::new(1);
        // Same normalized prefix but a real varying-size endpoint (CL drifts
        // far beyond FREQ_CL_TOL) must never promote → real results survive.
        assert!(c.note_frequency("application/json", "shape", 100, "/api/a").is_none());
        assert!(c.note_frequency("application/json", "shape", 4000, "/api/b").is_none());
        assert!(c.note_frequency("application/json", "shape", 9000, "/api/c").is_none());
        // Distinct content hashes never accumulate toward one catchall.
        let mut c2 = CatchallCache::new(1);
        assert!(c2.note_frequency("text/html", "h1", 800, "/p1").is_none());
        assert!(c2.note_frequency("text/html", "h2", 800, "/p2").is_none());
        assert!(c2.note_frequency("text/html", "h3", 800, "/p3").is_none());
    }

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

    /// v0.4.7 — `x.com` and `x.com:443` must collapse to ONE host so the
    /// wildcard fingerprint and the per-host / bypass budgets aren't split.
    /// Non-default ports stay distinct.
    #[test]
    fn default_port_is_normalized_away() {
        assert_eq!(bare_host("https://x.com:443/foo"), "x.com");
        assert_eq!(bare_host("https://x.com:443"), "x.com");
        assert_eq!(bare_host("http://x.com:80/abc"), "x.com");
        // non-default ports preserved (genuinely different endpoints)
        assert_eq!(bare_host("https://x.com:8443"), "x.com:8443");
        assert_eq!(bare_host("http://x.com:8080"), "x.com:8080");
        // a port that merely ENDS in 80/443 must not be mangled
        assert_eq!(bare_host("http://x.com:8080/a"), "x.com:8080");
        assert_eq!(bare_host("https://x.com:10443"), "x.com:10443");

        assert_eq!(host_to_input("https://x.com:443"), "https://x.com");
        assert_eq!(host_to_input("https://x.com:443/api"), "https://x.com/api");
        assert_eq!(host_to_input("http://x.com:80"), "http://x.com");
        assert_eq!(host_to_input("https://x.com:8443"), "https://x.com:8443");
        // both spellings converge on one key
        assert_eq!(
            host_to_input("https://x.com:443"),
            host_to_input("https://x.com")
        );
        assert_eq!(bare_host("https://x.com:443"), bare_host("https://x.com"));
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
            response_headers: vec![],
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
            bypass: None,
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
        // v0.4.5 — schema compat: `bypass` absent when None (downstream-safe).
        assert!(!s.contains("\"bypass\""), "bypass must be omitted when None");
        // v0.4.9 — response_headers omitted when empty (default records stay small).
        assert!(
            !s.contains("\"response_headers\""),
            "response_headers must be omitted when empty"
        );
    }

    /// v0.4.9 — `response_headers` serializes as a JSON OBJECT with lowercase
    /// keys, and duplicate headers (e.g. set-cookie) fold into one ", "-joined
    /// value in first-seen order.
    #[test]
    fn response_headers_serialize_as_folded_object() {
        let mut rec = FuzzRecord {
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
            body_preview: "".into(),
            response_headers: vec![
                ("content-type".into(), "text/html".into()),
                ("set-cookie".into(), "a=1".into()),
                ("set-cookie".into(), "b=2".into()),
                ("x-frame-options".into(), "DENY".into()),
            ],
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
            bypass: None,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
        let h = &v["response_headers"];
        assert!(h.is_object(), "response_headers must be a JSON object");
        assert_eq!(h["content-type"], "text/html");
        assert_eq!(h["x-frame-options"], "DENY");
        // duplicate set-cookie folded, order preserved
        assert_eq!(h["set-cookie"], "a=1, b=2");

        // empty → field omitted entirely
        rec.response_headers.clear();
        assert!(!serde_json::to_string(&rec).unwrap().contains("response_headers"));
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
