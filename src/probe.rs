//! Async HTTP(S) probing with TLS impersonation (JA3/JA4 + HTTP/2 SETTINGS
//! fingerprint matching real Chrome / Firefox / Safari / Edge versions).
//!
//! Enrich mode samples a preconfigured browser client per probe. Fuzz mode
//! selects one deterministic profile per host so wildcard pre-flight and
//! wordlist responses remain comparable on UA-dependent applications.
//!
//! Why wreq + BoringSSL instead of reqwest + native-tls/rustls:
//! reqwest's TLS ClientHello is fixed and visibly non-Chrome (cipher suite
//! ordering, TLS extensions, signature algorithms, supported groups). Modern
//! WAFs fingerprint that via JA4+ (the JA3 successor — Cloudflare, AWS, and
//! VirusTotal use it; JA3 itself was broken by Chrome 110 randomising the
//! extensions order). wreq is built on BoringSSL — the same TLS stack
//! Chrome ships — and `wreq-util` provides 100+ preconfigured emulation
//! profiles whose ClientHello + HTTP/2 SETTINGS frame are byte-identical
//! to the impersonated browser version.
//!
//! What's NOT bypassed:
//!  - Cloudflare's behavioural challenges (JS execution, mouse events) — those
//!    need a headless browser, not raw HTTP. We're optimising for "first
//!    request gets through the static-signature rule layer".
//!  - Per-IP rate limits / reputation. The user is expected to throttle and
//!    rotate egress IPs at a higher layer if they hit those.

use once_cell::sync::OnceCell;
use base64::Engine as _;
use percent_encoding::percent_decode_str;
use std::collections::HashSet;
use std::future::Future;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};
use wreq::Client;
use wreq_util::Emulation;

/// Probe outcome. Body is preserved for the downstream tech-detector
/// (which inspects `<script src>`, `<meta>`, and inline markers).
///
/// `status_line` + `via_https` are populated during probe but not consumed
/// by the current output writers — kept on the struct because external
/// scripts that import this crate use them. Clippy dead-code allowlisted.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HttpProbeResult {
    pub status_code: u16,
    pub status_line: String,
    pub title: Option<String>,
    /// Initial URL that produced this response, before following redirects.
    pub probe_url: String,
    pub final_url: Option<String>,
    pub chain: Vec<String>,
    pub via_https: bool,
    pub content_length: Option<u64>,
    pub word_count: usize,
    /// Body line count (httpx parity — emitted as `lines`). Counts
    /// `\n`-separated lines via `str::lines()`.
    pub line_count: usize,
    pub server: Option<String>,
    pub location: Option<String>,
    /// Response Content-Type header value (e.g. "text/html; charset=utf-8").
    /// None when the response had no such header.
    pub content_type: Option<String>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub body: String,
    /// Wall-clock time from the moment `http_probe_once` started its first
    /// `send()` to the moment the final response (terminal hop) finished
    /// streaming. Includes every redirect-chase hop. Maps to httpx's
    /// `time` field via `format_elapsed_go`.
    pub elapsed: Duration,
}

/// Format a `Duration` the way Go's `time.Duration.String()` does — picks
/// the largest reasonable unit (ns / µs / ms / s), prints with up to 9
/// fractional digits, trims trailing zeros. Matches httpx's `time` field
/// (e.g. "662.326051ms", "1.5s", "300µs").
pub fn format_elapsed_go(d: Duration) -> String {
    let nanos = d.as_nanos() as u64;
    if nanos == 0 {
        return "0s".to_string();
    }
    if nanos >= 1_000_000_000 {
        let int_part = nanos / 1_000_000_000;
        let frac = nanos % 1_000_000_000;
        if frac == 0 {
            return format!("{}s", int_part);
        }
        let s = format!("{}.{:09}", int_part, frac);
        return format!("{}s", s.trim_end_matches('0'));
    }
    if nanos >= 1_000_000 {
        let int_part = nanos / 1_000_000;
        let frac = nanos % 1_000_000;
        if frac == 0 {
            return format!("{}ms", int_part);
        }
        let s = format!("{}.{:06}", int_part, frac);
        return format!("{}ms", s.trim_end_matches('0'));
    }
    if nanos >= 1_000 {
        let int_part = nanos / 1_000;
        let frac = nanos % 1_000;
        if frac == 0 {
            return format!("{}µs", int_part);
        }
        let s = format!("{}.{:03}", int_part, frac);
        return format!("{}µs", s.trim_end_matches('0'));
    }
    format!("{}ns", nanos)
}

/// Case-insensitive `<title>` extractor, whitespace-collapsed, ≤160 chars.
pub fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let tag_start = lower.find("<title")?;
    let after_open = tag_start + lower[tag_start..].find('>')? + 1;
    let end_rel = lower[after_open..].find("</title>")?;
    let raw = &html[after_open..after_open + end_rel];
    let collapsed: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed.chars().take(160).collect())
    }
}

/// Resolve a Location header value relative to the URL it came from.
pub fn resolve_redirect_url(base: &str, loc: &str) -> String {
    url::Url::parse(base)
        .and_then(|url| url.join(loc))
        .map(Into::into)
        .unwrap_or_else(|_| loc.to_string())
}

fn same_origin(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (url::Url::parse(left), url::Url::parse(right)) else {
        return false;
    };
    left.scheme() == right.scheme()
        && left.host_str().map(str::to_ascii_lowercase)
            == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default()
}

/// Consume at most `cap` decoded response bytes. Stopping early drops the
/// response body so a server that ignores Range cannot force an entire archive
/// or an unbounded stream into memory.
pub async fn read_body_capped(mut response: wreq::Response, cap: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::with_capacity(cap.min(16 * 1024));
    while body.len() < cap {
        let chunk = response.chunk().await.map_err(|e| e.to_string())?;
        let Some(chunk) = chunk else { break };
        if append_capped(&mut body, &chunk, cap) {
            break;
        }
    }
    Ok(body)
}

fn append_capped(body: &mut Vec<u8>, chunk: &[u8], cap: usize) -> bool {
    let remaining = cap.saturating_sub(body.len());
    body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    chunk.len() >= remaining
}

/// One slot in the impersonation pool. Each slot is a fully-built client
/// pinned to a specific browser version; per-probe we pick one at random,
/// giving the appearance (to a WAF) of dozens of different real browsers
/// scanning the same site.
///
/// Accept-Language is kept per-slot too because real browsers vary it by
/// install — and some WAFs cross-check Accept-Language consistency vs the
/// presumed locale of the TLS / HTTP-2 fingerprint.
///
/// `tag` is the short label emitted in the fuzz-mode JSONL `tls_impersonation`
/// field (e.g. `"chrome-137"`, `"firefox-139"`, `"vanilla"`). It is set when
/// the pool is built so the fuzz worker doesn't need a runtime lookup.
pub struct PoolSlot {
    client: Client,
    pub accept_lang: &'static str,
    pub tag: &'static str,
}

static POOL: OnceCell<Vec<PoolSlot>> = OnceCell::new();
static PROXY_POOL: OnceCell<ProxyPool> = OnceCell::new();
static WREQ_POOL_HOOK: Once = Once::new();
static WREQ_POOL_RETRIES: AtomicUsize = AtomicUsize::new(0);
static WREQ_POOL_FAILURES: AtomicUsize = AtomicUsize::new(0);
const WREQ_POOL_ASSERTION: &str =
    "assertion failed: Pin::new(&mut rx).poll(cx).is_pending()";

/// v0.5.0 — user auth for the ENRICH probe path (`-H`, `--bearer`, `--cookie`).
///
/// Before v0.5.0 these flags were parsed but reached only fuzz mode, because
/// `AuthCtx` was built inside the fuzz block. Enrich probes went out
/// **unauthenticated with no warning** — `httpxer -u https://internal
/// --bearer $TOK` silently sent no Authorization header at all.
///
/// Stored process-globally (same shape as `POOL`) rather than threaded through
/// `probe_hostname` → `http_probe_with_retry` → `http_probe_once`, so the fix
/// adds no new parameters to three public signatures and their call sites.
/// Set once at startup via `init_auth`; empty when no auth flags were given.
static AUTH: OnceCell<(Vec<(String, String)>, Option<String>)> = OnceCell::new();

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ProxySchemeCounts {
    http: usize,
    https: usize,
    socks4: usize,
    socks5: usize,
}

/// Validated proxy input. `--proxy` accepts one endpoint directly or a file
/// containing one endpoint per line. Endpoint credentials stay inside wreq's
/// parsed `Proxy` value and are never rendered in diagnostics.
pub struct ProxyConfig {
    endpoints: Vec<ProxyEndpoint>,
    from_file: bool,
    counts: ProxySchemeCounts,
}

impl ProxyConfig {
    pub fn from_spec(spec: &str) -> anyhow::Result<Self> {
        let forced_file = spec.strip_prefix('@');
        let path = forced_file.map(PathBuf::from).unwrap_or_else(|| PathBuf::from(spec));
        let has_explicit_scheme = spec.contains("://");
        let file_like = forced_file.is_some()
            || path.is_file()
            || (!has_explicit_scheme
                && (spec.contains(std::path::MAIN_SEPARATOR)
                    || spec.contains('/')
                    || spec.contains('\\')
                    || ["txt", "list", "lst", "csv"].iter().any(|ext| {
                        path.extension()
                            .and_then(|v| v.to_str())
                            .is_some_and(|v| v.eq_ignore_ascii_case(ext))
                    })));

        let entries = if file_like {
            if !path.is_file() {
                anyhow::bail!("--proxy file does not exist or is not a regular file");
            }
            read_proxy_file(&path)?
        } else {
            vec![(1usize, spec.trim().to_string())]
        };

        let mut endpoints = Vec::new();
        let mut counts = ProxySchemeCounts::default();
        let mut seen = HashSet::new();
        for (line, raw) in entries {
            let (normalized, proxy, family) = parse_proxy_entry(&raw)
                .map_err(|reason| anyhow::anyhow!("invalid proxy entry at line {}: {}", line, reason))?;
            if !seen.insert(normalized) {
                continue;
            }
            match family {
                "http" => counts.http += 1,
                "https" => counts.https += 1,
                "socks4" | "socks4a" => counts.socks4 += 1,
                "socks5" | "socks5h" => counts.socks5 += 1,
                _ => unreachable!("proxy scheme was validated"),
            }
            endpoints.push(proxy);
        }
        if endpoints.is_empty() {
            anyhow::bail!("--proxy file contains no usable endpoints");
        }

        Ok(Self {
            endpoints,
            from_file: file_like,
            counts,
        })
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn source_label(&self) -> &'static str {
        if self.from_file { "file" } else { "URL" }
    }

    pub fn scheme_summary(&self) -> String {
        format!(
            "http={}, https={}, socks4={}, socks5={}",
            self.counts.http, self.counts.https, self.counts.socks4, self.counts.socks5
        )
    }
}

fn read_proxy_file(path: &Path) -> anyhow::Result<Vec<(usize, String)>> {
    let file = std::fs::File::open(path).map_err(|e| anyhow::anyhow!("open --proxy file: {}", e))?;
    let mut entries = Vec::new();
    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| anyhow::anyhow!("read --proxy file line {}: {}", idx + 1, e))?;
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        entries.push((idx + 1, value.to_string()));
    }
    Ok(entries)
}

fn parse_proxy_entry(raw: &str) -> Result<(String, ProxyEndpoint, &'static str), &'static str> {
    if raw.is_empty() {
        return Err("empty endpoint");
    }
    let normalized = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{}", raw)
    };
    let parsed = url::Url::parse(&normalized).map_err(|_| "malformed URL")?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    let family = match scheme.as_str() {
        "http" => "http",
        "https" => "https",
        "socks4" => "socks4",
        "socks4a" => "socks4a",
        "socks5" => "socks5",
        "socks5h" => "socks5h",
        _ => return Err("unsupported scheme (use http, https, socks4, socks4a, socks5, or socks5h)"),
    };
    if parsed.host_str().is_none() {
        return Err("missing host");
    }
    if !parsed.username().is_empty() && parsed.password().is_none() {
        return Err("proxy username requires a password");
    }
    if matches!(family, "socks4" | "socks4a")
        && (!parsed.username().is_empty() || parsed.password().is_some())
    {
        return Err("SOCKS4 authentication is not supported; use SOCKS5 for credentials");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("query strings and fragments are not supported");
    }
    if !matches!(parsed.path(), "" | "/") {
        return Err("URL paths are not supported");
    }
    let canonical = parsed.to_string();
    let proxy = wreq::Proxy::all(canonical.as_str())
        .map_err(|_| "endpoint could not be parsed or resolved")?;
    let http_auth = if matches!(family, "http" | "https") {
        match parsed.password() {
            Some(password) => {
                let username = percent_decode_str(parsed.username())
                    .decode_utf8()
                    .map_err(|_| "username is not valid UTF-8")?;
                let password = percent_decode_str(password)
                    .decode_utf8()
                    .map_err(|_| "password is not valid UTF-8")?;
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{}", username, password));
                Some(
                    wreq::header::HeaderValue::from_str(&format!("Basic {}", encoded))
                        .map_err(|_| "credentials are not valid HTTP header data")?,
                )
            }
            None => None,
        }
    } else {
        None
    };
    Ok((canonical, ProxyEndpoint { proxy, http_auth }, family))
}

#[derive(Clone)]
struct ProxyEndpoint {
    proxy: wreq::Proxy,
    http_auth: Option<wreq::header::HeaderValue>,
}

struct ProxyPool {
    endpoints: Vec<ProxyEndpoint>,
    next: AtomicUsize,
}

impl ProxyPool {
    fn new(endpoints: Vec<ProxyEndpoint>) -> Self {
        Self {
            endpoints,
            next: AtomicUsize::new(0),
        }
    }

    fn next(&self) -> Option<ProxyEndpoint> {
        if self.endpoints.is_empty() {
            return None;
        }
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.endpoints.len();
        Some(self.endpoints[idx].clone())
    }
}

impl PoolSlot {
    /// Build a request with this slot's stable browser profile and the next
    /// configured egress proxy. The proxy is selected here, not on the client,
    /// so redirects, retries, pre-flight, backup, and fuzz probes all rotate.
    pub fn get(&self, url: &str) -> wreq::RequestBuilder {
        self.with_proxy(self.client.get(url), url)
    }

    pub fn head(&self, url: &str) -> wreq::RequestBuilder {
        self.with_proxy(self.client.head(url), url)
    }

    fn with_proxy(&self, request: wreq::RequestBuilder, url: &str) -> wreq::RequestBuilder {
        self.with_proxy_endpoint(request, url, PROXY_POOL.get().and_then(ProxyPool::next))
    }

    fn with_proxy_endpoint(
        &self,
        request: wreq::RequestBuilder,
        url: &str,
        endpoint: Option<ProxyEndpoint>,
    ) -> wreq::RequestBuilder {
        match endpoint {
            Some(endpoint) => {
                let request = request.proxy(endpoint.proxy);
                let plain_http = url::Url::parse(url)
                    .ok()
                    .is_some_and(|target| target.scheme() == "http");
                match (plain_http, endpoint.http_auth) {
                    (true, Some(auth)) => request.header(wreq::header::PROXY_AUTHORIZATION, auth),
                    _ => request,
                }
            }
            None => request,
        }
    }
}

fn is_wreq_pool_panic(payload: &(dyn std::any::Any + Send)) -> bool {
    payload
        .downcast_ref::<&str>()
        .is_some_and(|message| message.contains(WREQ_POOL_ASSERTION))
        || payload
            .downcast_ref::<String>()
            .is_some_and(|message| message.contains(WREQ_POOL_ASSERTION))
}

fn install_wreq_pool_panic_hook() {
    WREQ_POOL_HOOK.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let exact_pool_assertion = info
                .location()
                .is_some_and(|location| {
                    location.file().contains("wreq-")
                        && location.file().ends_with("/src/util/client/pool.rs")
                })
                && is_wreq_pool_panic(info.payload());
            if !exact_pool_assertion {
                default_hook(info);
            }
        }));
    });
}

/// Retry only the known wreq 5.3 checkout race. Any unrelated panic resumes
/// unwinding so application defects remain visible.
pub async fn retry_wreq_pool_once<F, Fut, T>(mut operation: F) -> Result<T, ()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = T>,
{
    use futures::FutureExt as _;

    match std::panic::AssertUnwindSafe(operation())
        .catch_unwind()
        .await
    {
        Ok(output) => Ok(output),
        Err(payload) if is_wreq_pool_panic(payload.as_ref()) => {
            WREQ_POOL_RETRIES.fetch_add(1, Ordering::Relaxed);
            match std::panic::AssertUnwindSafe(operation())
                .catch_unwind()
                .await
            {
                Ok(output) => Ok(output),
                Err(payload) if is_wreq_pool_panic(payload.as_ref()) => {
                    WREQ_POOL_FAILURES.fetch_add(1, Ordering::Relaxed);
                    Err(())
                }
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

pub fn wreq_pool_panic_stats() -> (usize, usize) {
    (
        WREQ_POOL_RETRIES.load(Ordering::Relaxed),
        WREQ_POOL_FAILURES.load(Ordering::Relaxed),
    )
}

/// Install the user's auth headers + initial cookie for enrich-mode probes.
/// Idempotent — a second call is ignored (matches `init_pool` semantics).
pub fn init_auth(headers: Vec<(String, String)>, cookie: Option<String>) {
    let _ = AUTH.set((headers, cookie));
}

/// Build the client pool. Called once from main, before any probes fire.
/// Each emulation profile gets one preconfigured client (no per-probe build
/// overhead) — `wreq::Client` already handles concurrent use across tasks.
///
/// Profile pool kept ~10 entries: enough variety to defeat single-profile
/// rule-blocks, small enough that all client builds finish in ms.
///
/// Proxy selection is attached by `PoolSlot::get` per request. Keeping it off
/// the client lets one stable TLS/browser profile rotate across a mixed proxy
/// file without constructing `profiles × proxies` clients.
pub fn init_pool(
    timeout_ms: u64,
    no_impersonate: bool,
    proxy_config: Option<ProxyConfig>,
) -> anyhow::Result<()> {
    install_wreq_pool_panic_hook();
    if let Some(config) = proxy_config {
        let _ = PROXY_POOL.set(ProxyPool::new(config.endpoints));
    }

    POOL.get_or_init(|| {
        let timeout = Duration::from_millis(timeout_ms);
        // 16-slot pool — wide-enough variety that a WAF watching one scanning
        // IP sees a plausible mix of desktop + mobile + browser versions, not
        // a single repeating JA4 hash. Includes mobile profiles (iOS Safari,
        // Firefox Android) because the mobile share of real internet traffic
        // is roughly 50%; an all-desktop scan stands out.
        let profiles: &[(Emulation, &str, &str)] = &[
            // Desktop Chrome — broadest real-world share
            (Emulation::Chrome137, "en-US,en;q=0.9", "chrome-137"),
            (Emulation::Chrome136, "en-US,en;q=0.9", "chrome-136"),
            (Emulation::Chrome135, "en-GB,en;q=0.9", "chrome-135"),
            (
                Emulation::Chrome133,
                "en-US,en;q=0.9,fr;q=0.8",
                "chrome-133",
            ),
            (
                Emulation::Chrome131,
                "en-US,en;q=0.9,es;q=0.8",
                "chrome-131",
            ),
            // Desktop Firefox
            (Emulation::Firefox139, "en-US,en;q=0.5", "firefox-139"),
            (
                Emulation::Firefox136,
                "en-US,en;q=0.5,de;q=0.3",
                "firefox-136",
            ),
            (Emulation::Firefox133, "en-US,en;q=0.5", "firefox-133"),
            // Desktop Safari (macOS)
            (Emulation::Safari18_5, "en-US,en;q=0.9", "safari-18.5"),
            (Emulation::Safari18_3_1, "en-US,en;q=0.9", "safari-18.3.1"),
            (Emulation::Safari18_2, "en-US,en;q=0.9", "safari-18.2"),
            // Desktop Edge (Chromium-based — distinct JA4 from Chrome because
            // of slightly different cipher suite ordering and HTTP-2 settings)
            (Emulation::Edge134, "en-US,en;q=0.9", "edge-134"),
            (Emulation::Edge131, "en-US,en;q=0.9", "edge-131"),
            // Mobile Safari (iOS)
            (
                Emulation::SafariIos18_1_1,
                "en-US,en;q=0.9",
                "safari-ios-18.1.1",
            ),
            (
                Emulation::SafariIos17_4_1,
                "en-US,en;q=0.9",
                "safari-ios-17.4.1",
            ),
            // Mobile Firefox (Android)
            (
                Emulation::FirefoxAndroid135,
                "en-US,en;q=0.5",
                "firefox-android-135",
            ),
        ];
        let mut pool: Vec<PoolSlot> = Vec::new();
        for (emul, lang, tag) in profiles {
            let mut b = Client::builder()
                .timeout(timeout)
                .connect_timeout(timeout)
                .cert_verification(false);
            if !no_impersonate {
                b = b.emulation(*emul);
            }
            if let Ok(c) = b.build() {
                pool.push(PoolSlot {
                    client: c,
                    accept_lang: lang,
                    tag: if no_impersonate { "vanilla" } else { tag },
                });
            }
        }
        if pool.is_empty() {
            // Final safety net — at minimum one plain client so probes don't
            // all silently no-op if every profile build fails.
            let b = Client::builder().timeout(timeout);
            if let Ok(c) = b.build() {
                pool.push(PoolSlot {
                    client: c,
                    accept_lang: "en-US,en;q=0.9",
                    tag: "vanilla",
                });
            }
        }
        pool
    });
    Ok(())
}

fn pick_slot() -> Option<&'static PoolSlot> {
    let pool = POOL.get()?;
    if pool.is_empty() {
        return None;
    }
    Some(&pool[fastrand::usize(0..pool.len())])
}

/// Deterministic per-host slot picker. Hashes `host_key` to one fixed slot in
/// the pool, so every probe against the same host uses the same TLS/UA
/// profile. Fuzz mode's wildcard fingerprint (CL, content-type, snippet_md5)
/// is computed at pre-flight; if the matching probes used a different
/// profile, a UA-varying server (mobile-vs-desktop layouts) would produce a
/// different snippet and the wildcard would silently fail to suppress.
///
/// Across distinct hosts the hash still spreads load over the pool, so a
/// multi-target scan keeps the per-host JA4 variety the enrich path gets.
pub fn pick_pool_slot_for(host_key: &str) -> Option<&'static PoolSlot> {
    let pool = POOL.get()?;
    if pool.is_empty() {
        return None;
    }
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    host_key.hash(&mut hasher);
    Some(&pool[(hasher.finish() as usize) % pool.len()])
}

/// One probe attempt — up to `max_redirects` hops, 2 MiB streamed body cap.
/// Returns None on first-hop network failure (caller may retry).
///
/// `max_redirects` is the maximum number of REDIRECT hops to chase after
/// the initial URL — total URLs probed is `1 + max_redirects` when every
/// hop returns a 3xx. Set to 0 to mimic `--no-follow-redirects` from this
/// path. Default at call site is 10 (matches httpx `-mr 10`).
pub async fn http_probe_once(
    url: &str,
    follow: bool,
    max_redirects: usize,
) -> Option<HttpProbeResult> {
    let slot = pick_slot()?;
    let started_https = url.starts_with("https://");
    let mut current = url.to_string();
    let mut chain: Vec<String> = Vec::new();
    let mut last: Option<Hop> = None;
    // `last_url` shadows `current` at every successful hop, so a mid-chain
    // network failure (where `current` has already been advanced to the
    // next-hop URL we couldn't fetch) doesn't leak that unreachable URL into
    // the record's `final_url`. Always set together with `last`.
    let mut last_url: Option<String> = None;
    let probe_start = Instant::now();
    // The loop walks the start URL + up to max_redirects redirect hops.
    let last_hop_inclusive = max_redirects;

    for hop in 0..=last_hop_inclusive {
        // The emulation profile already sets a matching UA, Accept-Encoding,
        // sec-ch-ua etc. — we just add Accept-Language for variety and a
        // browser-like Accept header for HTML targets (httpx-style).
        let mut req = slot
            .get(&current)
            .header("Accept-Language", slot.accept_lang)
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            );
        // User-supplied headers and cookies are scoped to the original origin.
        // Replaying them after a cross-origin redirect would disclose bearer
        // tokens, API keys or session cookies to the redirect destination.
        if same_origin(url, &current) {
            if let Some((extra, cookie)) = AUTH.get() {
            for (n, v) in extra {
                req = req.header(n.as_str(), v.as_str());
            }
            if let Some(c) = cookie {
                req = req.header("Cookie", c.as_str());
            }
            }
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(_) => {
                if hop == 0 {
                    return None;
                }
                break;
            }
        };

        let status = resp.status().as_u16();
        let status_text = resp.status().canonical_reason().unwrap_or("").to_string();

        let header_cl: Option<u64> = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        let location: Option<String> = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let server: Option<String> = resp
            .headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let content_type: Option<String> = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Capture every header for tech-detect. Multi-value Set-Cookie is
        // split into individual (name, value) cookie pairs.
        let mut headers_out: Vec<(String, String)> = Vec::with_capacity(resp.headers().len());
        let mut cookies_out: Vec<(String, String)> = Vec::new();
        for (n, v) in resp.headers().iter() {
            if let Ok(vs) = v.to_str() {
                let lname = n.as_str().to_ascii_lowercase();
                if lname == "set-cookie" {
                    if let Some((cn, rest)) = vs.split_once('=') {
                        let cv = rest.split([';', ',']).next().unwrap_or("");
                        cookies_out.push((cn.trim().to_string(), cv.trim().to_string()));
                    }
                }
                headers_out.push((lname, vs.to_string()));
            }
        }

        // 2 MiB streamed body cap. Loop on chunk() so we stop reading the
        // moment we hit the cap — rogue endpoints can't OOM-flood us.
        const BODY_CAP: usize = 2 * 1024 * 1024;
        let mut body_bytes: Vec<u8> = Vec::with_capacity(16 * 1024);
        let mut resp_mut = resp;
        while let Ok(Some(chunk)) = resp_mut.chunk().await {
            let remaining = BODY_CAP.saturating_sub(body_bytes.len());
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
        let body_capped = body_len >= BODY_CAP;
        let body_str = String::from_utf8_lossy(&body_bytes).into_owned();
        let title = extract_title(&body_str);
        let word_count = body_str.split_whitespace().count();
        let line_count = body_str.lines().count();

        // Wire Content-Length wins; else body length when not capped; else None.
        let content_length: Option<u64> = header_cl.or(if body_capped {
            None
        } else if body_len > 0 {
            Some(body_len as u64)
        } else {
            None
        });

        last = Some(Hop {
            status,
            status_text,
            title,
            content_length,
            word_count,
            line_count,
            server,
            location: location.clone(),
            content_type,
            headers: headers_out,
            cookies: cookies_out,
            body: body_str,
        });
        last_url = Some(current.clone());

        let is_redirect = (300..400).contains(&status);
        if !follow || !is_redirect {
            break;
        }
        match location {
            Some(loc) => {
                let next = resolve_redirect_url(&current, &loc);
                chain.push(current);
                current = next;
            }
            None => break,
        }
    }

    let h = last?;
    // `last_url` is always `Some` when `last` is — they're set together. The
    // unwrap fallback to `current` is defensive only.
    let last_hop_url = last_url.unwrap_or_else(|| current.clone());
    let final_url = if chain.is_empty() {
        None
    } else {
        Some(last_hop_url.clone())
    };
    Some(HttpProbeResult {
        status_code: h.status,
        status_line: format!("HTTP/1.1 {} {}", h.status, h.status_text),
        title: h.title,
        probe_url: url.to_string(),
        final_url,
        chain,
        via_https: started_https || last_hop_url.starts_with("https://"),
        content_length: h.content_length,
        word_count: h.word_count,
        line_count: h.line_count,
        server: h.server,
        location: h.location,
        content_type: h.content_type,
        headers: h.headers,
        cookies: h.cookies,
        body: h.body,
        elapsed: probe_start.elapsed(),
    })
}

struct Hop {
    status: u16,
    status_text: String,
    title: Option<String>,
    content_length: Option<u64>,
    word_count: usize,
    line_count: usize,
    server: Option<String>,
    location: Option<String>,
    content_type: Option<String>,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    body: String,
}

/// Retry-once + scheme-flip wrapper. Async (no spawn_blocking needed because
/// wreq is already async).
pub async fn http_probe_with_retry(
    url: &str,
    follow: bool,
    max_redirects: usize,
) -> Option<HttpProbeResult> {
    if let Ok(Some(r)) = retry_wreq_pool_once(|| http_probe_once(url, follow, max_redirects)).await {
        return Some(r);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    if let Ok(Some(r)) = retry_wreq_pool_once(|| http_probe_once(url, follow, max_redirects)).await {
        return Some(r);
    }
    // Scheme flip is useful on non-standard ports only — :80 / :443 rarely
    // cross-speak in practice. Use the real URL parser so paths that
    // happen to contain `:` (e.g. `/a:80/b`) aren't mistaken for the port.
    let is_http = url.starts_with("http://");
    let is_https = url.starts_with("https://");
    let non_standard_port = url::Url::parse(url)
        .ok()
        .and_then(|u| u.port_or_known_default())
        .map(|p| !matches!(p, 80 | 443))
        .unwrap_or(false);
    if !non_standard_port {
        return None;
    }
    let alt = if is_http {
        url.replacen("http://", "https://", 1)
    } else if is_https {
        url.replacen("https://", "http://", 1)
    } else {
        return None;
    };
    retry_wreq_pool_once(|| http_probe_once(&alt, follow, max_redirects))
        .await
        .unwrap_or(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_config_accepts_direct_authenticated_url() {
        let config = ProxyConfig::from_spec("http://alice:secret@127.0.0.1:8080").unwrap();
        assert_eq!(config.len(), 1);
        assert_eq!(config.source_label(), "URL");
        assert_eq!(config.counts.http, 1);
    }

    #[test]
    fn proxy_file_accepts_mixed_schemes_and_deduplicates() {
        let path = std::env::temp_dir().join(format!(
            "httpxer-proxies-{}-{}.txt",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::write(
            &path,
            concat!(
                "# mixed proxy list\n",
                "http://127.0.0.1:8001\n",
                "https://user:pass@127.0.0.1:8002\n",
                "socks4://127.0.0.1:8003\n",
                "socks5://127.0.0.1:8004\n",
                "socks5h://user:pass@127.0.0.1:8005\n",
                "127.0.0.1:8006\n",
                "http://127.0.0.1:8001\n",
            ),
        )
        .unwrap();

        let config = ProxyConfig::from_spec(path.to_str().unwrap()).unwrap();
        assert_eq!(config.len(), 6);
        assert_eq!(config.source_label(), "file");
        assert_eq!(
            config.counts,
            ProxySchemeCounts {
                http: 2,
                https: 1,
                socks4: 1,
                socks5: 2,
            }
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn proxy_errors_do_not_echo_credentials() {
        let error = ProxyConfig::from_spec("ftp://alice:topsecret@127.0.0.1:21")
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("unsupported scheme"));
        assert!(!error.contains("alice"));
        assert!(!error.contains("topsecret"));
    }

    #[test]
    fn socks4_credentials_are_rejected_without_panicking() {
        let result = std::panic::catch_unwind(|| {
            ProxyConfig::from_spec("socks4://alice:secret@127.0.0.1:1080")
        });
        assert!(result.is_ok(), "SOCKS4 validation must not panic");
        let error = result.unwrap().err().unwrap().to_string();
        assert!(error.contains("SOCKS4 authentication is not supported"));
        assert!(!error.contains("alice"));
        assert!(!error.contains("secret"));
    }

    async fn one_shot_http_proxy(marker: &'static [u8]) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                marker.len()
            );
            stream.write_all(header.as_bytes()).await.unwrap();
            stream.write_all(marker).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        format!("http://{}", address)
    }

    #[tokio::test]
    async fn authenticated_proxy_entry_sends_basic_authorization() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            request_tx
                .send(String::from_utf8_lossy(&request[..read]).into_owned())
                .unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let raw = format!("http://alice:secret@{}", address);
        let (_, endpoint, _) = parse_proxy_entry(&raw).unwrap();
        let slot = PoolSlot {
            client: Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            accept_lang: "en-US,en;q=0.9",
            tag: "test",
        };
        let response = slot
            .with_proxy_endpoint(
                slot.client.get("http://target.invalid/auth-check"),
                "http://target.invalid/auth-check",
                Some(endpoint),
            )
            .send()
            .await
            .unwrap();
        let _ = read_body_capped(response, 8).await.unwrap();

        let request = request_rx.await.unwrap().to_ascii_lowercase();
        assert!(
            request.contains("proxy-authorization: basic ywxpy2u6c2vjcmv0"),
            "captured request:\n{}",
            request
        );
    }

    #[tokio::test]
    async fn authenticated_proxy_entry_authorizes_https_connect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).await.unwrap();
            request_tx
                .send(String::from_utf8_lossy(&request[..read]).into_owned())
                .unwrap();
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let raw = format!("http://alice:secret@{}", address);
        let (_, endpoint, _) = parse_proxy_entry(&raw).unwrap();
        let slot = PoolSlot {
            client: Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            accept_lang: "en-US,en;q=0.9",
            tag: "test",
        };
        let _ = slot
            .with_proxy_endpoint(
                slot.client.get("https://target.invalid/connect-check"),
                "https://target.invalid/connect-check",
                Some(endpoint),
            )
            .send()
            .await;

        let request = request_rx.await.unwrap().to_ascii_lowercase();
        assert!(request.starts_with("connect target.invalid:443 http/1.1"));
        assert!(
            request.contains("proxy-authorization: basic ywxpy2u6c2vjcmv0"),
            "captured CONNECT request:\n{}",
            request
        );
    }

    #[tokio::test]
    async fn request_level_proxy_pool_rotates_endpoints() {
        let first = one_shot_http_proxy(b"first").await;
        let second = one_shot_http_proxy(b"second").await;
        let (_, first_proxy, _) = parse_proxy_entry(&first).unwrap();
        let (_, second_proxy, _) = parse_proxy_entry(&second).unwrap();
        let proxy_pool = ProxyPool::new(vec![first_proxy, second_proxy]);
        let slot = PoolSlot {
            client: Client::builder()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
            accept_lang: "en-US,en;q=0.9",
            tag: "test",
        };

        let first_response = slot
            .with_proxy_endpoint(
                slot.client.get("http://target.invalid/one"),
                "http://target.invalid/one",
                proxy_pool.next(),
            )
            .send()
            .await
            .unwrap();
        let first_body = read_body_capped(first_response, 32).await.unwrap();
        let second_response = slot
            .with_proxy_endpoint(
                slot.client.get("http://target.invalid/two"),
                "http://target.invalid/two",
                proxy_pool.next(),
            )
            .send()
            .await
            .unwrap();
        let second_body = read_body_capped(second_response, 32).await.unwrap();

        assert_eq!(first_body, b"first");
        assert_eq!(second_body, b"second");
    }

    #[test]
    fn resolve_redirect_url_absolute() {
        assert_eq!(
            resolve_redirect_url("https://a.com/x", "https://b.com/y"),
            "https://b.com/y"
        );
    }

    #[test]
    fn resolve_redirect_url_root_relative() {
        assert_eq!(
            resolve_redirect_url("https://a.com/x/y", "/z"),
            "https://a.com/z"
        );
    }

    #[test]
    fn resolve_redirect_url_relative() {
        assert_eq!(
            resolve_redirect_url("https://a.com/x/y", "z"),
            "https://a.com/x/z"
        );
        assert_eq!(resolve_redirect_url("https://a.com", "z"), "https://a.com/z");
    }

    #[test]
    fn resolve_redirect_url_handles_rfc3986_forms() {
        assert_eq!(
            resolve_redirect_url("https://a.com/x/y", "?q=1"),
            "https://a.com/x/y?q=1"
        );
        assert_eq!(
            resolve_redirect_url("https://a.com/x/y", "//b.com/z"),
            "https://b.com/z"
        );
        assert_eq!(
            resolve_redirect_url("https://a.com/x/y", "../z"),
            "https://a.com/z"
        );
    }

    #[test]
    fn redirect_credentials_require_same_origin() {
        assert!(same_origin("https://a.com/x", "https://a.com/y"));
        assert!(same_origin("https://a.com/x", "https://a.com:443/y"));
        assert!(!same_origin("https://a.com/x", "http://a.com/y"));
        assert!(!same_origin("https://a.com/x", "https://a.com:8443/y"));
        assert!(!same_origin("https://a.com/x", "https://b.com/y"));
    }

    #[test]
    fn capped_append_never_exceeds_limit() {
        let mut body = vec![1, 2];
        assert!(append_capped(&mut body, &[3, 4, 5, 6], 4));
        assert_eq!(body, vec![1, 2, 3, 4]);
        assert!(append_capped(&mut body, &[7], 4));
        assert_eq!(body.len(), 4);
    }

    #[tokio::test]
    async fn known_wreq_pool_assertion_is_retried_once() {
        let attempts = AtomicUsize::new(0);
        let result = retry_wreq_pool_once(|| async {
            if attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                panic!("{}", WREQ_POOL_ASSERTION);
            }
            7usize
        })
        .await;

        assert_eq!(result, Ok(7));
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        assert!(!is_wreq_pool_panic(&"different panic"));
    }

    #[test]
    fn format_elapsed_go_picks_correct_unit() {
        use std::time::Duration;
        assert_eq!(format_elapsed_go(Duration::ZERO), "0s");
        assert_eq!(format_elapsed_go(Duration::from_nanos(500)), "500ns");
        assert_eq!(format_elapsed_go(Duration::from_micros(300)), "300µs");
        assert_eq!(format_elapsed_go(Duration::from_micros(1500)), "1.5ms");
        assert_eq!(
            format_elapsed_go(Duration::from_nanos(662_326_051)),
            "662.326051ms",
            "Go-style ms with µs precision"
        );
        assert_eq!(format_elapsed_go(Duration::from_secs(1)), "1s");
        assert_eq!(
            format_elapsed_go(Duration::from_nanos(1_500_000_000)),
            "1.5s"
        );
        assert_eq!(
            format_elapsed_go(Duration::from_nanos(1_001_000_000)),
            "1.001s"
        );
    }

    #[test]
    fn extract_title_basic() {
        assert_eq!(extract_title("<title>Hi</title>"), Some("Hi".to_string()));
        assert_eq!(
            extract_title("<TITLE>  multi  word  </TITLE>"),
            Some("multi word".to_string())
        );
        assert_eq!(extract_title("<title></title>"), None);
        assert_eq!(extract_title("no title here"), None);
    }
}

/// Bare-hostname input: try https:// first, fall back to http://. Matches
/// httpx's default behaviour for scheme-less list entries.
pub async fn probe_hostname(
    host: &str,
    follow: bool,
    max_redirects: usize,
) -> Option<HttpProbeResult> {
    let https = format!("https://{}", host);
    if let Some(r) = http_probe_with_retry(&https, follow, max_redirects).await {
        return Some(r);
    }
    let http = format!("http://{}", host);
    http_probe_with_retry(&http, follow, max_redirects).await
}
