//! Async HTTP(S) probing with TLS impersonation (JA3/JA4 + HTTP/2 SETTINGS
//! fingerprint matching real Chrome / Firefox / Safari / Edge versions).
//!
//! Per probe we pick a random preconfigured client from a rotating pool, so
//! a scan from one IP presents dozens of different real-browser fingerprints
//! to a WAF — no static signature for Cloudflare / Akamai / Imperva /
//! Datadome / PerimeterX to rule-block on.
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
use std::time::Duration;
use wreq::Client;
use wreq_util::Emulation;

/// Probe outcome. Body is preserved for the downstream tech-detector
/// (which inspects `<script src>`, `<meta>`, and inline markers).
#[derive(Debug, Clone)]
pub struct HttpProbeResult {
    pub status_code: u16,
    pub status_line: String,
    pub title: Option<String>,
    pub final_url: Option<String>,
    pub chain: Vec<String>,
    pub via_https: bool,
    pub content_length: Option<u64>,
    pub word_count: usize,
    pub server: Option<String>,
    pub location: Option<String>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub body: String,
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
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return loc.to_string();
    }
    let scheme_end = match base.find("://") {
        Some(i) => i + 3,
        None => return loc.to_string(),
    };
    let host_end = base[scheme_end..]
        .find('/')
        .map(|i| scheme_end + i)
        .unwrap_or(base.len());
    let origin = &base[..host_end];
    if loc.starts_with('/') {
        format!("{}{}", origin, loc)
    } else {
        let last_slash = base
            .rfind('/')
            .filter(|&i| i >= scheme_end + 2)
            .unwrap_or(host_end);
        format!("{}/{}", &base[..last_slash], loc)
    }
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
    pub client: Client,
    pub accept_lang: &'static str,
    pub tag: &'static str,
}

static POOL: OnceCell<Vec<PoolSlot>> = OnceCell::new();

/// Build the client pool. Called once from main, before any probes fire.
/// Each emulation profile gets one preconfigured client (no per-probe build
/// overhead) — `wreq::Client` already handles concurrent use across tasks.
///
/// Profile pool kept ~10 entries: enough variety to defeat single-profile
/// rule-blocks, small enough that all client builds finish in ms.
pub fn init_pool(timeout_ms: u64, no_impersonate: bool) {
    POOL.get_or_init(|| {
        let timeout = Duration::from_millis(timeout_ms);
        // 16-slot pool — wide-enough variety that a WAF watching one scanning
        // IP sees a plausible mix of desktop + mobile + browser versions, not
        // a single repeating JA4 hash. Includes mobile profiles (iOS Safari,
        // Firefox Android) because the mobile share of real internet traffic
        // is roughly 50%; an all-desktop scan stands out.
        let profiles: &[(Emulation, &str, &str)] = &[
            // Desktop Chrome — broadest real-world share
            (Emulation::Chrome137, "en-US,en;q=0.9",       "chrome-137"),
            (Emulation::Chrome136, "en-US,en;q=0.9",       "chrome-136"),
            (Emulation::Chrome135, "en-GB,en;q=0.9",       "chrome-135"),
            (Emulation::Chrome133, "en-US,en;q=0.9,fr;q=0.8", "chrome-133"),
            (Emulation::Chrome131, "en-US,en;q=0.9,es;q=0.8", "chrome-131"),
            // Desktop Firefox
            (Emulation::Firefox139, "en-US,en;q=0.5",       "firefox-139"),
            (Emulation::Firefox136, "en-US,en;q=0.5,de;q=0.3", "firefox-136"),
            (Emulation::Firefox133, "en-US,en;q=0.5",       "firefox-133"),
            // Desktop Safari (macOS)
            (Emulation::Safari18_5,   "en-US,en;q=0.9", "safari-18.5"),
            (Emulation::Safari18_3_1, "en-US,en;q=0.9", "safari-18.3.1"),
            (Emulation::Safari18_2,   "en-US,en;q=0.9", "safari-18.2"),
            // Desktop Edge (Chromium-based — distinct JA4 from Chrome because
            // of slightly different cipher suite ordering and HTTP-2 settings)
            (Emulation::Edge134, "en-US,en;q=0.9", "edge-134"),
            (Emulation::Edge131, "en-US,en;q=0.9", "edge-131"),
            // Mobile Safari (iOS)
            (Emulation::SafariIos18_1_1, "en-US,en;q=0.9", "safari-ios-18.1.1"),
            (Emulation::SafariIos17_4_1, "en-US,en;q=0.9", "safari-ios-17.4.1"),
            // Mobile Firefox (Android)
            (Emulation::FirefoxAndroid135, "en-US,en;q=0.5", "firefox-android-135"),
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
            if let Ok(c) = Client::builder().timeout(timeout).build() {
                pool.push(PoolSlot {
                    client: c,
                    accept_lang: "en-US,en;q=0.9",
                    tag: "vanilla",
                });
            }
        }
        pool
    });
}

/// Public accessor for the impersonation pool — the fuzz orchestrator needs
/// direct access to the slot (client + accept_lang + tag) because it issues
/// raw single-shot GETs with `redirect::Policy::none()` rather than going
/// through `http_probe_once`'s manual hop-chasing loop.
///
/// `init_pool` MUST have been called before this — that's already done at the
/// top of `main()` for both enrich and fuzz mode.
pub fn pick_pool_slot() -> Option<&'static PoolSlot> {
    pick_slot()
}

fn pick_slot() -> Option<&'static PoolSlot> {
    let pool = POOL.get()?;
    if pool.is_empty() {
        return None;
    }
    Some(&pool[fastrand::usize(0..pool.len())])
}

/// One probe attempt — up to 4 redirect hops, 2 MiB streamed body cap.
/// Returns None on first-hop network failure (caller may retry).
pub async fn http_probe_once(url: &str, follow: bool) -> Option<HttpProbeResult> {
    let slot = pick_slot()?;
    let client = &slot.client;
    let started_https = url.starts_with("https://");
    let mut current = url.to_string();
    let mut chain: Vec<String> = Vec::new();
    let mut last: Option<Hop> = None;

    for hop in 0..=3 {
        // The emulation profile already sets a matching UA, Accept-Encoding,
        // sec-ch-ua etc. — we just add Accept-Language for variety and a
        // browser-like Accept header for HTML targets (httpx-style).
        let resp = match client
            .get(&current)
            .header("Accept-Language", slot.accept_lang)
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            )
            .send()
            .await
        {
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

        // Wire Content-Length wins; else body length when not capped; else None.
        let content_length: Option<u64> = header_cl.or_else(|| {
            if body_capped {
                None
            } else if body_len > 0 {
                Some(body_len as u64)
            } else {
                None
            }
        });

        last = Some(Hop {
            status,
            status_text,
            title,
            content_length,
            word_count,
            server,
            location: location.clone(),
            headers: headers_out,
            cookies: cookies_out,
            body: body_str,
        });

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
    let final_url = if chain.is_empty() {
        None
    } else {
        Some(current.clone())
    };
    Some(HttpProbeResult {
        status_code: h.status,
        status_line: format!("HTTP/1.1 {} {}", h.status, h.status_text),
        title: h.title,
        final_url,
        chain,
        via_https: started_https || current.starts_with("https://"),
        content_length: h.content_length,
        word_count: h.word_count,
        server: h.server,
        location: h.location,
        headers: h.headers,
        cookies: h.cookies,
        body: h.body,
    })
}

struct Hop {
    status: u16,
    status_text: String,
    title: Option<String>,
    content_length: Option<u64>,
    word_count: usize,
    server: Option<String>,
    location: Option<String>,
    headers: Vec<(String, String)>,
    cookies: Vec<(String, String)>,
    body: String,
}

/// Retry-once + scheme-flip wrapper. Async (no spawn_blocking needed because
/// wreq is already async).
pub async fn http_probe_with_retry(url: &str, follow: bool) -> Option<HttpProbeResult> {
    if let Some(r) = http_probe_once(url, follow).await {
        return Some(r);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    if let Some(r) = http_probe_once(url, follow).await {
        return Some(r);
    }
    // Scheme flip is useful on non-standard ports only — :80 / :443 rarely
    // cross-speak in practice.
    let is_http = url.starts_with("http://");
    let is_https = url.starts_with("https://");
    let non_standard_port = url
        .rsplit_once(':')
        .and_then(|(_, rest)| rest.split('/').next())
        .and_then(|p| p.parse::<u16>().ok())
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
    http_probe_once(&alt, follow).await
}

/// Bare-hostname input: try https:// first, fall back to http://. Matches
/// httpx's default behaviour for scheme-less list entries.
pub async fn probe_hostname(host: &str, follow: bool) -> Option<HttpProbeResult> {
    let https = format!("https://{}", host);
    if let Some(r) = http_probe_with_retry(&https, follow).await {
        return Some(r);
    }
    let http = format!("http://{}", host);
    http_probe_with_retry(&http, follow).await
}
