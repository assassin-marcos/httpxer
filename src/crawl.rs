//! Response-body link extraction for `--crawl` mode.
//!
//! Five extractors:
//!   - **HTML** — regex-based (not a full DOM, but covers every
//!     dirsearch-equivalent tag: `<a href>`, `<link href>`, `<script src>`,
//!     `<form action>`, `<iframe src>`, `<img src>`, `<source src>`,
//!     `<embed src>`, `<object data>`, plus `<meta http-equiv=refresh>`)
//!   - **JavaScript** — quoted same-origin route literals, inline scripts,
//!     framework request calls, and source-map references
//!   - **JSON** — URL/path values, OpenAPI-style path keys, manifests, and
//!     JavaScript embedded in source-map `sourcesContent`
//!   - **robots.txt** — Disallow / Allow / Sitemap directives
//!   - **sitemap.xml** — `<loc>` URL extraction
//!
//! Filtering pipeline (in order):
//!   1. Absolutise relative URLs against the response URL
//!   2. Same-host scope check (built-in deny list + user `--scope`)
//!   3. Low-value static-asset drop (.css/images/fonts/media; JS is retained)
//!   4. Self-referencing URL drop (extracted URL == source URL)
//!   5. Dedup
//!   6. Cap at `max_links_per_page`
//!
use once_cell::sync::OnceCell;
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use url::Url;

const MAX_CANDIDATE_LEN: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedLink {
    pub url: String,
    pub source: &'static str,
}

/// Built-in third-party CDN / analytics deny list. Never crawled even when
/// `--scope *` is set. Catches the common case of `<script src>` pointing
/// at a public CDN — those URLs aren't part of the target's attack surface.
pub const THIRD_PARTY_HOSTS: &[&str] = &[
    "googleapis.com",
    "gstatic.com",
    "google-analytics.com",
    "googletagmanager.com",
    "googletagservices.com",
    "doubleclick.net",
    "cloudflare.com",
    "cloudfront.net",
    "fastly.net",
    "fastlylb.net",
    "jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "bootstrapcdn.com",
    "maxcdn.com",
    "jquery.com",
    "facebook.com",
    "facebook.net",
    "twitter.com",
    "youtube.com",
    "youtu.be",
    "vimeo.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "githubusercontent.com",
    "googleusercontent.com",
    "amazonaws.com",
    "azureedge.net",
    "akamaihd.net",
    "akamaized.net",
    "newrelic.com",
    "nr-data.net",
    "sentry.io",
    "intercom.io",
    "stripe.com",
    "stripe.network",
    "segment.io",
    "segment.com",
    "hotjar.com",
    "fonts.gstatic.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "use.fontawesome.com",
];

/// Static-asset extensions we skip from crawled URLs. Recursing /
/// re-probing these adds noise and rarely yields findings.
/// Pure-media extensions skipped from crawl-extracted URLs. Re-fuzzed:
///
/// v0.4.2 — TRIMMED from 40 entries to 22 (pure media only). Previous
/// list was dropping HIGHLY recon-valuable extensions:
///   - js, mjs, map (JS files contain API endpoints + secrets!)
///   - json, xml, rss, atom (config / API responses / sitemaps)
///   - pdf (often-leaked documents)
///   - zip, tar.gz, 7z, rar, etc. (BACKUP archives — recon GOLD)
///   - exe, msi, deb, rpm (installers — leak intel about deployments)
///
/// Result: `<script src="/Scripts/jquery.js">` extracted from a page
/// like `/Result.aspx` was getting silently dropped, so users saw 0
/// crawl-discovered findings even when the page had dozens of links.
/// dirsearch keeps everything by default — we now match that policy
/// for the categories that matter.
///
/// Still filtered (low recon value, just confirms the asset exists):
///   - css (rarely contains endpoints; mostly noise)
///   - images (png/jpg/gif/svg/ico/webp/bmp/tiff/avif)
///   - fonts (woff/woff2/ttf/eot/otf)
///   - video (mp4/webm/mov/avi/mkv/flv/m4v)
///   - audio (mp3/wav/ogg/flac/m4a)
pub const STATIC_ASSET_EXTS: &[&str] = &[
    // CSS — sometimes has commented endpoints but mostly noise
    "css",
    // Images
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tiff", "avif",
    // Fonts
    "woff", "woff2", "ttf", "eot", "otf",
    // Video / audio
    "mp4", "webm", "mov", "avi", "mkv", "flv", "m4v",
    "mp3", "wav", "ogg", "flac", "m4a",
];

/// Crawl configuration — what to extract, what to allow as scope.
#[derive(Debug, Clone)]
pub struct CrawlCfg {
    pub crawl_robots: bool,
    pub crawl_sitemap: bool,
    pub max_links_per_page: usize,
    /// Scope hosts — patterns like `target.com` (exact match) or
    /// `*.target.com` (suffix match). Empty = same-host as input only.
    pub scope_hosts: Vec<String>,
}

impl Default for CrawlCfg {
    fn default() -> Self {
        Self {
            crawl_robots: true,
            crawl_sitemap: true,
            max_links_per_page: 200,
            scope_hosts: Vec::new(),
        }
    }
}

/// Extract candidate URLs from a response body. Returned URLs are:
///   - Absolute (resolved against `base_url`)
///   - In-scope (per `cfg.scope_hosts` + built-in third-party deny list)
///   - Not static-asset extensions
///   - Not the source URL itself (no self-references)
///   - Deduplicated
///   - Capped at `cfg.max_links_per_page`
pub fn extract_links(
    body: &str,
    content_type: &str,
    base_url: &str,
    cfg: &CrawlCfg,
) -> Vec<ExtractedLink> {
    let mut out: HashMap<String, &'static str> = HashMap::new();
    let ct = content_type.to_ascii_lowercase();
    let javascript = is_javascript_response(&ct, base_url);
    let json = is_json_response(&ct, base_url);
    let html_or_xml =
        ct.contains("html") || ct.contains("xml") || (ct.is_empty() && !javascript && !json);

    // HTML + XML
    if html_or_xml {
        insert_urls(&mut out, extract_html_urls(body, base_url), "crawl-html");
        for (script, script_is_json) in extract_inline_script_bodies(body) {
            let urls = if script_is_json {
                extract_json_urls(script, base_url)
            } else {
                extract_javascript_urls(script, base_url)
            };
            insert_urls(&mut out, urls, "crawl-inline-js");
        }
    }

    if javascript {
        insert_urls(
            &mut out,
            extract_javascript_urls(body, base_url),
            "crawl-js",
        );
    }

    if json {
        insert_urls(&mut out, extract_json_urls(body, base_url), "crawl-json");
    }

    // robots.txt — content-type-agnostic, gated on the URL suffix
    if cfg.crawl_robots && base_url.ends_with("/robots.txt") {
        insert_urls(
            &mut out,
            extract_robots_urls(body, base_url),
            "crawl-robots",
        );
    }

    // sitemap.xml — XML responses or sitemap.xml suffix
    if cfg.crawl_sitemap && (base_url.ends_with("/sitemap.xml") || ct.contains("xml")) {
        insert_urls(
            &mut out,
            extract_sitemap_urls(body, base_url),
            "crawl-sitemap",
        );
    }

    // Filter pipeline
    let mut filtered: Vec<ExtractedLink> = out
        .into_iter()
        .filter(|(url, _)| {
            url != base_url && url.trim_end_matches('/') != base_url.trim_end_matches('/')
        })
        .filter(|(url, _)| in_scope(url, base_url, &cfg.scope_hosts))
        .filter(|(url, _)| !is_static_asset(url))
        .map(|(url, source)| ExtractedLink { url, source })
        .collect();

    // Sort then truncate (deterministic — same input always produces same
    // output, useful for tests + diff-friendly output)
    filtered.sort_by(|a, b| a.url.cmp(&b.url));
    filtered.truncate(cfg.max_links_per_page);
    filtered
}

#[cfg(test)]
pub fn extract_urls(body: &str, content_type: &str, base_url: &str, cfg: &CrawlCfg) -> Vec<String> {
    extract_links(body, content_type, base_url, cfg)
        .into_iter()
        .map(|link| link.url)
        .collect()
}

fn insert_urls(
    out: &mut HashMap<String, &'static str>,
    urls: impl IntoIterator<Item = String>,
    source: &'static str,
) {
    for url in urls {
        out.entry(url).or_insert(source);
    }
}

fn response_path_has_extension(base_url: &str, extensions: &[&str]) -> bool {
    let Ok(parsed) = Url::parse(base_url) else {
        return false;
    };
    let path = parsed.path().to_ascii_lowercase();
    extensions.iter().any(|ext| path.ends_with(ext))
}

fn is_javascript_response(content_type: &str, base_url: &str) -> bool {
    content_type.contains("javascript")
        || content_type.contains("ecmascript")
        || response_path_has_extension(base_url, &[".js", ".mjs", ".cjs"])
}

fn is_json_response(content_type: &str, base_url: &str) -> bool {
    content_type.contains("application/json")
        || content_type.contains("text/json")
        || content_type.contains("+json")
        || response_path_has_extension(base_url, &[".json", ".map"])
}

fn extract_inline_script_bodies(body: &str) -> Vec<(&str, bool)> {
    static RE: OnceCell<Regex> = OnceCell::new();
    let re = RE.get_or_init(|| Regex::new(r"(?is)<script\b([^>]*)>(.*?)</script\s*>").unwrap());
    re.captures_iter(body)
        .filter_map(|capture| {
            let attrs = capture.get(1)?.as_str().to_ascii_lowercase();
            let script = capture.get(2)?.as_str();
            if script.trim().is_empty() {
                return None;
            }
            let is_json = attrs.contains("application/json")
                || attrs.contains("application/ld+json")
                || attrs.contains("importmap");
            Some((script, is_json))
        })
        .collect()
}

fn unescape_script_string(raw: &str) -> String {
    raw.replace("\\/", "/")
        .replace("\\u002f", "/")
        .replace("\\u002F", "/")
        .replace("\\x2f", "/")
        .replace("\\x2F", "/")
        .replace("\\u003a", ":")
        .replace("\\u003A", ":")
        .replace("\\u003f", "?")
        .replace("\\u003F", "?")
        .replace("\\u0026", "&")
        .replace("\\u003d", "=")
        .replace("\\u003D", "=")
        .replace("&amp;", "&")
}

fn looks_like_bare_relative_path(value: &str) -> bool {
    let first = value.split('/').next().unwrap_or("").to_ascii_lowercase();
    value.contains('/')
        && matches!(
            first.as_str(),
            "api"
                | "rest"
                | "graphql"
                | "rpc"
                | "services"
                | "service"
                | "oauth"
                | "auth"
                | "admin"
                | "internal"
                | "v1"
                | "v2"
                | "v3"
        )
}

fn resolve_endpoint_candidate(
    raw: &str,
    base_url: &str,
    allow_bare_relative: bool,
) -> Option<String> {
    let value = unescape_script_string(raw.trim());
    if value.is_empty()
        || value.len() > MAX_CANDIDATE_LEN
        || value.chars().any(char::is_whitespace)
        || value.contains(['<', '>', '"', '\'', '`'])
        || value.contains("${")
        || value.contains("{{")
        || value.contains(['{', '}', '[', ']', '*'])
        || value.contains("/:")
        || value.starts_with('#')
        || value.starts_with("data:")
        || value.starts_with("javascript:")
        || value.starts_with("mailto:")
        || value.starts_with("tel:")
    {
        return None;
    }

    let candidate = if let Some(rest) = value.strip_prefix("ws://") {
        format!("http://{rest}")
    } else if let Some(rest) = value.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("//")
        || value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || (allow_bare_relative && looks_like_bare_relative_path(&value))
    {
        value
    } else {
        return None;
    };

    let base = Url::parse(base_url).ok()?;
    let mut resolved = base.join(&candidate).ok()?;
    if !matches!(resolved.scheme(), "http" | "https") {
        return None;
    }
    resolved.set_fragment(None);
    Some(resolved.to_string())
}

fn extract_javascript_urls(body: &str, base_url: &str) -> Vec<String> {
    static STRINGS: OnceCell<Vec<Regex>> = OnceCell::new();
    static SOURCE_MAP: OnceCell<Regex> = OnceCell::new();
    let strings = STRINGS.get_or_init(|| {
        [
            r#"\"((?:\\.|[^\"\\]){1,2048})\""#,
            r#"'((?:\\.|[^'\\]){1,2048})'"#,
            r#"`((?:\\.|[^`\\]){1,2048})`"#,
        ]
        .iter()
        .map(|pattern| Regex::new(pattern).unwrap())
        .collect()
    });
    let source_map = SOURCE_MAP
        .get_or_init(|| Regex::new(r"(?im)(?:sourceMappingURL\s*=\s*)([^\s*]+)").unwrap());

    let mut out = HashSet::new();
    for regex in strings {
        for capture in regex.captures_iter(body) {
            if let Some(candidate) = capture
                .get(1)
                .and_then(|value| resolve_endpoint_candidate(value.as_str(), base_url, false))
            {
                out.insert(candidate);
            }
        }
    }
    for capture in source_map.captures_iter(body) {
        let Some(value) = capture.get(1).map(|value| value.as_str().trim()) else {
            continue;
        };
        if value.starts_with("data:") {
            continue;
        }
        let source_map_url = if value.starts_with("http://")
            || value.starts_with("https://")
            || value.starts_with("//")
            || value.starts_with('/')
            || value.starts_with("./")
            || value.starts_with("../")
        {
            value.to_string()
        } else {
            format!("./{value}")
        };
        if let Some(candidate) = resolve_endpoint_candidate(&source_map_url, base_url, false) {
            out.insert(candidate);
        }
    }
    out.into_iter().collect()
}

fn json_key_allows_relative_path(key: Option<&str>) -> bool {
    let Some(key) = key else {
        return false;
    };
    let key = key.to_ascii_lowercase();
    [
        "url", "uri", "path", "endpoint", "route", "href", "src", "action", "location",
        "redirect", "next", "previous", "download", "upload", "api",
    ]
    .iter()
    .any(|needle| key == *needle || key.ends_with(&format!("_{needle}")))
}

fn collect_json_urls(value: &Value, key: Option<&str>, base_url: &str, out: &mut HashSet<String>) {
    match value {
        Value::String(raw) => {
            if key.is_some_and(|name| name.eq_ignore_ascii_case("sourcesContent")) {
                out.extend(extract_javascript_urls(raw, base_url));
            } else if let Some(candidate) =
                resolve_endpoint_candidate(raw, base_url, json_key_allows_relative_path(key))
            {
                out.insert(candidate);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_json_urls(value, key, base_url, out);
            }
        }
        Value::Object(values) => {
            for (child_key, child_value) in values {
                if let Some(candidate) =
                    resolve_endpoint_candidate(child_key, base_url, key == Some("paths"))
                {
                    out.insert(candidate);
                }
                collect_json_urls(child_value, Some(child_key), base_url, out);
            }
        }
        _ => {}
    }
}

fn extract_json_urls(body: &str, base_url: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let mut out = HashSet::new();
    collect_json_urls(&value, None, base_url, &mut out);
    out.into_iter().collect()
}

/// Extract HTML URLs via regex against well-known link-bearing tags. Each
/// captured value is resolved against `base_url` to produce an absolute URL.
fn extract_html_urls(body: &str, base_url: &str) -> Vec<String> {
    static PATTERNS: OnceCell<Vec<Regex>> = OnceCell::new();
    let regexes = PATTERNS.get_or_init(|| {
        let raw_patterns = [
            r#"(?i)<a\s+[^>]*href\s*=\s*["']([^"']+)["']"#,
            r#"(?i)<link\s+[^>]*href\s*=\s*["']([^"']+)["']"#,
            r#"(?i)<script\s+[^>]*src\s*=\s*["']([^"']+)["']"#,
            r#"(?i)<img\s+[^>]*src\s*=\s*["']([^"']+)["']"#,
            r#"(?i)<form\s+[^>]*action\s*=\s*["']([^"']+)["']"#,
            r#"(?i)<iframe\s+[^>]*src\s*=\s*["']([^"']+)["']"#,
            r#"(?i)<source\s+[^>]*src\s*=\s*["']([^"']+)["']"#,
            r#"(?i)<embed\s+[^>]*src\s*=\s*["']([^"']+)["']"#,
            r#"(?i)<object\s+[^>]*data\s*=\s*["']([^"']+)["']"#,
            // meta-refresh: <meta http-equiv="refresh" content="0;url=/foo">
            r#"(?i)<meta\s+[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"';\s]+)"#,
        ];
        raw_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect()
    });

    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return vec![],
    };

    let mut out: HashSet<String> = HashSet::new();
    for re in regexes {
        for cap in re.captures_iter(body) {
            if let Some(m) = cap.get(1) {
                let raw = m.as_str().trim();
                // Skip empty, fragment-only, and javascript: links
                if raw.is_empty()
                    || raw.starts_with('#')
                    || raw.starts_with("javascript:")
                    || raw.starts_with("data:")
                    || raw.starts_with("mailto:")
                    || raw.starts_with("tel:")
                {
                    continue;
                }
                if let Ok(absolutised) = base.join(raw) {
                    // Strip fragment
                    let mut u = absolutised;
                    u.set_fragment(None);
                    out.insert(u.to_string());
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Parse robots.txt — Disallow / Allow / Sitemap directives.
fn extract_robots_urls(body: &str, base_url: &str) -> Vec<String> {
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return vec![],
    };
    let mut out: HashSet<String> = HashSet::new();
    for line in body.lines() {
        let l = line.trim();
        // Strip inline comments
        let l = l.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        // Disallow / Allow — both yield path candidates
        for prefix in &["disallow:", "allow:"] {
            if l.to_ascii_lowercase().starts_with(prefix) {
                let path = l[prefix.len()..].trim();
                if path.is_empty() || path == "/" {
                    continue;
                }
                if let Ok(u) = base.join(path) {
                    let mut u = u;
                    u.set_fragment(None);
                    out.insert(u.to_string());
                }
            }
        }
        // Sitemap directive
        if l.to_ascii_lowercase().starts_with("sitemap:") {
            let url = l["sitemap:".len()..].trim();
            if !url.is_empty() {
                if let Ok(u) = Url::parse(url) {
                    out.insert(u.to_string());
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Parse sitemap.xml — extract `<loc>` URLs.
fn extract_sitemap_urls(body: &str, _base_url: &str) -> Vec<String> {
    static RE: OnceCell<Regex> = OnceCell::new();
    let re = RE.get_or_init(|| Regex::new(r"(?is)<loc>\s*([^<]+?)\s*</loc>").unwrap());
    let mut out: HashSet<String> = HashSet::new();
    for cap in re.captures_iter(body) {
        if let Some(m) = cap.get(1) {
            let raw = m.as_str().trim();
            if let Ok(u) = Url::parse(raw) {
                out.insert(u.to_string());
            }
        }
    }
    out.into_iter().collect()
}

/// Same-host scope check. URL is in-scope when:
///   - Its host matches a `scope_hosts` pattern (exact or `*.suffix`), OR
///   - `scope_hosts` is empty AND URL's host == base_url's host
///   - AND its host is NOT in the third-party deny list
pub fn in_scope(url: &str, base_url: &str, scope_hosts: &[String]) -> bool {
    let u_host = match Url::parse(url).ok().and_then(|u| u.host_str().map(String::from)) {
        Some(h) => h.to_ascii_lowercase(),
        None => return false,
    };
    // Third-party deny list — always blocked
    for tp in THIRD_PARTY_HOSTS {
        if u_host == *tp || u_host.ends_with(&format!(".{}", tp)) {
            return false;
        }
    }
    // Empty scope → default to base host only
    if scope_hosts.is_empty() {
        let base_host = match Url::parse(base_url)
            .ok()
            .and_then(|b| b.host_str().map(String::from))
        {
            Some(h) => h.to_ascii_lowercase(),
            None => return false,
        };
        return u_host == base_host;
    }
    // Match against scope patterns
    for pat in scope_hosts {
        let p = pat.trim().to_ascii_lowercase();
        if let Some(suffix) = p.strip_prefix("*.") {
            if u_host == suffix || u_host.ends_with(&format!(".{}", suffix)) {
                return true;
            }
        } else if u_host == p {
            return true;
        }
    }
    false
}

/// Static-asset extension check on the URL's path. Case-insensitive.
fn is_static_asset(url: &str) -> bool {
    let path = match Url::parse(url) {
        Ok(u) => u.path().to_string(),
        Err(_) => return false,
    };
    let lc = path.to_ascii_lowercase();
    let last = lc.rsplit('/').next().unwrap_or("");
    if let Some(idx) = last.rfind('.') {
        let ext = &last[idx + 1..];
        for asset in STATIC_ASSET_EXTS {
            if ext == *asset {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(scope: Vec<&str>) -> CrawlCfg {
        CrawlCfg {
            crawl_robots: true,
            crawl_sitemap: true,
            max_links_per_page: 200,
            scope_hosts: scope.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn html_extract_anchor_and_form_and_script() {
        let body = r#"
            <html><body>
            <a href="/admin">admin</a>
            <a href="https://example.com/api/v1/users">users</a>
            <form action="/login" method="post"></form>
            <script src="/static/app.js"></script>
            <link rel="stylesheet" href="/css/main.css">
            <iframe src="/embed/widget"></iframe>
            </body></html>
        "#;
        let urls = extract_html_urls(body, "https://example.com/");
        let urls_set: HashSet<_> = urls.iter().collect();
        assert!(urls_set.contains(&"https://example.com/admin".to_string()));
        assert!(urls_set.contains(&"https://example.com/api/v1/users".to_string()));
        assert!(urls_set.contains(&"https://example.com/login".to_string()));
        assert!(urls_set.contains(&"https://example.com/embed/widget".to_string()));
        // Static assets are extracted at THIS layer; the filter step in
        // extract_urls() drops them.
        assert!(urls_set.contains(&"https://example.com/static/app.js".to_string()));
        assert!(urls_set.contains(&"https://example.com/css/main.css".to_string()));
    }

    #[test]
    fn html_skips_javascript_data_mailto_fragment() {
        // r##"..."## because the body contains `"#section"` which would
        // otherwise terminate a single-# raw string at the `"#`.
        let body = r##"
            <a href="javascript:void(0)">js</a>
            <a href="#section">anchor</a>
            <a href="mailto:foo@bar.com">mail</a>
            <a href="data:text/html,...">data</a>
            <a href="/real">real</a>
        "##;
        let urls = extract_html_urls(body, "https://x.com/");
        let urls_set: HashSet<_> = urls.iter().collect();
        assert_eq!(urls.len(), 1);
        assert!(urls_set.contains(&"https://x.com/real".to_string()));
    }

    #[test]
    fn html_meta_refresh_extracted() {
        let body = r#"<meta http-equiv="refresh" content="0;url=/redirect-target">"#;
        let urls = extract_html_urls(body, "https://x.com/");
        assert!(urls.contains(&"https://x.com/redirect-target".to_string()));
    }

    #[test]
    fn robots_extract_disallow_allow_sitemap() {
        let body = "
User-agent: *
Disallow: /admin/
Disallow: /private
Allow: /public
Sitemap: https://x.com/sitemap.xml

# Comment line, should be skipped
Disallow: /api/v2  # inline comment too
";
        let urls = extract_robots_urls(body, "https://x.com/robots.txt");
        let urls_set: HashSet<_> = urls.iter().collect();
        assert!(urls_set.contains(&"https://x.com/admin/".to_string()));
        assert!(urls_set.contains(&"https://x.com/private".to_string()));
        assert!(urls_set.contains(&"https://x.com/public".to_string()));
        assert!(urls_set.contains(&"https://x.com/api/v2".to_string()));
        assert!(urls_set.contains(&"https://x.com/sitemap.xml".to_string()));
    }

    #[test]
    fn sitemap_extract_loc() {
        let body = r#"<?xml version="1.0"?>
            <urlset>
              <url><loc>https://x.com/page1</loc></url>
              <url><loc>https://x.com/page2</loc></url>
              <url><loc>  https://x.com/page3  </loc></url>
            </urlset>"#;
        let urls = extract_sitemap_urls(body, "https://x.com/sitemap.xml");
        let urls_set: HashSet<_> = urls.iter().collect();
        assert_eq!(urls.len(), 3);
        assert!(urls_set.contains(&"https://x.com/page1".to_string()));
        assert!(urls_set.contains(&"https://x.com/page2".to_string()));
        assert!(urls_set.contains(&"https://x.com/page3".to_string()));
    }

    #[test]
    fn scope_default_same_host_only() {
        let c = cfg(vec![]);
        assert!(in_scope(
            "https://target.com/admin",
            "https://target.com/",
            &c.scope_hosts
        ));
        assert!(!in_scope(
            "https://other.com/admin",
            "https://target.com/",
            &c.scope_hosts
        ));
    }

    #[test]
    fn scope_wildcard_subdomain() {
        let c = cfg(vec!["*.target.com"]);
        assert!(in_scope(
            "https://api.target.com/foo",
            "https://target.com/",
            &c.scope_hosts
        ));
        assert!(in_scope(
            "https://target.com/foo",
            "https://target.com/",
            &c.scope_hosts
        ));
        assert!(!in_scope(
            "https://other.com/foo",
            "https://target.com/",
            &c.scope_hosts
        ));
    }

    #[test]
    fn third_party_always_blocked_even_in_scope() {
        let c = cfg(vec!["*"]); // would otherwise allow everything
        // googleapis.com is on the deny list
        assert!(!in_scope(
            "https://fonts.googleapis.com/css?...",
            "https://target.com/",
            &c.scope_hosts
        ));
        assert!(!in_scope(
            "https://cdnjs.cloudflare.com/ajax/...",
            "https://target.com/",
            &c.scope_hosts
        ));
    }

    #[test]
    fn static_asset_filter() {
        // STILL filtered (pure media — low recon value)
        assert!(is_static_asset("https://x.com/app.css"));
        assert!(is_static_asset("https://x.com/logo.png"));
        assert!(is_static_asset("https://x.com/font.woff2"));
        assert!(is_static_asset("https://x.com/clip.mp4"));
        // NOT filtered in v0.4.2 (high recon value — JS/JSON contain
        // endpoints + secrets; archives are backup dumps)
        assert!(!is_static_asset("https://x.com/main.JS"));
        assert!(!is_static_asset("https://x.com/Scripts/jquery.js"));
        assert!(!is_static_asset("https://x.com/api.json"));
        assert!(!is_static_asset("https://x.com/sitemap.xml"));
        assert!(!is_static_asset("https://x.com/backup.zip"));
        assert!(!is_static_asset("https://x.com/dump.tar.gz"));
        assert!(!is_static_asset("https://x.com/db.sql.gz"));
        assert!(!is_static_asset("https://x.com/setup.exe"));
        assert!(!is_static_asset("https://x.com/manual.pdf"));
        // Real endpoints — never filtered
        assert!(!is_static_asset("https://x.com/api/users"));
        assert!(!is_static_asset("https://x.com/admin"));
        assert!(!is_static_asset("https://x.com/api.v2/list"));
    }

    #[test]
    fn extract_urls_full_pipeline() {
        let body = r#"
            <a href="/admin">a</a>
            <a href="/admin/users">b</a>
            <script src="https://cdnjs.cloudflare.com/foo.js"></script>
            <link href="/main.css">
            <a href="https://evil.com/external">c</a>
            <a href="https://target.com/">self</a>
        "#;
        let c = cfg(vec![]);
        let urls = extract_urls(body, "text/html", "https://target.com/", &c);
        let urls_set: HashSet<_> = urls.iter().collect();
        // /admin and /admin/users pass
        assert!(urls_set.contains(&"https://target.com/admin".to_string()));
        assert!(urls_set.contains(&"https://target.com/admin/users".to_string()));
        // CDN-hosted JS blocked by third-party deny list
        assert!(!urls.iter().any(|u| u.contains("cdnjs.cloudflare.com")));
        // /main.css blocked by static-asset filter
        assert!(!urls.iter().any(|u| u.contains("main.css")));
        // evil.com blocked by scope (default = base host only)
        assert!(!urls.iter().any(|u| u.contains("evil.com")));
        // Self-reference blocked
        assert!(!urls.iter().any(|u| u == "https://target.com/"));
    }

    #[test]
    fn javascript_extracts_routes_queries_escapes_and_source_map() {
        let body = r##"
            fetch("/api/bootstrap?client=web");
            const route = "\/graph\/rubygems\/a_marmita\/latest?g=force-directed";
            const socket = "wss://target.com/events";
            const external = "https://evil.com/api/users";
            const unresolved = `/api/users/${id}`;
            const noise = "foo/bar";
            //# sourceMappingURL=app.js.map
        "##;
        let links = extract_links(
            body,
            "application/javascript",
            "https://target.com/assets/app.js",
            &cfg(vec![]),
        );
        let urls: HashSet<_> = links.iter().map(|link| link.url.as_str()).collect();

        assert!(urls.contains("https://target.com/api/bootstrap?client=web"));
        assert!(
            urls.contains("https://target.com/graph/rubygems/a_marmita/latest?g=force-directed")
        );
        assert!(urls.contains("https://target.com/events"));
        assert!(urls.contains("https://target.com/assets/app.js.map"));
        assert!(!urls.iter().any(|url| url.contains("evil.com")));
        assert!(!urls.iter().any(|url| url.contains("${id}")));
        assert!(!urls.iter().any(|url| url.ends_with("foo/bar")));
        assert!(links.iter().all(|link| link.source == "crawl-js"));
    }

    #[test]
    fn html_extracts_inline_javascript_and_json_scripts() {
        let body = r#"
            <script>fetch('/inline/start?from=html')</script>
            <script type="application/json">{"next":"/inline/from-json"}</script>
        "#;
        let links = extract_links(body, "text/html", "https://target.com/start", &cfg(vec![]));
        assert!(links.iter().any(|link| {
            link.url == "https://target.com/inline/start?from=html"
                && link.source == "crawl-inline-js"
        }));
        assert!(links.iter().any(|link| {
            link.url == "https://target.com/inline/from-json" && link.source == "crawl-inline-js"
        }));
    }

    #[test]
    fn json_extracts_links_openapi_paths_and_source_content() {
        let body = r#"{
            "next": "/api/final?from=json",
            "endpoint": "api/v2/users",
            "paths": {
                "/openapi/status": {"get": {}},
                "/openapi/users/{id}": {"get": {}}
            },
            "sourcesContent": ["fetch('/api/from-map?source=map')"],
            "description": "ordinary/value"
        }"#;
        let links = extract_links(
            body,
            "application/json",
            "https://target.com/assets/app.js.map",
            &cfg(vec![]),
        );
        let urls: HashSet<_> = links.iter().map(|link| link.url.as_str()).collect();

        assert!(urls.contains("https://target.com/api/final?from=json"));
        assert!(urls.contains("https://target.com/assets/api/v2/users"));
        assert!(urls.contains("https://target.com/openapi/status"));
        assert!(!urls.iter().any(|url| url.contains("openapi/users")));
        assert!(urls.contains("https://target.com/api/from-map?source=map"));
        assert!(!urls.iter().any(|url| url.ends_with("ordinary/value")));
        assert!(links.iter().all(|link| link.source == "crawl-json"));
    }

    #[test]
    fn combined_extractors_share_deterministic_page_cap() {
        let body = r#"
            <a href="/z-last">last</a>
            <script>fetch('/a-first'); fetch('/m-middle')</script>
        "#;
        let mut c = cfg(vec![]);
        c.max_links_per_page = 2;
        let urls = extract_urls(body, "text/html", "https://target.com/", &c);
        assert_eq!(
            urls,
            vec![
                "https://target.com/a-first".to_string(),
                "https://target.com/m-middle".to_string(),
            ]
        );
    }
}
