//! Response-body link extraction for `--crawl` mode.
//!
//! Three extractors:
//!   - **HTML** — regex-based (not a full DOM, but covers every
//!     dirsearch-equivalent tag: `<a href>`, `<link href>`, `<script src>`,
//!     `<form action>`, `<iframe src>`, `<img src>`, `<source src>`,
//!     `<embed src>`, `<object data>`, plus `<meta http-equiv=refresh>`)
//!   - **robots.txt** — Disallow / Allow / Sitemap directives
//!   - **sitemap.xml** — `<loc>` URL extraction
//!
//! Filtering pipeline (in order):
//!   1. Absolutise relative URLs against the response URL
//!   2. Same-host scope check (built-in deny list + user `--scope`)
//!   3. Static-asset extension drop (.css/.js/.png/...)
//!   4. Self-referencing URL drop (extracted URL == source URL)
//!   5. Dedup
//!   6. Cap at `max_links_per_page`
//!
//! JS endpoint extraction (regex against quoted path-like strings) is
//! deferred to v0.3.8 — high-FP without careful tuning.

use once_cell::sync::OnceCell;
use regex::Regex;
use std::collections::HashSet;
use url::Url;

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
pub const STATIC_ASSET_EXTS: &[&str] = &[
    "css", "js", "mjs", "map", "json", "xml", "rss", "atom",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tiff",
    "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "webm", "mov", "avi", "mkv", "flv",
    "mp3", "wav", "ogg", "flac",
    "pdf",
    "zip", "tar", "gz", "tgz", "rar", "7z", "iso", "dmg",
    "exe", "msi", "deb", "rpm",
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
pub fn extract_urls(
    body: &str,
    content_type: &str,
    base_url: &str,
    cfg: &CrawlCfg,
) -> Vec<String> {
    let mut out: HashSet<String> = HashSet::new();
    let ct = content_type.to_ascii_lowercase();

    // HTML + XML
    if ct.contains("html") || ct.contains("xml") || ct.is_empty() {
        out.extend(extract_html_urls(body, base_url));
    }

    // robots.txt — content-type-agnostic, gated on the URL suffix
    if cfg.crawl_robots && base_url.ends_with("/robots.txt") {
        out.extend(extract_robots_urls(body, base_url));
    }

    // sitemap.xml — XML responses or sitemap.xml suffix
    if cfg.crawl_sitemap && (base_url.ends_with("/sitemap.xml") || ct.contains("xml")) {
        out.extend(extract_sitemap_urls(body, base_url));
    }

    // Filter pipeline
    let mut filtered: Vec<String> = out
        .into_iter()
        .filter(|u| u != base_url && u.trim_end_matches('/') != base_url.trim_end_matches('/'))
        .filter(|u| in_scope(u, base_url, &cfg.scope_hosts))
        .filter(|u| !is_static_asset(u))
        .collect();

    // Sort then truncate (deterministic — same input always produces same
    // output, useful for tests + diff-friendly output)
    filtered.sort();
    filtered.truncate(cfg.max_links_per_page);
    filtered
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
        assert!(is_static_asset("https://x.com/app.css"));
        assert!(is_static_asset("https://x.com/main.JS"));
        assert!(is_static_asset("https://x.com/logo.png"));
        assert!(is_static_asset("https://x.com/font.woff2"));
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
}
