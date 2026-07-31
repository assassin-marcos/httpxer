//! Recursion guards — strict directory detection + recursion bounds.
//!
//! Two concerns this module owns:
//!   1. **Directory detection** — given a probe response, decide whether
//!      it signals "I'm a directory worth recursing into". Conservative
//!      by default (only 301/302/307/308 with `Location == URL+"/"` parity).
//!   2. **Per-host dir budget** — an atomic counter that hard-caps how many
//!      discovered directories per input host enter the recursion frontier
//!      (`--max-dirs-per-host`). When hit, recursion stops for that host with
//!      a stderr warning.
//!
//! NOT provided: self-similarity / path-loop detection. A `/admin/admin/…`
//! or `/foo/bar/foo/bar/…` cycle is NOT specifically detected. What actually
//! bounds a runaway recursion is the combination of `--recursion-depth`
//! (hard depth ceiling), `--max-dirs-per-host` (breadth ceiling), and the
//! visited-URL dedupe in `fuzz.rs`. An earlier self-similarity detector
//! existed here but was never wired into the scan path, so it is gone rather
//! than left as a guard that looks live and isn't.
//!
//! The smart `--exclude-subdirs` default list lives here too — built-in
//! asset/traversal noise that the user shouldn't have to specify.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Built-in default exclude list — paths we never recurse into AND
/// (when `ExcludeMode::Substring` is active) never even probe.
///
/// v0.3.10 expanded list (matches the user's bash `EXCL=( ... )` pattern):
///   - Static asset dirs + compound forms (`static/css`, `static/fonts`...)
///   - Encoded path-traversal noise — every dot/slash/backslash variant
///   - Semicolon-bypass roots (Java path-param injection)
///   - Slash-confusion + backslash-traversal combos
///   - Mixed second-level encodings seen in real recon logs
///   - Health/probe endpoints (always 200, recursion noise)
///
/// v0.3.11 change: ALL JavaScript-related entries removed by default —
/// `js`, `static/js`, `assets/js`, `node_modules`, `_next`, `_nuxt`,
/// `_app`, `__webpack*`, `.sapper`, `.svelte-kit`, `@vite`,
/// `@react-refresh`, `@fs`, `bower_components`. JS files routinely
/// contain real API endpoints, config data, and secret leaks worth
/// crawling. If you want them dropped, add explicitly with
/// `--add-excludes 'js,node_modules,_next,...'`.
///
/// Lowercase-only — `segment_excluded` / `path_excluded` lowercase the
/// candidate before comparison so uppercase variants (`%2E%2E`, `%5C`)
/// match the lowercase entries here.
pub const DEFAULT_EXCLUDE_SUBDIRS: &[&str] = &[
    // ── Static asset dirs (single segment) ────────────────────────────
    // NOTE: `js` and all JS-related entries are DELIBERATELY NOT in this
    // list (v0.3.11 change). JS files often contain real API endpoints
    // and config data worth crawling — blocking them by default
    // forfeits a major recon surface. If you want JS dropped, add
    // `--add-excludes 'js,node_modules,_next,...'` explicitly.
    "assets",
    "static",
    "public",
    "dist",
    "build",
    "bundle",
    "bundles",
    "css",
    "fonts",
    "images",
    "img",
    "media",
    "videos",
    "audio",
    "icons",
    "svg",
    "wp-content/uploads",
    "uploads/cache",
    // ── Static asset compound forms (multi-segment — caught in substring mode) ─
    // NOTE: `static/js`, `assets/js` deliberately NOT here — see above.
    "static/css",
    "static/fonts",
    "static/images",
    "static/img",
    "static/media",
    "static/icons",
    "assets/css",
    "assets/fonts",
    "assets/images",
    "assets/img",
    // ── PHP / Composer / framework dirs (not JS-specific) ─────────────
    "vendor",
    // ── Encoded dot-traversal (every variant) ─────────────────────────
    "%2e%2e",       // ..
    "%2e.",         // .. (mixed encode)
    ".%2e",         // .. (mixed encode)
    "..%2f",        // ../
    "..%5c",        // ..\
    "..\\",         // ..\
    "../",          // plain ../
    "..",           // plain ..
    // ── Semicolon-bypass roots (Java / Tomcat / Jetty path-param) ─────
    "%3b",          // ;
    ";/",           // ;/
    "%3b/",         // ;/
    ";%2f",         // ;/
    ";",            // bare semicolon
    "..;",          // ..; (Tomcat traversal)
    // ── Slash-confusion roots ─────────────────────────────────────────
    "%2f/",         // //
    "//",           // //
    "/../",         // /../
    "//..",         // //..
    "///",          // ///
    "%2f%2f",       // //
    // ── Backslash-traversal ───────────────────────────────────────────
    "%5c",          // \
    "\\/",          // \/
    "\\..",         // \..
    "\\",           // bare backslash
    // ── Mixed second-level combos seen in real recon logs ─────────────
    "/..//",
    "/;/",
    "/.%2e",
    "/%2e.",
    "/%3b",
    "/%5c",
    // ── Health / probe endpoints (always-200 noise) ──────────────────
    "healthz",
    "readyz",
    "livez",
    "ping",
    "_health",
    "_status",
    "actuator/health",
    "ready",
    "live",
];

/// Exclusion match mode. dirsearch-paste-compat users want substring
/// (any queued path CONTAINING the entry is dropped); pre-v0.3.10
/// httpxer used segment (the dir's last path component EQUALS one of
/// the entries). Substring is more aggressive — catches traversal /
/// semicolon noise hidden anywhere in the path. Segment is more precise
/// — won't reject `/api/css-tooling/x` just because it has `css` in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExcludeMode {
    /// Match if the path's LAST component equals an exclude entry
    /// (case-insensitive). Default — least aggressive, least false-drops.
    #[default]
    Segment,
    /// Match if the path CONTAINS any exclude entry as a substring
    /// (case-insensitive). Aggressive — drops `/api/admin/%3b/anything`
    /// because `%3b` appears anywhere in it.
    Substring,
}

impl ExcludeMode {
    pub fn from_cli(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "segment" => Ok(ExcludeMode::Segment),
            "substring" => Ok(ExcludeMode::Substring),
            other => anyhow::bail!(
                "invalid --exclude-mode '{}' (want segment|substring)",
                other
            ),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ExcludeMode::Segment => "segment",
            ExcludeMode::Substring => "substring",
        }
    }
}

/// True iff `path_segment` should be skipped per `exclude_set`, using
/// segment-equality matching (case-insensitive).
pub fn segment_excluded(path_segment: &str, exclude_set: &HashSet<String>) -> bool {
    let lc = path_segment.to_ascii_lowercase();
    exclude_set.contains(&lc)
}

/// True iff `path` should be skipped per the merged exclude list, using
/// the chosen `mode`. Path can be a full URL OR a bare path like
/// `/admin/users` OR a wordlist entry like `admin/api/x`.
///
/// - **Segment mode**: extracts the last non-empty path segment and
///   compares to the exclude entries (existing v0.3.7 behavior).
/// - **Substring mode**: lowercases the path and checks if ANY exclude
///   entry appears as a substring. Catches encoded traversal noise
///   anywhere in the path. v0.3.10 addition.
pub fn path_excluded(
    path: &str,
    exclude_set: &HashSet<String>,
    mode: ExcludeMode,
) -> bool {
    match mode {
        ExcludeMode::Segment => {
            // Try URL form first; fall back to plain string segment split.
            if let Some(seg) = last_path_segment(path) {
                return segment_excluded(&seg, exclude_set);
            }
            // Bare path — split on '/' and take last non-empty.
            let last = path
                .trim_matches('/')
                .rsplit('/')
                .find(|s| !s.is_empty())
                .unwrap_or("");
            segment_excluded(last, exclude_set)
        }
        ExcludeMode::Substring => {
            let lc = path.to_ascii_lowercase();
            exclude_set.iter().any(|e| lc.contains(e))
        }
    }
}

/// Build the exclude set from CLI flags. When `override_list` is `Some`,
/// the built-in defaults are REPLACED (matches `--exclude-subdirs <list>`
/// semantics). When `None`, defaults are used plus the `add_list` is
/// appended (matches `--add-excludes <list>` semantics).
pub fn build_exclude_set(
    override_list: Option<&str>,
    add_list: Option<&str>,
) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    match override_list {
        Some(s) => {
            // User passed --exclude-subdirs — replace defaults entirely.
            // Empty string -> empty set (legit way to disable).
            for entry in s.split(',') {
                let t = entry.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    out.insert(t);
                }
            }
        }
        None => {
            // No override — start from the built-in defaults.
            for d in DEFAULT_EXCLUDE_SUBDIRS {
                out.insert(d.to_string());
            }
        }
    }
    // v0.5.0 — `--add-excludes` now ALWAYS appends, in both branches. Before
    // this it lived inside the `None` arm, so passing `--exclude-subdirs`
    // together with `--add-excludes` silently discarded the add-list — directly
    // contradicting its documented "doesn't replace defaults; just adds".
    if let Some(s) = add_list {
        for entry in s.split(',') {
            let t = entry.trim().to_ascii_lowercase();
            if !t.is_empty() {
                out.insert(t);
            }
        }
    }
    out
}

/// Inspect a URL's path and return its last non-empty segment, lowercased.
/// Used by the `--exclude-subdirs` segment-mode check.
pub fn last_path_segment(url: &str) -> Option<String> {
    let path = url::Url::parse(url).ok()?.path().to_string();
    path.trim_matches('/')
        .rsplit('/')
        .find(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
}

/// Strong file suffixes that should never become recursion roots. Some
/// gateways normalize every known route to a trailing slash, including files
/// such as `security.txt -> security.txt/`. Redirect parity alone therefore
/// does not prove that appending a complete wordlist below the path is useful.
const FILE_LIKE_EXTENSIONS: &[&str] = &[
    "7z", "apk", "ashx", "asmx", "asp", "aspx", "atom", "avif", "axd", "bak",
    "backup", "bash", "bat", "bin", "bmp", "bz2", "c", "cer", "cfg", "cgi",
    "class", "conf", "config", "cpp", "crt", "cs", "css", "csv", "db", "deb",
    "dll", "do", "doc", "docx", "ear", "env", "eot", "exe", "flac", "gif",
    "go", "gql", "graphql", "gz", "h", "htaccess", "htm", "html", "ico", "ini",
    "jar", "java", "jpeg", "jpg", "js", "json", "jsp", "jspx", "key", "lock",
    "log", "m4a", "m4v", "map", "md", "mdb", "mjs", "mkv", "mov", "mp3",
    "mp4", "msi", "npmrc", "old", "orig", "otf", "p12", "pdf", "pem", "pfx",
    "php", "php3", "php4", "php5", "phtml", "pl", "png", "ppt", "pptx",
    "properties", "proto", "ps1", "pub", "py", "pyc", "rar", "rb", "rpm", "rs",
    "rss", "rtf", "save", "sh", "shtml", "sql", "sqlite", "sqlite3", "svg",
    "swp", "tar", "tgz", "tiff", "tmp", "toml", "ts", "ttf", "txt", "war",
    "wasm", "wav", "webm", "webp", "woff", "woff2", "wsdl", "xhtml", "xls",
    "xlsx", "xml", "xz", "yaml", "yml", "zip",
];

/// Registered/common `/.well-known/` leaf resources without a conventional
/// extension. These are documents or protocol endpoints, not directories to
/// expand with a fuzzing wordlist. `acme-challenge` is intentionally absent:
/// it is a genuine path prefix containing challenge tokens.
const WELL_KNOWN_LEAF_RESOURCES: &[&str] = &[
    "apple-app-site-association",
    "assetlinks.json",
    "change-password",
    "dnt-policy.txt",
    "gpc.json",
    "host-meta",
    "host-meta.json",
    "jwks.json",
    "mta-sts.txt",
    "nodeinfo",
    "oauth-authorization-server",
    "openid-configuration",
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "security.txt",
    "traffic-advice",
    "webfinger",
];

const KNOWN_HIDDEN_DIRECTORIES: &[&str] = &[
    ".aws",
    ".config",
    ".git",
    ".hg",
    ".idea",
    ".ssh",
    ".svn",
    ".vscode",
    ".well-known",
];

fn request_path(req_url: &str) -> &str {
    let after_authority = req_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(req_url);
    let path = after_authority
        .find('/')
        .map(|index| &after_authority[index..])
        .unwrap_or("/");
    path.split(['?', '#']).next().unwrap_or(path)
}

fn decoded_segment(segment: &str) -> Cow<'_, str> {
    if segment.as_bytes().contains(&b'%') {
        percent_encoding::percent_decode_str(segment).decode_utf8_lossy()
    } else {
        Cow::Borrowed(segment)
    }
}

fn known_case_insensitive(values: &[&str], candidate: &str) -> bool {
    values
        .iter()
        .any(|value| candidate.eq_ignore_ascii_case(value))
}

fn recursion_path_is_file_like(req_url: &str) -> bool {
    let path = request_path(req_url);
    let mut segments = path.trim_end_matches('/').rsplit('/');
    let Some(last_raw) = segments.next().filter(|segment| !segment.is_empty()) else {
        return false;
    };
    let last = decoded_segment(last_raw);

    // Hidden directories are allowed even when their name resembles a file
    // suffix (`.config`). Known hidden files such as `.env` and `.htaccess`
    // are not in this allow-list and continue through extension detection.
    if known_case_insensitive(KNOWN_HIDDEN_DIRECTORIES, &last) {
        return false;
    }

    if let Some((_, extension)) = last.rsplit_once('.') {
        if !extension.is_empty()
            && known_case_insensitive(FILE_LIKE_EXTENSIONS, extension)
        {
            return true;
        }
    }

    segments
        .next()
        .map(decoded_segment)
        .is_some_and(|parent| parent.eq_ignore_ascii_case(".well-known"))
        && known_case_insensitive(WELL_KNOWN_LEAF_RESOURCES, &last)
}

fn plausible_directory_path(req_url: &str) -> bool {
    let path = request_path(req_url);
    let Some(last_raw) = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
    else {
        return false;
    };
    // `detect_directory` has already applied the stronger file/resource gate.
    let last = decoded_segment(last_raw);
    if !last.contains('.') || known_case_insensitive(KNOWN_HIDDEN_DIRECTORIES, &last) {
        return true;
    }

    // Preserve common dotted version directories (`v1.2`, `2.0.1`) without
    // allowing arbitrary unknown dotted leaves into auth recursion.
    let version = last
        .strip_prefix('v')
        .or_else(|| last.strip_prefix('V'))
        .unwrap_or(&last);
    version.bytes().any(|byte| byte == b'.')
        && version.bytes().any(|byte| byte.is_ascii_digit())
        && version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn starts_with_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn terminal_content_type(content_type: &str) -> bool {
    let mime = content_type.split(';').next().unwrap_or("").trim();
    starts_with_ascii_case_insensitive(mime, "image/")
        || starts_with_ascii_case_insensitive(mime, "audio/")
        || starts_with_ascii_case_insensitive(mime, "video/")
        || starts_with_ascii_case_insensitive(mime, "font/")
        || [
            "text/plain",
            "text/css",
            "text/csv",
            "text/javascript",
            "application/javascript",
            "application/octet-stream",
            "application/pdf",
            "application/wasm",
            "application/zip",
            "application/gzip",
            "application/x-7z-compressed",
            "application/x-rar-compressed",
            "application/x-tar",
        ]
        .iter()
        .any(|blocked| mime.eq_ignore_ascii_case(blocked))
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    !needle.is_empty()
        && haystack
            .as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn body_has_directory_index(body: &str) -> bool {
    // Directory markers occur near the start. Capping inspection keeps this
    // constant-bounded even though response bodies may be up to 256 KiB.
    let mut end = body.len().min(16 * 1024);
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    let sample = &body[..end];
    [
        "index of /",
        "directory listing for",
        "parent directory",
        "httpd/unix-directory",
    ]
    .iter()
    .any(|marker| contains_ascii_case_insensitive(sample, marker))
}

fn response_is_attachment(headers: &[(String, String)]) -> bool {
    header_value(headers, "content-disposition").is_some_and(|value| {
        contains_ascii_case_insensitive(value, "attachment")
            || contains_ascii_case_insensitive(value, "filename=")
    })
}

fn content_location_has_directory_parity(
    req_url: &str,
    directory_url: &str,
    headers: &[(String, String)],
) -> bool {
    let Some(location) = header_value(headers, "content-location") else {
        return false;
    };
    let resolved = crate::probe::resolve_redirect_url(req_url, location);
    canonical_url_key(&resolved) == canonical_url_key(directory_url)
}

fn directory_url(req_url: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(req_url) {
        let path = format!("{}/", parsed.path().trim_end_matches('/'));
        parsed.set_path(&path);
        parsed.set_query(None);
        parsed.set_fragment(None);
        return parsed.to_string();
    }
    let base = req_url.split(['?', '#']).next().unwrap_or(req_url);
    format!("{}/", base.trim_end_matches('/'))
}

#[derive(Debug, Clone, Copy)]
pub struct DirectoryResponse<'a> {
    pub status: u16,
    pub location: &'a str,
    pub content_type: &'a str,
    pub body: &'a str,
    pub headers: &'a [(String, String)],
}

/// Strict directory detector. Returns `Some(dir_url_with_trailing_slash)`
/// when the response signals "directory worth recursing into".
///
/// Evidence recognised (most-specific, lowest-FP first):
///   1. **301/302/307/308** with `Location == URL + "/"` (classic Apache /
///      nginx missing-trailing-slash redirect). Constant-Location catchalls
///      fail this parity check.
///   2. **200** with an autoindex marker, directory `Content-Type`, matching
///      `Content-Location`, or an explicit trailing-slash route with a
///      non-terminal content type — only when `recurse_on_200` is true.
///   3. **401/403** on a plausible directory-shaped route, with the caller's
///      auth-catchall and sibling probes providing the network confirmation.
///
/// File-like paths, standard `/.well-known/` leaf resources, attachments and
/// static/binary payloads do not become recursion roots. All checks use the
/// response already collected by the fuzz probe and add no network requests.
pub fn detect_directory(
    req_url: &str,
    response: DirectoryResponse<'_>,
    recurse_on_200: bool,
    recurse_on_403: bool,
    recurse_on_auth: bool,
) -> Option<String> {
    let status_can_recurse = matches!(response.status, 301 | 302 | 307 | 308)
        || (response.status == 200 && recurse_on_200)
        || (response.status == 403 && recurse_on_403)
        || (response.status == 401 && recurse_on_auth);
    if !status_can_recurse {
        return None;
    }

    // File-shaped routes remain valid findings, but never become recursion
    // prefixes. This guard applies to every signal below, including explicit
    // 403 recursion and misleading URL+"/" normalization redirects.
    if recursion_path_is_file_like(req_url) || response_is_attachment(response.headers) {
        return None;
    }
    let directory_url = directory_url(req_url);

    // Pattern 1: redirect-to-trailing-slash.
    if matches!(response.status, 301 | 302 | 307 | 308) && !response.location.is_empty() {
        let resolved = crate::probe::resolve_redirect_url(req_url, response.location);
        if canonical_url_key(&resolved) == canonical_url_key(&directory_url) {
            return Some(directory_url);
        }
        // Constant-Location catchall — Location is the same regardless
        // of the request path. NOT a directory; drop.
        return None;
    }
    // Pattern 2: response-backed 200 directory evidence. Autoindex and
    // explicit directory headers outrank MIME rejection; a text/plain
    // directory listing is still a directory.
    if response.status == 200 && recurse_on_200 {
        let mime = response.content_type.split(';').next().unwrap_or("").trim();
        let directory_mime = mime.eq_ignore_ascii_case("httpd/unix-directory");
        if body_has_directory_index(response.body)
            || directory_mime
            || content_location_has_directory_parity(
                req_url,
                &directory_url,
                response.headers,
            )
        {
            return Some(directory_url);
        }
        if request_path(req_url).ends_with('/')
            && !terminal_content_type(response.content_type)
        {
            return Some(directory_url);
        }
        return None;
    }
    // Pattern 3: 403 explicit opt-in, still constrained to a plausible
    // directory path. The caller separately rejects blanket auth catchalls.
    if response.status == 403 && recurse_on_403 && plausible_directory_path(req_url) {
        return Some(directory_url);
    }
    // Pattern 4 (v0.4.5): auth-dir auto-recursion. A 401 on a plausible
    // directory path (e.g. /api, /internal, /.well-known, /v1.2) is a
    // protected prefix worth descending into — its children may be
    // accessible (e.g. /api=401 but /api/actuator=200). A 403 is deliberately
    // excluded from the automatic path: gateways and WAFs commonly return
    // path-sensitive 403s for dictionary-looking names that do not identify a
    // real directory. Users who need exhaustive 403 recursion can opt in with
    // --recurse-on-403 (Pattern 3 above).
    if recurse_on_auth && response.status == 401 && plausible_directory_path(req_url) {
        return Some(directory_url);
    }
    None
}

/// Per-host recursion budget. One atomic counter so workers can charge
/// discoveries without contention. When `try_inc_dir` returns false the host
/// has hit its directory cap and no further dirs enter the frontier.
///
/// v0.4.10 — the probe counter was deleted. It backed `--max-probes-per-host`,
/// but `try_inc_probe` was only ever called from unit tests, so that cap never
/// applied to a real scan (verified: `--max-probes-per-host 10` still issued
/// 1260 probes). Keeping a counter nothing charges is worse than not having it;
/// `max_dirs` is the enforced bound.
pub struct HostBudget {
    pub max_dirs: usize,
    dirs: AtomicUsize,
}

impl HostBudget {
    pub fn new(max_dirs: usize) -> Self {
        Self {
            max_dirs,
            dirs: AtomicUsize::new(0),
        }
    }

    /// Try to charge one directory discovery. Returns false when the dir
    /// budget is exhausted (no more dirs will enter the frontier).
    pub fn try_inc_dir(&self) -> bool {
        let n = self.dirs.fetch_add(1, Ordering::Relaxed);
        n < self.max_dirs
    }

    #[allow(dead_code)]
    pub fn dirs_used(&self) -> usize {
        self.dirs.load(Ordering::Relaxed)
    }
}

/// Canonical URL key for the visited-set. Lowercases scheme + host,
/// includes port (when explicit or default-known), keeps raw path. Strips
/// query + fragment (path-collision should dedupe). Used by both the
/// recursion frontier and the crawl extractor.
pub fn canonical_url_key(url: &str) -> String {
    if let Ok(u) = url::Url::parse(url) {
        let scheme = u.scheme().to_ascii_lowercase();
        let host = u.host_str().unwrap_or("").to_ascii_lowercase();
        let port = u
            .port_or_known_default()
            .map(|p| format!(":{}", p))
            .unwrap_or_default();
        let path = u.path();
        return format!("{}://{}{}{}", scheme, host, port, path);
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_basic(
        req_url: &str,
        status: u16,
        location: &str,
        body: &str,
        recurse_on_200: bool,
        recurse_on_403: bool,
        recurse_on_auth: bool,
    ) -> Option<String> {
        detect_directory(
            req_url,
            DirectoryResponse {
                status,
                location,
                content_type: "",
                body,
                headers: &[],
            },
            recurse_on_200,
            recurse_on_403,
            recurse_on_auth,
        )
    }

    #[test]
    fn exclude_mode_from_cli_parses() {
        assert_eq!(
            ExcludeMode::from_cli("segment").unwrap(),
            ExcludeMode::Segment
        );
        assert_eq!(
            ExcludeMode::from_cli("substring").unwrap(),
            ExcludeMode::Substring
        );
        assert_eq!(
            ExcludeMode::from_cli("SUBSTRING").unwrap(),
            ExcludeMode::Substring
        );
        assert!(ExcludeMode::from_cli("bogus").is_err());
    }

    #[test]
    fn path_excluded_segment_mode() {
        let mut set = HashSet::new();
        set.insert("css".to_string());
        set.insert("%3b".to_string());
        // Last segment matches → dropped.
        assert!(path_excluded(
            "https://x.com/static/css",
            &set,
            ExcludeMode::Segment
        ));
        assert!(path_excluded("/static/css", &set, ExcludeMode::Segment));
        // Last segment doesn't match → kept (even though `css` is mid-path).
        assert!(!path_excluded(
            "https://x.com/css-tooling/v1/api",
            &set,
            ExcludeMode::Segment
        ));
        // Mid-path traversal not caught by segment mode.
        assert!(!path_excluded(
            "https://x.com/api/%3b/users",
            &set,
            ExcludeMode::Segment
        ));
    }

    #[test]
    fn path_excluded_substring_mode() {
        let mut set = HashSet::new();
        set.insert("%3b".to_string());
        set.insert("%2e%2e".to_string());
        set.insert("//".to_string());
        // Substring anywhere → dropped.
        assert!(path_excluded(
            "/api/%3b/users",
            &set,
            ExcludeMode::Substring
        ));
        assert!(path_excluded(
            "/x/%2e%2e/etc/passwd",
            &set,
            ExcludeMode::Substring
        ));
        assert!(path_excluded("/api//double-slash", &set, ExcludeMode::Substring));
        // No substring match → kept.
        assert!(!path_excluded("/api/users", &set, ExcludeMode::Substring));
        // Case-insensitive.
        assert!(path_excluded("/X/%3B/Y", &set, ExcludeMode::Substring));
    }

    #[test]
    fn path_excluded_works_on_bare_paths() {
        let mut set = HashSet::new();
        set.insert("assets".to_string());
        // Bare wordlist entry (no scheme/host).
        assert!(path_excluded("assets", &set, ExcludeMode::Segment));
        assert!(path_excluded("/assets", &set, ExcludeMode::Segment));
        assert!(path_excluded("foo/assets", &set, ExcludeMode::Segment));
        assert!(!path_excluded("assets-list", &set, ExcludeMode::Segment));
    }

    #[test]
    fn default_excludes_cover_user_list_minus_js() {
        // Smoke-check the default list covers the non-JS patterns from
        // the user's bash EXCL list. JS-related entries (js, static/js,
        // assets/js, node_modules, _next, _nuxt, _app, __webpack*,
        // .sapper, .svelte-kit, @vite, @react-refresh, @fs,
        // bower_components) are DELIBERATELY excluded from defaults as
        // of v0.3.11 — JS files contain endpoints/config worth crawling.
        let set = build_exclude_set(None, None);
        for entry in &[
            "%2e%2e", "%2e.", ".%2e", "..%2f", "..%5c", "../", "..",
            "%3b", ";/", ";%2f", "..;",
            "%2f/", "//", "/../", "//..", "///",
            "%5c", "\\..",
            "/..//", "/;/", "/%3b", "/%5c",
            "assets", "css", "fonts", "images", "img", "icons", "media",
            "static/css", "static/fonts", "static/images", "static/img",
            "static/media", "static/icons",
        ] {
            assert!(
                set.contains(&entry.to_ascii_lowercase()),
                "missing default exclude entry: {}",
                entry
            );
        }
    }

    /// v0.3.11 — ensure JS-related entries are NOT in the default
    /// exclude list. JS files often contain real endpoints / config /
    /// secret leaks worth crawling. Users who want them dropped must
    /// opt in via `--add-excludes 'js,node_modules,...'`.
    #[test]
    fn defaults_do_not_block_js_crawl() {
        let set = build_exclude_set(None, None);
        for entry in &[
            "js",
            "static/js",
            "assets/js",
            "node_modules",
            "bower_components",
            "_next",
            "_nuxt",
            "_app",
            "__webpack",
            "__webpack_hmr",
            ".sapper",
            ".svelte-kit",
            "@vite",
            "@react-refresh",
            "@fs",
        ] {
            assert!(
                !set.contains(&entry.to_ascii_lowercase()),
                "v0.3.11 default exclude list must NOT contain JS-related entry: {} \
                 (JS crawling is supported by default; users opt out via --add-excludes)",
                entry
            );
        }
    }

    #[test]
    fn exclude_set_replaces_defaults_on_override() {
        let set = build_exclude_set(Some("foo,bar"), None);
        assert!(set.contains("foo"));
        assert!(set.contains("bar"));
        assert!(!set.contains("assets")); // default not present when override given
    }

    #[test]
    fn exclude_set_appends_on_add() {
        let set = build_exclude_set(None, Some("custom_dir,my_admin"));
        assert!(set.contains("assets"));
        assert!(set.contains("custom_dir"));
        assert!(set.contains("my_admin"));
        assert!(set.contains("%2e%2e")); // traversal default
    }

    #[test]
    fn exclude_set_empty_override_disables_all() {
        let set = build_exclude_set(Some(""), None);
        assert!(set.is_empty());
    }

    #[test]
    fn segment_excluded_case_insensitive() {
        let mut set = HashSet::new();
        set.insert("assets".to_string());
        assert!(segment_excluded("Assets", &set));
        assert!(segment_excluded("ASSETS", &set));
        assert!(!segment_excluded("admin", &set));
    }

    #[test]
    fn last_segment_basic() {
        assert_eq!(
            last_path_segment("https://x.com/admin/users").as_deref(),
            Some("users")
        );
        assert_eq!(
            last_path_segment("https://x.com/admin/users/").as_deref(),
            Some("users")
        );
        assert_eq!(
            last_path_segment("https://x.com/").as_deref(),
            None
        );
    }

    #[test]
    fn detect_directory_redirect_parity() {
        // 301 with Location == URL + "/" → directory.
        assert_eq!(
            detect_basic(
                "https://x.com/admin",
                301,
                "/admin/",
                "",
                false,
                false,
                false
            )
            .as_deref(),
            Some("https://x.com/admin/")
        );
        // 301 with constant Location → NOT a directory.
        assert_eq!(
            detect_basic(
                "https://x.com/admin",
                301,
                "/login",
                "",
                false,
                false,
                false
            ),
            None
        );
        // Query/fragment state belongs to the finding, not the recursion root.
        assert_eq!(
            detect_basic(
                "https://x.com/admin?view=compact#top",
                301,
                "/admin/",
                "",
                false,
                false,
                false,
            )
            .as_deref(),
            Some("https://x.com/admin/")
        );
    }

    #[test]
    fn detect_directory_rejects_file_like_redirects() {
        for path in [
            "/.well-known/security.txt",
            "/.well-known/jwks.json",
            "/.well-known/openapi.yaml",
            "/download/archive.tar.gz",
            "/admin.php",
        ] {
            let request = format!("https://x.com{path}");
            let location = format!("{path}/");
            assert_eq!(
                detect_basic(&request, 301, &location, "", false, false, false),
                None,
                "file-like path must not become a recursion root: {path}"
            );
        }
    }

    #[test]
    fn detect_directory_rejects_well_known_leaf_resources() {
        for leaf in [
            "apple-app-site-association",
            "change-password",
            "host-meta",
            "nodeinfo",
            "oauth-authorization-server",
            "openid-configuration",
            "webfinger",
        ] {
            let request = format!("https://x.com/.well-known/{leaf}");
            let location = format!("/.well-known/{leaf}/");
            assert_eq!(
                detect_basic(&request, 301, &location, "", false, false, false),
                None,
                "well-known leaf must not become a recursion root: {leaf}"
            );
        }
    }

    #[test]
    fn detect_directory_keeps_real_dotted_and_well_known_directories() {
        for (request, location) in [
            ("https://x.com/.well-known", "/.well-known/"),
            (
                "https://x.com/.well-known/acme-challenge",
                "/.well-known/acme-challenge/",
            ),
            ("https://x.com/releases/v1.2", "/releases/v1.2/"),
        ] {
            let expected = format!("{}/", request.trim_end_matches('/'));
            assert_eq!(
                detect_basic(request, 301, location, "", false, false, false)
                    .as_deref(),
                Some(expected.as_str()),
                "real directory must remain eligible: {request}"
            );
        }
    }

    #[test]
    fn file_like_guard_applies_to_non_redirect_recursion_signals() {
        assert!(detect_basic(
            "https://x.com/security.txt",
            200,
            "",
            "<h1>Index of /security.txt</h1>",
            true,
            false,
            false
        )
        .is_none());
        assert!(detect_basic(
            "https://x.com/openapi.json",
            403,
            "",
            "",
            false,
            true,
            false
        )
        .is_none());
    }

    #[test]
    fn response_evidence_accepts_real_200_directories() {
        for content_type in ["text/html", "application/json", ""] {
            assert_eq!(
                detect_directory(
                    "https://x.com/api/",
                    DirectoryResponse {
                        status: 200,
                        location: "",
                        content_type,
                        body: "<html><body>API root</body></html>",
                        headers: &[],
                    },
                    true,
                    false,
                    false,
                )
                .as_deref(),
                Some("https://x.com/api/")
            );
        }

        let content_location = vec![("Content-Location".to_string(), "/admin/".to_string())];
        assert_eq!(
            detect_directory(
                "https://x.com/admin",
                DirectoryResponse {
                    status: 200,
                    location: "",
                    content_type: "text/html",
                    body: "",
                    headers: &content_location,
                },
                true,
                false,
                false,
            )
            .as_deref(),
            Some("https://x.com/admin/")
        );

        assert_eq!(
            detect_directory(
                "https://x.com/dav",
                DirectoryResponse {
                    status: 200,
                    location: "",
                    content_type: "httpd/unix-directory",
                    body: "",
                    headers: &[],
                },
                true,
                false,
                false,
            )
            .as_deref(),
            Some("https://x.com/dav/")
        );
    }

    #[test]
    fn response_evidence_rejects_terminal_200_resources() {
        for content_type in [
            "text/plain; charset=utf-8",
            "application/pdf",
            "application/octet-stream",
            "image/png",
        ] {
            assert!(detect_directory(
                "https://x.com/download/",
                DirectoryResponse {
                    status: 200,
                    location: "",
                    content_type,
                    body: "payload",
                    headers: &[],
                },
                true,
                false,
                false,
            )
            .is_none());
        }

        let attachment = vec![(
            "content-disposition".to_string(),
            "attachment; filename=download".to_string(),
        )];
        assert!(detect_directory(
            "https://x.com/download/",
            DirectoryResponse {
                status: 200,
                location: "",
                content_type: "text/html",
                body: "",
                headers: &attachment,
            },
            true,
            false,
            false,
        )
        .is_none());

        // A generic 200 page without slash/header/index evidence is not enough.
        assert!(detect_directory(
            "https://x.com/dashboard",
            DirectoryResponse {
                status: 200,
                location: "",
                content_type: "text/html",
                body: "<html><h1>Dashboard</h1></html>",
                headers: &[],
            },
            true,
            false,
            false,
        )
        .is_none());
    }

    #[test]
    fn file_shape_detection_handles_encoding_case_and_hidden_directories() {
        assert!(detect_basic(
            "https://x.com/schema%2EJSON",
            301,
            "/schema%2EJSON/",
            "",
            false,
            false,
            false,
        )
        .is_none());
        assert_eq!(
            detect_basic(
                "https://x.com/.config",
                301,
                "/.config/",
                "",
                false,
                false,
                false,
            )
            .as_deref(),
            Some("https://x.com/.config/")
        );
        assert_eq!(
            directory_url("https://x.com/releases%20archive?download=1#top"),
            "https://x.com/releases%20archive/"
        );
    }

    #[test]
    fn detect_directory_autoindex() {
        assert_eq!(
            detect_basic(
                "https://x.com/files",
                200,
                "",
                "<html><h1>Index of /files</h1></html>",
                true,
                false,
                false
            )
            .as_deref(),
            Some("https://x.com/files/")
        );
        // recurse_on_200=false → no detection even with marker.
        assert_eq!(
            detect_basic(
                "https://x.com/files",
                200,
                "",
                "<html><h1>Index of /files</h1></html>",
                false,
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn detect_directory_403_opt_in() {
        assert!(detect_basic("https://x.com/secret", 403, "", "", false, false, false).is_none());
        assert!(detect_basic("https://x.com/secret", 403, "", "", false, true, false).is_some());
    }

    /// Auth-dir auto-recursion follows directory-shaped 401 responses. A 403
    /// remains opt-in because a path-sensitive WAF denial does not prove that
    /// the requested directory exists.
    #[test]
    fn detect_directory_auth_dir_shaped() {
        // 401 dir-shaped, auth on → recurse.
        assert_eq!(
            detect_basic("https://x.com/api", 401, "", "", false, false, true).as_deref(),
            Some("https://x.com/api/")
        );
        // 403 stays off under automatic auth recursion and needs opt-in.
        assert!(detect_basic("https://x.com/internal", 403, "", "", false, false, true).is_none());
        assert!(detect_basic("https://x.com/internal", 403, "", "", false, true, true).is_some());
        // 401 FILE-shaped (.php) → NOT recursed (no children to find).
        assert!(detect_basic("https://x.com/admin.php", 401, "", "", false, false, true).is_none());
        // auth off → 401 never recurses.
        assert!(detect_basic("https://x.com/api", 401, "", "", false, false, false).is_none());
        // 200 must NOT be treated as an auth dir.
        assert!(detect_basic("https://x.com/api", 200, "", "", false, false, true).is_none());
    }

    /// v0.4.10 — the dir cap is the one enforced recursion bound. Charging
    /// past `max_dirs` must refuse, so no further directories enter the
    /// frontier (each dir costs a full wordlist re-fuzz).
    /// v0.5.0 regression: `--add-excludes` must append even when
    /// `--exclude-subdirs` overrides the defaults. Before the fix the add-list
    /// was inside the `None` arm only, so passing both SILENTLY discarded the
    /// add-list — contradicting its documented "just adds" behaviour.
    #[test]
    fn add_excludes_appends_even_with_override() {
        // both set → override replaces defaults, add-list still applied
        let set = build_exclude_set(Some("only1,only2"), Some("extra1,extra2"));
        assert!(set.contains("only1") && set.contains("only2"), "override kept");
        assert!(
            set.contains("extra1") && set.contains("extra2"),
            "--add-excludes must NOT be dropped when --exclude-subdirs is set"
        );
        assert!(!set.contains("assets"), "defaults replaced by override");
        assert_eq!(set.len(), 4);

        // add-list alone → defaults + additions (unchanged behaviour)
        let d = build_exclude_set(None, Some("extra1"));
        assert!(d.contains("extra1") && d.contains("assets"));

        // empty override string disables defaults; add-list still honoured
        let e = build_exclude_set(Some(""), Some("kept"));
        assert!(e.contains("kept") && !e.contains("assets"));
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn host_budget_caps_dirs() {
        let b = HostBudget::new(3);
        assert!(b.try_inc_dir()); // 1
        assert!(b.try_inc_dir()); // 2
        assert!(b.try_inc_dir()); // 3
        assert!(!b.try_inc_dir()); // 4 → over cap
        assert!(!b.try_inc_dir()); // stays refused
        assert_eq!(b.max_dirs, 3);
    }

    #[test]
    fn canonical_url_key_lowercases_and_drops_query() {
        assert_eq!(
            canonical_url_key("HTTPS://Example.COM/Admin?x=1#frag"),
            "https://example.com:443/Admin"
        );
    }
}
