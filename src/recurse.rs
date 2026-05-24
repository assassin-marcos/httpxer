//! Recursion guards — strict directory detection + loop prevention.
//!
//! Three concerns this module owns:
//!   1. **Directory detection** — given a probe response, decide whether
//!      it signals "I'm a directory worth recursing into". Conservative
//!      by default (only 301/302/307/308 with `Location == URL+"/"` parity).
//!   2. **Self-similarity loop detection** — before enqueueing a new dir,
//!      check that the tail K path segments don't repeat an existing
//!      visited pattern. Catches `/admin/admin/admin/` cycles and
//!      `/foo/bar/foo/bar/` mutual-recursion patterns.
//!   3. **Per-host probe + dir budgets** — atomic counters that hard-cap
//!      total HTTP requests and discovered directories per input host.
//!      When hit, recursion stops for that host with a stderr warning.
//!
//! The smart `--exclude-subdirs` default list lives here too — built-in
//! asset/traversal noise that the user shouldn't have to specify.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Built-in `--exclude-subdirs` default — directories we never recurse
/// into unless the user explicitly overrides. Catches:
///   - Static asset dirs (recursing finds nothing real)
///   - JS framework asset prefixes (`_next`, `_nuxt`, `node_modules`)
///   - Encoded path-traversal noise (`%2e%2e`, `..`, `..%2f`)
///   - Common semicolon-trick paths (Java path-param injection)
///   - Health/probe endpoints (always 200 with same body, recursion noise)
pub const DEFAULT_EXCLUDE_SUBDIRS: &[&str] = &[
    // Static asset directories
    "assets",
    "static",
    "public",
    "dist",
    "build",
    "bundle",
    "bundles",
    "css",
    "js",
    "fonts",
    "images",
    "img",
    "media",
    "videos",
    "audio",
    "icons",
    "svg",
    // JS framework asset prefixes
    "node_modules",
    "vendor",
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
    // Encoded path-traversal noise
    "%2e%2e",
    "%2E%2E",
    "%2e%2e%2f",
    "%2e%2e%5c",
    "..%2f",
    "..%5c",
    "..;",
    // Common semicolon-trick paths
    "%3b",
    "%3B",
    ";",
    // Health/probe endpoints
    "healthz",
    "readyz",
    "livez",
    "ping",
    "_health",
    "_status",
];

/// True iff `path_segment` should be skipped per the merged exclude list
/// (built-in defaults + user `--add-excludes` + user `--exclude-subdirs`
/// override). Case-insensitive match on the segment as a string.
pub fn segment_excluded(path_segment: &str, exclude_set: &HashSet<String>) -> bool {
    let lc = path_segment.to_ascii_lowercase();
    exclude_set.contains(&lc)
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
            // Use defaults + append --add-excludes.
            for d in DEFAULT_EXCLUDE_SUBDIRS {
                out.insert(d.to_string());
            }
            if let Some(s) = add_list {
                for entry in s.split(',') {
                    let t = entry.trim().to_ascii_lowercase();
                    if !t.is_empty() {
                        out.insert(t);
                    }
                }
            }
        }
    }
    out
}

/// Inspect a URL's path and return its last non-empty segment, lowercased.
/// Used by the exclude check + the self-similarity detector.
pub fn last_path_segment(url: &str) -> Option<String> {
    let path = url::Url::parse(url).ok()?.path().to_string();
    path.trim_matches('/')
        .rsplit('/')
        .find(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
}

/// Self-similarity loop detector. Returns `true` if the last `window` path
/// segments of `candidate` repeat any consecutive `window` segments that
/// have already been seen in any previously-enqueued URL for this host.
///
/// Catches:
///   - `/admin/admin/admin/` (window=1 catches this)
///   - `/foo/bar/foo/bar/` (window=2 catches this)
///   - `/api/v1/api/v1/users/` (window=2 catches this)
///
/// `visited_segments_index` is a precomputed index of `(host, segment_pair)`
/// from prior enqueues — caller maintains it.
pub fn is_self_similar(
    candidate_url: &str,
    visited_segments_index: &Mutex<HashSet<Vec<String>>>,
    window: usize,
) -> bool {
    let Some(segs) = path_segments(candidate_url) else {
        return false;
    };
    if segs.len() < window {
        // Tail doesn't even exist — can't form a window to compare.
        return false;
    }
    let tail: Vec<String> = segs[segs.len() - window..]
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    // Within-URL self-repeat check — needs at least two windows of
    // segments (one for the tail + one earlier slot to compare against).
    if segs.len() >= window * 2 {
        for start in 0..=segs.len() - window * 2 {
            let earlier: Vec<String> = segs[start..start + window]
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect();
            if earlier == tail {
                return true;
            }
        }
    }
    // Cross-URL check — independent of within-URL length; if the tail
    // matches any window-pair we've seen from a different URL, that's a
    // sibling-loop signal.
    if let Ok(idx) = visited_segments_index.lock() {
        if idx.contains(&tail) {
            return true;
        }
    }
    false
}

/// Index update — call after enqueueing a URL so future self-similarity
/// checks can detect cross-URL loops.
pub fn index_segments(url: &str, visited_segments_index: &Mutex<HashSet<Vec<String>>>, window: usize) {
    let Some(segs) = path_segments(url) else { return };
    if segs.len() < window {
        return;
    }
    let mut idx = match visited_segments_index.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    for start in 0..=segs.len().saturating_sub(window) {
        let pair: Vec<String> = segs[start..start + window]
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        idx.insert(pair);
    }
}

fn path_segments(url: &str) -> Option<Vec<String>> {
    let parsed = url::Url::parse(url).ok()?;
    let path = parsed.path().to_string();
    let segs: Vec<String> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    Some(segs)
}

/// Strict directory detector. Returns `Some(dir_url_with_trailing_slash)`
/// when the response signals "directory worth recursing into".
///
/// Patterns recognised (most-specific, lowest-FP first):
///   1. **301/302/307/308** with `Location == URL + "/"` (classic Apache /
///      nginx missing-trailing-slash redirect). Constant-Location
///      catchalls (every path -> /login) FAIL this parity check.
///   2. **200** with body containing `Index of /` (autoindex marker) —
///      only when `recurse_on_200` is true.
///   3. **403** — only when `recurse_on_403` is true (too WAF-prone by
///      default).
///
/// `req_url` should be the URL we sent the request to (post-redirect-resolution).
/// `status` / `location` / `body_preview` describe the response we got back.
pub fn detect_directory(
    req_url: &str,
    status: u16,
    location: &str,
    body_preview: &str,
    recurse_on_200: bool,
    recurse_on_403: bool,
) -> Option<String> {
    // Pattern 1: redirect-to-trailing-slash.
    if matches!(status, 301 | 302 | 307 | 308) && !location.is_empty() {
        let want = format!("{}/", req_url.trim_end_matches('/'));
        let resolved = crate::probe::resolve_redirect_url(req_url, location);
        if resolved == want {
            return Some(want);
        }
        // Constant-Location catchall — Location is the same regardless
        // of the request path. NOT a directory; drop.
        return None;
    }
    // Pattern 2: 200 + autoindex marker.
    if status == 200 && recurse_on_200 {
        if body_preview.contains("Index of /") || body_preview.contains("<h1>Index of") {
            return Some(format!("{}/", req_url.trim_end_matches('/')));
        }
    }
    // Pattern 3: 403 explicit opt-in.
    if status == 403 && recurse_on_403 {
        return Some(format!("{}/", req_url.trim_end_matches('/')));
    }
    None
}

/// Per-host budget tracker. Atomic counters so workers can update without
/// contention. When `inc_probe` returns false, the host has hit its probe
/// cap and no more probes should be issued for it.
pub struct HostBudget {
    pub max_probes: usize,
    pub max_dirs: usize,
    probes: AtomicUsize,
    dirs: AtomicUsize,
}

impl HostBudget {
    pub fn new(max_probes: usize, max_dirs: usize) -> Self {
        Self {
            max_probes,
            max_dirs,
            probes: AtomicUsize::new(0),
            dirs: AtomicUsize::new(0),
        }
    }

    /// Try to charge one probe. Returns false when the budget is exhausted.
    pub fn try_inc_probe(&self) -> bool {
        let n = self.probes.fetch_add(1, Ordering::Relaxed);
        n < self.max_probes
    }

    /// Try to charge one directory discovery. Returns false when the dir
    /// budget is exhausted (no more dirs will enter the frontier).
    pub fn try_inc_dir(&self) -> bool {
        let n = self.dirs.fetch_add(1, Ordering::Relaxed);
        n < self.max_dirs
    }

    pub fn probes_used(&self) -> usize {
        self.probes.load(Ordering::Relaxed)
    }

    pub fn dirs_used(&self) -> usize {
        self.dirs.load(Ordering::Relaxed)
    }

    pub fn exhausted(&self) -> bool {
        self.probes.load(Ordering::Relaxed) >= self.max_probes
            || self.dirs.load(Ordering::Relaxed) >= self.max_dirs
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
    fn self_similar_within_url_detected() {
        let idx = Mutex::new(HashSet::new());
        // /admin/admin/admin/ has tail "admin" repeating earlier "admin"
        assert!(is_self_similar(
            "https://x.com/admin/admin/admin/",
            &idx,
            1
        ));
        // /foo/bar/foo/bar/ — tail "foo/bar" repeats earlier
        assert!(is_self_similar(
            "https://x.com/foo/bar/foo/bar/",
            &idx,
            2
        ));
        // /admin/users/posts/ — no repeat
        assert!(!is_self_similar(
            "https://x.com/admin/users/posts/",
            &idx,
            2
        ));
    }

    #[test]
    fn index_then_detect_cross_url_loop() {
        let idx = Mutex::new(HashSet::new());
        index_segments("https://x.com/admin/api/", &idx, 2);
        // Different URL but the tail matches an indexed pair → loop.
        // Actually only detected when the tail of the candidate matches
        // exactly the indexed window. /api/admin/ has tail "admin" or
        // "api/admin" depending on window; we used window=2 so the tail
        // would be the last 2 segs.
        // /a/b/admin/api → tail [admin, api] — matches indexed pair.
        assert!(is_self_similar(
            "https://x.com/something/admin/api",
            &idx,
            2
        ));
    }

    #[test]
    fn detect_directory_redirect_parity() {
        // 301 with Location == URL + "/" → directory.
        assert_eq!(
            detect_directory(
                "https://x.com/admin",
                301,
                "/admin/",
                "",
                false,
                false
            )
            .as_deref(),
            Some("https://x.com/admin/")
        );
        // 301 with constant Location → NOT a directory.
        assert_eq!(
            detect_directory(
                "https://x.com/admin",
                301,
                "/login",
                "",
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn detect_directory_autoindex() {
        assert_eq!(
            detect_directory(
                "https://x.com/files",
                200,
                "",
                "<html><h1>Index of /files</h1></html>",
                true,
                false
            )
            .as_deref(),
            Some("https://x.com/files/")
        );
        // recurse_on_200=false → no detection even with marker.
        assert_eq!(
            detect_directory(
                "https://x.com/files",
                200,
                "",
                "<html><h1>Index of /files</h1></html>",
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn detect_directory_403_opt_in() {
        assert!(detect_directory("https://x.com/secret", 403, "", "", false, false).is_none());
        assert!(detect_directory("https://x.com/secret", 403, "", "", false, true).is_some());
    }

    #[test]
    fn host_budget_caps_probes() {
        let b = HostBudget::new(3, 100);
        assert!(b.try_inc_probe()); // 1
        assert!(b.try_inc_probe()); // 2
        assert!(b.try_inc_probe()); // 3
        assert!(!b.try_inc_probe()); // 4 → over cap
        assert!(b.exhausted());
    }

    #[test]
    fn canonical_url_key_lowercases_and_drops_query() {
        assert_eq!(
            canonical_url_key("HTTPS://Example.COM/Admin?x=1#frag"),
            "https://example.com:443/Admin"
        );
    }
}
