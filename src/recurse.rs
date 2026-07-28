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
    recurse_on_auth: bool,
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
    // Pattern 3: 403 explicit opt-in (legacy flag — recurses ANY 403).
    if status == 403 && recurse_on_403 {
        return Some(format!("{}/", req_url.trim_end_matches('/')));
    }
    // Pattern 4 (v0.4.5): auth-dir auto-recursion. A 401/403 on a
    // DIRECTORY-SHAPED path (no file extension, e.g. /api, /internal) is a
    // protected directory worth descending into — its children may be
    // accessible (e.g. /api=401 but /api/actuator=200). Gated to dir-shaped
    // paths so we don't waste the wordlist recursing a protected *file*
    // (/admin.php), and bounded by the per-host --max-dirs-per-host budget.
    // The 401/403 itself is NOT emitted (caller filters by status), so this
    // adds coverage with no output noise.
    if recurse_on_auth && matches!(status, 401 | 403) && is_dir_shaped(req_url) {
        return Some(format!("{}/", req_url.trim_end_matches('/')));
    }
    None
}

/// True if the URL's last path segment looks like a directory (no file
/// extension), e.g. `/api`, `/internal/v2` → true; `/x.php`, `/a.bak` → false.
/// Used to gate auth-dir auto-recursion to plausible directories only.
fn is_dir_shaped(req_url: &str) -> bool {
    let after_scheme = req_url.split("://").nth(1).unwrap_or(req_url);
    let path = after_scheme
        .find('/')
        .map(|i| &after_scheme[i..])
        .unwrap_or("/");
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let last = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    !last.is_empty() && !last.contains('.')
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
            detect_directory(
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
            detect_directory(
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
                false,
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
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn detect_directory_403_opt_in() {
        // Legacy --recurse-on-403 flag recurses ANY 403 (auth off here).
        assert!(detect_directory("https://x.com/secret", 403, "", "", false, false, false).is_none());
        assert!(detect_directory("https://x.com/secret", 403, "", "", false, true, false).is_some());
    }

    /// v0.4.5 — auth-dir auto-recursion: a 401/403 on a directory-shaped path
    /// recurses (so /api → /api/actuator is found); a file-shaped path does not.
    #[test]
    fn detect_directory_auth_dir_shaped() {
        // 401 dir-shaped, auth on → recurse.
        assert_eq!(
            detect_directory("https://x.com/api", 401, "", "", false, false, true).as_deref(),
            Some("https://x.com/api/")
        );
        // 403 dir-shaped, auth on → recurse.
        assert!(detect_directory("https://x.com/internal", 403, "", "", false, false, true).is_some());
        // 401 FILE-shaped (.php) → NOT recursed (no children to find).
        assert!(detect_directory("https://x.com/admin.php", 401, "", "", false, false, true).is_none());
        // auth off → 401 never recurses.
        assert!(detect_directory("https://x.com/api", 401, "", "", false, false, false).is_none());
        // 200 must NOT be treated as an auth dir.
        assert!(detect_directory("https://x.com/api", 200, "", "", false, false, true).is_none());
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
