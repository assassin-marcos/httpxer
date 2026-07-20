//! Per-host wildcard detection.
//!
//! For each host, the fuzz orchestrator first probes `/<32 random hex chars>`.
//! If the response is 200/3xx with a body, record
//! `(content_length, content_type, snippet_md5)` and use it as a fingerprint —
//! any subsequent fuzz hit with the SAME triple is flagged `is_wildcard:true`.
//!
//! Common real-world case: a host returns an identical small HTML 404
//! page for every path. Without per-host wildcard suppression, every
//! fuzzer hit on that host scores as a finding even though nothing
//! exists — debug.log, error.log, terraform.tfvars all look "200 OK"
//! to a basic status-code filter.
//!
//! The map key is the bare hostname (no scheme) — that's the unit httpxer's
//! input pipeline normalises everything to via `extract_host()`.

use md5::{Digest, Md5};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Upper bound for learned static-catchall size drift. Above this, same-prefix
/// random-path responses are treated as an app-shell wildcard where the
/// content length is not reliable enough to participate in matching.
const MAX_DYNAMIC_LAYER1_TOLERANCE: i64 = 256;
const DYNAMIC_LAYER1_SLACK: i64 = 16;

/// Minimum pairwise raw-body token-similarity required for the content-aware
/// catchall layer (Layer 1b) to fire. This is a SECONDARY backstop — the
/// primary guard is the exact normalized-snippet hash match (both samples must
/// normalize to the identical 200-char fingerprint). The token ratio only
/// guards against an over-aggressive normalizer fusing two *structurally
/// different* pages, which sit near ~0.5 or below. Kept at 0.70 (not higher)
/// because SHORT catchall bodies ("404 not found" + a nonce) legitimately have
/// few shared tokens, so one varying nonce can drag a high-similarity body down
/// toward ~0.85 — still clearly a wildcard, must not be rejected.
const L1B_TOKEN_RATIO_MIN: f64 = 0.70;
/// Raw-body prefix (bytes) used for the token-ratio guard — cheap + the
/// volatile region we target sits near the top of error bodies.
const L1B_TOKEN_PREFIX_BYTES: usize = 2048;

/// Per-host wildcard fingerprint. Carries BOTH layers of detection:
///
/// **Layer 1 (static catchall)** — `content_length` + `content_type` +
/// `snippet_md5` describe an identical wildcard response. Set when all
/// pre-flight samples returned the same body bytes (modulo `tolerance`).
///
/// **Layer 2 (path-echo / dynamic-CL)** — `k` + `base` describe a linear
/// relationship `CL = k × path_len + base` (k = how many times the path
/// appears in the body, base = the constant portion's size). Set when
/// Layer 1 failed but pre-flight samples' (CL, path_len) pairs fit a line.
/// This is the dirsearch / feroxbuster pattern that defeats single-sample
/// detection on path-echo servers (`/anything → 200 + "Resource /anything
/// not found"`). New in v0.3.9.
///
/// At runtime, `matches()` tries both layers in order — Layer 1 first
/// (cheap), Layer 2 second (formula-based). A probe matches the wildcard
/// if EITHER layer fires. `tolerance` is the per-byte CL slack permitted
/// for both layers (default 10 bytes — accommodates timestamps / request
/// IDs in error bodies without over-suppressing real findings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WildcardSig {
    pub content_length: i64,
    pub content_type: String,
    pub snippet_md5: String,
    /// Layer 2 slope — number of times the requested path appears in the
    /// wildcard body. `None` = Layer 1-only fingerprint (no path-echo
    /// pattern detected). When `Some`, `base` MUST also be Some.
    pub k: Option<i64>,
    /// Layer 2 intercept — constant portion of body size (everything
    /// except the path echoes).
    pub base: Option<i64>,
    /// Per-byte tolerance for both layers' CL matching. Accommodates
    /// timestamps / request IDs in error bodies. Default 10.
    pub tolerance: i64,
    /// **Layer 1b (content-aware catchall)** — md5 of the *normalized* body
    /// (`normalize_snippet`): volatile tokens (UUIDs, long hex/number runs,
    /// timestamps) blanked, whitespace collapsed. Set when the server returns
    /// a near-constant-size body that differs only in a per-request nonce.
    /// Empty for L1 / L2 sigs. When non-empty (and `snippet_md5` empty,
    /// `k` None), runtime matching is by normalized CONTENT — never size-only
    /// — so a real same-size page with different content is NOT suppressed.
    pub normalized_snippet_md5: String,
}

impl WildcardSig {
    /// Backwards-compat constructor — Layer 1 only, default tolerance.
    pub fn layer1(content_length: i64, content_type: String, snippet_md5: String) -> Self {
        Self {
            content_length,
            content_type,
            snippet_md5,
            k: None,
            base: None,
            tolerance: 10,
            normalized_snippet_md5: String::new(),
        }
    }

    /// True if a probe response matches THIS signature. Content-aware and
    /// shared by both `WildcardMap::matches_body` (host-level) and the
    /// per-directory catchall cache (v0.4.6): Layer 1b matches by NORMALIZED
    /// body only (never size-only, so a real same-size page survives); Layer 1
    /// by exact md5 + CL tolerance (or any CL when `content_length < 0`);
    /// Layer 2 by the path-echo formula `CL ≈ k × path_len + base`.
    pub fn matches_probe(
        &self,
        cl: i64,
        ct: &str,
        md5: &str,
        probe_path_len: usize,
        raw_body: &str,
    ) -> bool {
        let tol = self.tolerance;

        // Layer 1b (content-aware): empty snippet_md5 + present normalized hash
        // + k None. Authoritative for such sigs — match by normalized content.
        if self.k.is_none() && self.snippet_md5.is_empty() && !self.normalized_snippet_md5.is_empty()
        {
            return self.content_type == ct
                && md5_hex(&normalize_snippet(raw_body)) == self.normalized_snippet_md5;
        }

        // Layer 1 — static catchall (CT + exact md5; CL within tolerance, or
        // any CL when content_length < 0 = app-shell fallback).
        if !self.snippet_md5.is_empty() && self.content_type == ct && self.snippet_md5 == md5 {
            if self.content_length < 0 {
                return true;
            }
            if (self.content_length - cl).abs() <= tol {
                return true;
            }
        }

        // Layer 2 — path-echo linear formula.
        if let (Some(k), Some(base)) = (self.k, self.base) {
            if self.content_type == ct {
                let expected = k * probe_path_len as i64 + base;
                if (expected - cl).abs() <= tol {
                    return true;
                }
            }
        }
        false
    }
}

/// One probe sample collected during wildcard pre-flight. Carries the
/// `path_len` (length of the URL path used) so Layer 2 detection can
/// compute the linear `CL = k × path_len + base` relationship.
#[derive(Debug, Clone)]
pub struct ProbeSample {
    pub status: u16,
    pub content_length: i64,
    pub content_type: String,
    pub snippet_md5: String,
    pub path_len: usize,
    /// Full (lossy-decoded, body-cap-bounded) response body. Already produced
    /// by `dispatch_one`; carried here so Layer 1b can fingerprint by
    /// *normalized content* rather than size alone. Empty when unavailable.
    pub raw_body: String,
}

/// Normalize a response body for content-aware catchall fingerprinting:
/// blank out per-request volatile tokens (UUIDs, long hex/number runs,
/// ISO timestamps) and collapse whitespace, then keep the first 200 chars.
/// Two catchall responses that differ ONLY in a nonce normalize to the same
/// string; two genuinely different pages do not. Conservative by design —
/// these patterns are essentially absent from real HTML/JSON body prefixes
/// except as the volatile tokens we intend to erase.
pub(crate) fn normalize_snippet(body: &str) -> String {
    static NORM_RES: OnceLock<[regex::Regex; 4]> = OnceLock::new();
    let res = NORM_RES.get_or_init(|| {
        [
            // RFC-4122 UUID
            regex::Regex::new(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            )
            .unwrap(),
            // Long hex run (request-id / trace-id / hash)
            regex::Regex::new(r"[0-9a-fA-F]{16,}").unwrap(),
            // Long digit run (epoch ms/s, counters)
            regex::Regex::new(r"[0-9]{10,}").unwrap(),
            // ISO-8601 timestamp
            regex::Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}").unwrap(),
        ]
    });
    // Cap input before regex work; volatile tokens sit near the top.
    let mut s: String = body.chars().take(L1B_TOKEN_PREFIX_BYTES).collect();
    for re in res.iter() {
        s = re.replace_all(&s, "\u{1}").into_owned();
    }
    // Collapse whitespace, then keep the first 200 chars of the normalized text.
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(200)
        .collect()
}

/// md5 hex of a string — same digest path `dispatch_one` uses for snippet_md5.
pub(crate) fn md5_hex(s: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

/// Minimum pairwise token-set similarity across samples' raw bodies, using
/// `2·|A∩B| / (|A|+|B|)` over the first `L1B_TOKEN_PREFIX_BYTES`. Returns 1.0
/// when fewer than two samples (nothing to disagree) or all token sets are
/// empty (trivially identical). Guards Layer 1b against over-normalization.
pub(crate) fn min_pairwise_token_ratio(samples: &[ProbeSample]) -> f64 {
    fn tokens(body: &str) -> std::collections::HashSet<String> {
        body.chars()
            .take(L1B_TOKEN_PREFIX_BYTES)
            .collect::<String>()
            .to_ascii_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string())
            .collect()
    }
    if samples.len() < 2 {
        return 1.0;
    }
    let sets: Vec<_> = samples.iter().map(|s| tokens(&s.raw_body)).collect();
    let mut min_ratio = 1.0_f64;
    for i in 0..sets.len() {
        for j in (i + 1)..sets.len() {
            let inter = sets[i].intersection(&sets[j]).count();
            let total = sets[i].len() + sets[j].len();
            let ratio = if total == 0 {
                1.0
            } else {
                2.0 * inter as f64 / total as f64
            };
            if ratio < min_ratio {
                min_ratio = ratio;
            }
        }
    }
    min_ratio
}

/// Reduce a host key to its base `scheme://authority`, dropping any path —
/// `https://x.com/api/v2` → `https://x.com`. Lets a recursed dir URL fall back
/// to the base-host wildcard fingerprint recorded at round 0.
fn base_input_key(s: &str) -> String {
    if let Some(scheme_end) = s.find("://") {
        let after = scheme_end + 3;
        if let Some(slash) = s[after..].find('/') {
            return s[..after + slash].to_string();
        }
    }
    s.to_string()
}

/// Backwards-compat helper — pure Layer 1 (static catchall) agreement
/// check. Use `detect()` for the layered v0.3.9 detector.
pub fn agreed_from_samples(samples: &[WildcardSig]) -> Option<WildcardSig> {
    let first = samples.first()?.clone();
    if samples.iter().all(|s| {
        s.content_length == first.content_length
            && s.content_type == first.content_type
            && s.snippet_md5 == first.snippet_md5
    }) {
        Some(first)
    } else {
        None
    }
}

/// Two-layer wildcard detector — the v0.3.9 upgrade.
///
/// Returns `Some(sig)` when EITHER:
///   - **Layer 1**: all samples agree on `(CL, CT, snippet_md5)` (modulo
///     `tolerance`) → static catchall fingerprint stored.
///   - **Layer 2**: Layer 1 failed but samples fit a linear relationship
///     `CL = k × path_len + base` with same `content_type` and small
///     residuals → path-echo fingerprint stored.
///
/// Returns `None` when neither layer fires — the server is truly
/// path-sensitive and we cannot reliably distinguish wildcard from real
/// findings. Caller marks the dir path-sensitive and skips suppression.
///
/// `tolerance` (typical: 10) absorbs timestamp / request-ID jitter that
/// would otherwise defeat exact-match agreement.
pub fn detect(samples: &[ProbeSample], tolerance: i64) -> Option<WildcardSig> {
    if samples.is_empty() {
        return None;
    }
    let first = &samples[0];

    // ── Layer 1: static catchall (allow learned CL tolerance for jitter). ─────
    let same_ct_and_prefix = samples
        .iter()
        .all(|s| s.content_type == first.content_type && s.snippet_md5 == first.snippet_md5);
    if same_ct_and_prefix {
        let min_cl = samples
            .iter()
            .map(|s| s.content_length)
            .min()
            .unwrap_or(first.content_length);
        let max_cl = samples
            .iter()
            .map(|s| s.content_length)
            .max()
            .unwrap_or(first.content_length);
        let spread = max_cl - min_cl;
        let (content_length, learned_tolerance) = if spread <= MAX_DYNAMIC_LAYER1_TOLERANCE {
            let learned_tolerance = if spread <= tolerance {
                tolerance
            } else {
                spread.saturating_add(DYNAMIC_LAYER1_SLACK)
            };
            // Store the midpoint so runtime matching covers both sides of the
            // learned range with one tolerance value.
            (min_cl + spread / 2, learned_tolerance)
        } else {
            // App-shell fallback: random paths agree on the first body chunk
            // but carry large request-specific payload differences later in
            // the body. In this mode, matching is CT + first-body fingerprint
            // only; content length is intentionally ignored at runtime.
            (-1, 0)
        };
        return Some(WildcardSig {
            content_length,
            content_type: first.content_type.clone(),
            snippet_md5: first.snippet_md5.clone(),
            k: None,
            base: None,
            tolerance: learned_tolerance,
            normalized_snippet_md5: String::new(),
        });
    }

    // ── Layer 1b (content-aware): same CT + bounded CL spread, body varies
    //    only in a per-request nonce. ──────────────────────────────────────
    // Catches catchall servers that return a near-constant-size body with
    // per-request dynamic content (timestamp, request ID, nonce). L1 misses
    // these because snippet_md5 differs; L2 misses them because CL doesn't
    // scale with path length (k≈0). We fingerprint by NORMALIZED CONTENT
    // (volatile tokens blanked) so runtime matching is content-based, never
    // size-only — a real same-size page with different content is NOT
    // suppressed. Two guards prevent over-suppression: (1) bounded CL spread
    // (≤256), (2) raw-body token-similarity ≥ L1B_TOKEN_RATIO_MIN, so an
    // over-aggressive normalizer can't fuse two structurally different pages.
    // Requires real bodies — content fingerprinting is meaningless without
    // them (and pre-flight always captures a non-empty body for 2xx/3xx).
    let same_ct_with_bodies = samples
        .iter()
        .all(|s| s.content_type == first.content_type && !s.raw_body.is_empty());
    if same_ct_with_bodies {
        let min_cl = samples
            .iter()
            .map(|s| s.content_length)
            .min()
            .unwrap_or(first.content_length);
        let max_cl = samples
            .iter()
            .map(|s| s.content_length)
            .max()
            .unwrap_or(first.content_length);
        let spread = max_cl - min_cl;
        if spread <= MAX_DYNAMIC_LAYER1_TOLERANCE {
            let norm: Vec<String> = samples
                .iter()
                .map(|s| md5_hex(&normalize_snippet(&s.raw_body)))
                .collect();
            let normalized_agree = norm.iter().all(|h| *h == norm[0]);
            if normalized_agree && min_pairwise_token_ratio(samples) >= L1B_TOKEN_RATIO_MIN {
                // Tolerance: cover the observed spread for the (secondary) CL
                // sanity check; primary match is the normalized-content hash.
                let learned_tolerance = if spread <= tolerance {
                    tolerance
                } else {
                    spread.saturating_add(DYNAMIC_LAYER1_SLACK)
                };
                return Some(WildcardSig {
                    content_length: min_cl + spread / 2,
                    content_type: first.content_type.clone(),
                    snippet_md5: String::new(),
                    k: None,
                    base: None,
                    tolerance: learned_tolerance,
                    normalized_snippet_md5: norm[0].clone(),
                });
            }
        }
    }

    // ── Layer 2: linear CL = k × path_len + base. ─────────────────────
    // Need at least 2 samples with DIFFERENT path_lens to compute slope.
    if samples.len() < 2 {
        return None;
    }
    let same_ct = samples.iter().all(|s| s.content_type == first.content_type);
    if !same_ct {
        return None;
    }
    // Pick the path-length extremes for slope calculation (most stable
    // estimate against per-sample jitter).
    let min_s = samples.iter().min_by_key(|s| s.path_len).unwrap();
    let max_s = samples.iter().max_by_key(|s| s.path_len).unwrap();
    let dx = max_s.path_len as i64 - min_s.path_len as i64;
    if dx == 0 {
        // All samples used the same path length → can't compute slope.
        return None;
    }
    let dy = max_s.content_length - min_s.content_length;
    // Round to nearest integer K (we expect 1, 2, 3, occasionally more).
    let k_float = dy as f64 / dx as f64;
    let k = k_float.round() as i64;
    // K must be a sane "path appears N times" count. Outside [1, 20]
    // suggests this isn't actually a path-echo pattern.
    if !(1..=20).contains(&k) {
        return None;
    }
    let base = min_s.content_length - k * min_s.path_len as i64;
    // Verify ALL samples fit the formula within tolerance.
    for s in samples {
        let expected = k * s.path_len as i64 + base;
        if (expected - s.content_length).abs() > tolerance {
            return None;
        }
    }
    Some(WildcardSig {
        content_length: -1,
        content_type: first.content_type.clone(),
        snippet_md5: String::new(),
        k: Some(k),
        base: Some(base),
        tolerance,
        normalized_snippet_md5: String::new(),
    })
}

/// In-memory map of host → wildcard signature. Constructed once at fuzz
/// pre-flight then handed out to workers as `Arc<WildcardMap>`.
#[derive(Debug, Default)]
pub struct WildcardMap {
    inner: HashMap<String, WildcardSig>,
}

impl WildcardMap {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    pub fn insert(&mut self, host: String, sig: WildcardSig) {
        self.inner.insert(host, sig);
    }

    #[allow(dead_code)]
    pub fn get(&self, host: &str) -> Option<&WildcardSig> {
        self.inner.get(host)
    }

    /// Back-compat wrapper — matching without the response body. Cannot fire
    /// the content-aware Layer 1b (which needs the body); use `matches_body`
    /// in the live fuzz path. Retained for the many call sites / tests that
    /// only exercise Layer 1 (exact md5) and Layer 2 (formula).
    #[allow(dead_code)]
    pub fn matches(&self, host: &str, cl: i64, ct: &str, md5: &str, probe_path_len: usize) -> bool {
        self.matches_body(host, cl, ct, md5, probe_path_len, "")
    }

    /// True if this probe matches the recorded wildcard signature for this
    /// host. Checks Layer 1 (static catchall, exact md5), Layer 1b
    /// (content-aware catchall, normalized-body hash) and Layer 2 (path-echo
    /// linear formula). `probe_path_len` is the byte length of the URL path;
    /// `raw_body` is the probe's response body (for Layer 1b normalization).
    pub fn matches_body(
        &self,
        host: &str,
        cl: i64,
        ct: &str,
        md5: &str,
        probe_path_len: usize,
        raw_body: &str,
    ) -> bool {
        // Exact key first; then fall back to the base scheme://authority key.
        // Recursion passes a DISCOVERED DIR URL (e.g. https://x.com/api) as the
        // host, but the round-0 fingerprint is stored under the base input
        // (https://x.com) — without this fallback the host catchall wouldn't be
        // suppressed under recursed dirs (catchall junk would leak). v0.4.5.
        let sig = match self.inner.get(host) {
            Some(s) => s,
            None => {
                let base = base_input_key(host);
                match self.inner.get(&base) {
                    Some(s) => s,
                    None => return false,
                }
            }
        };
        // Per-sig content-aware match (shared with the per-directory catchall
        // cache in fuzz.rs). Layers L1b / L1 / L2 in order.
        sig.matches_probe(cl, ct, md5, probe_path_len, raw_body)
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: keying by bare hostname caused two inputs that share a
    /// host but differ in path prefix to collide — the second wildcard
    /// preflight silently overwrote the first. Fuzz now keys by the full
    /// host_to_input string, so the two coexist.
    fn l1(cl: i64, ct: &str, md5: &str) -> WildcardSig {
        WildcardSig::layer1(cl, ct.into(), md5.into())
    }

    fn s(cl: i64, ct: &str, md5: &str, path_len: usize) -> ProbeSample {
        ProbeSample {
            status: 200,
            content_length: cl,
            content_type: ct.into(),
            snippet_md5: md5.into(),
            path_len,
            raw_body: String::new(),
        }
    }

    /// Content-aware sample helper — carries a `raw_body` so Layer 1b tests
    /// can exercise normalized-content fingerprinting.
    fn sb(cl: i64, ct: &str, md5: &str, path_len: usize, raw_body: &str) -> ProbeSample {
        ProbeSample {
            status: 200,
            content_length: cl,
            content_type: ct.into(),
            snippet_md5: md5.into(),
            path_len,
            raw_body: raw_body.into(),
        }
    }

    /// v0.4.6 sibling-probe core: a prefix that returns a byte-identical shell
    /// for every sub-path yields a sig via `detect`; that sig (via the shared
    /// `matches_probe`) suppresses a same-shell hit but NOT a real, different
    /// page under the same prefix (the "no missing results" guarantee).
    #[test]
    fn sibling_probe_sig_suppresses_shell_but_not_real_page() {
        let shell = "<!doctype html><html><head><title>CRM</title></head><body>\
                     <div id=app></div><script src=/crm/main.js></script></body></html>";
        // Two random siblings under /crm → identical shell, different path_lens.
        let samples = vec![
            sb(1232, "text/html; charset=UTF-8", "shellmd5", 17, shell),
            sb(1232, "text/html; charset=UTF-8", "shellmd5", 33, shell),
        ];
        let sig = detect(&samples, 10).expect("constant shell yields a catchall sig");
        // A genuine catchall hit (same shell, any path) → suppressed.
        assert!(sig.matches_probe(1232, "text/html; charset=UTF-8", "shellmd5", 9, shell));
        // A real page under the same prefix (different body + md5 + size) →
        // NOT suppressed.
        let real = "{\"user\":\"admin\",\"secret\":\"exposed-token-value-here\"}";
        assert!(!sig.matches_probe(64, "application/json", "realmd5", 9, real));
    }

    #[test]
    fn map_keys_dont_collide_across_path_prefixes() {
        let mut m = WildcardMap::new();
        m.insert("https://x.com/api".into(), l1(100, "text/html", "aaa"));
        m.insert("https://x.com/admin".into(), l1(200, "text/html", "bbb"));
        assert_eq!(m.len(), 2, "different path-prefixes must stay distinct");
        // probe_path_len doesn't matter for Layer 1 matches.
        assert!(m.matches("https://x.com/api", 100, "text/html", "aaa", 0));
        assert!(m.matches("https://x.com/admin", 200, "text/html", "bbb", 0));
        assert!(!m.matches("https://x.com/api", 200, "text/html", "bbb", 0));
    }

    #[test]
    fn agreed_three_identical_samples() {
        let s = l1(100, "text/html", "abc");
        let samples = vec![s.clone(), s.clone(), s.clone()];
        assert_eq!(agreed_from_samples(&samples), Some(s));
    }

    #[test]
    fn agreed_returns_none_when_samples_disagree() {
        let a = l1(100, "text/html", "abc");
        let b = l1(100, "text/html", "DIFFERENT");
        assert!(agreed_from_samples(&[a.clone(), a, b]).is_none());
    }

    #[test]
    fn agreed_single_sample_passes_through() {
        let s = l1(100, "text/html", "abc");
        assert_eq!(agreed_from_samples(&[s.clone()]), Some(s));
    }

    #[test]
    fn agreed_empty_returns_none() {
        assert!(agreed_from_samples(&[]).is_none());
    }

    #[test]
    fn match_only_when_all_three_align_layer1() {
        let mut m = WildcardMap::new();
        m.insert("x.com".into(), l1(100, "text/html", "abc"));
        assert!(m.matches("x.com", 100, "text/html", "abc", 0));
        assert!(!m.matches("x.com", 100, "text/html", "xyz", 0));
        assert!(!m.matches("x.com", 100, "application/json", "abc", 0));
        // Layer 1 has ±10 tolerance built into the new matcher → 105 still
        // matches (formerly would not under exact match).
        assert!(m.matches("x.com", 105, "text/html", "abc", 0));
        // 111 is outside the ±10 tolerance → does NOT match.
        assert!(!m.matches("x.com", 111, "text/html", "abc", 0));
        assert!(!m.matches("y.com", 100, "text/html", "abc", 0));
    }

    // ── Layer 2 (v0.3.9) — path-echo / dynamic-CL detection ────────────

    /// Three samples with CL = 3 × path_len + 200 → Layer 2 fits with K=3.
    #[test]
    fn detect_layer2_fits_linear_relationship() {
        let samples = vec![
            s(251, "text/html", "md5-A", 17), // 3*17 + 200 = 251
            s(299, "text/html", "md5-B", 33), // 3*33 + 200 = 299
            s(395, "text/html", "md5-C", 65), // 3*65 + 200 = 395
        ];
        let sig = detect(&samples, 10).expect("Layer 2 should fit");
        assert_eq!(sig.k, Some(3));
        assert_eq!(sig.base, Some(200));
        assert_eq!(sig.content_type, "text/html");
    }

    /// Same as above but with ±2 bytes per-sample jitter (e.g. timestamp
    /// fluctuation in error body). Should still detect K=3.
    #[test]
    fn detect_layer2_tolerates_per_sample_jitter() {
        let samples = vec![
            s(250, "text/html", "md5-A", 17), // expected 251, off by -1
            s(301, "text/html", "md5-B", 33), // expected 299, off by +2
            s(394, "text/html", "md5-C", 65), // expected 395, off by -1
        ];
        let sig = detect(&samples, 10).expect("Layer 2 should fit within tolerance");
        assert_eq!(sig.k, Some(3));
    }

    /// Layer 1 must beat Layer 2 when both could fit (static catchall first).
    #[test]
    fn detect_prefers_layer1_when_both_possible() {
        let samples = vec![
            s(100, "text/html", "abc", 17),
            s(100, "text/html", "abc", 33),
            s(100, "text/html", "abc", 65),
        ];
        let sig = detect(&samples, 10).unwrap();
        assert!(sig.k.is_none(), "should pick Layer 1, not Layer 2");
        assert_eq!(sig.content_length, 100);
    }

    /// Dynamic fake-200 pages can keep the same first body chunk but drift in
    /// total size because of request IDs / state payloads. This used to be
    /// misclassified as path-sensitive once drift exceeded the hardcoded ±10.
    #[test]
    fn detect_layer1_learns_bounded_size_drift() {
        let samples = vec![
            s(55_523, "text/html; charset=utf-8", "same-prefix", 17),
            s(55_495, "text/html; charset=utf-8", "same-prefix", 33),
            s(55_511, "text/html; charset=utf-8", "same-prefix", 65),
        ];
        let sig = detect(&samples, 10).expect("bounded same-prefix drift is a wildcard");
        assert!(sig.k.is_none(), "dynamic static catchall stays Layer 1");
        assert_eq!(sig.content_type, "text/html; charset=utf-8");
        assert_eq!(sig.snippet_md5, "same-prefix");
        assert!(
            sig.tolerance > 10,
            "runtime tolerance must expand beyond the old fixed window"
        );

        let mut m = WildcardMap::new();
        m.insert("x.com".into(), sig);
        assert!(m.matches(
            "x.com",
            55_500,
            "text/html; charset=utf-8",
            "same-prefix",
            128,
        ));
    }

    /// App-shell fallback: a shared prefix with very large size spread is still
    /// a wildcard when the samples came from random paths. Content length is
    /// too noisy to use, so runtime matching falls back to CT + first-body hash.
    #[test]
    fn detect_layer1_ignores_length_for_wide_same_prefix_spread() {
        let samples = vec![
            s(49_189, "text/html; charset=utf-8", "same-prefix", 17),
            s(55_523, "text/html; charset=utf-8", "same-prefix", 33),
            s(55_785, "text/html; charset=utf-8", "same-prefix", 65),
        ];
        let sig = detect(&samples, 10).expect("same-prefix app shell is a wildcard");
        assert_eq!(sig.content_length, -1, "wide drift must ignore CL");
        assert_eq!(sig.tolerance, 0);

        let mut m = WildcardMap::new();
        m.insert("x.com".into(), sig);
        assert!(m.matches(
            "x.com",
            120_000,
            "text/html; charset=utf-8",
            "same-prefix",
            128,
        ));
        assert!(!m.matches(
            "x.com",
            120_000,
            "text/html; charset=utf-8",
            "different-prefix",
            128,
        ));
    }

    /// Truly path-sensitive server — neither layer fits → None.
    #[test]
    fn detect_returns_none_when_neither_layer_fits() {
        let samples = vec![
            s(100, "text/html", "abc", 17),
            s(500, "text/html", "xyz", 33), // unrelated CL jump
            s(150, "text/html", "qrs", 65), // not on a line either
        ];
        assert!(detect(&samples, 10).is_none());
    }

    /// Layer 2 fingerprint at runtime: probe path_len → expected CL via
    /// formula → match within tolerance.
    #[test]
    fn matches_layer2_via_formula() {
        let mut m = WildcardMap::new();
        // Wildcard for x.com: CL = 3 × path_len + 200
        m.insert(
            "x.com".into(),
            WildcardSig {
                content_length: -1,
                content_type: "text/html".into(),
                snippet_md5: String::new(),
                k: Some(3),
                base: Some(200),
                tolerance: 10,
                normalized_snippet_md5: String::new(),
            },
        );
        // Probe at /foo (path_len=4) — expected CL = 12+200 = 212.
        assert!(m.matches("x.com", 212, "text/html", "any-md5", 4));
        assert!(m.matches("x.com", 220, "text/html", "any-md5", 4)); // within tol
        assert!(!m.matches("x.com", 230, "text/html", "any-md5", 4)); // out of tol
        assert!(!m.matches("x.com", 212, "application/json", "any-md5", 4));
        // Probe at /admin (path_len=6) — expected CL = 18+200 = 218.
        assert!(m.matches("x.com", 218, "text/html", "any-md5", 6));
    }

    /// REAL ENDPOINT against a Layer 2 fingerprint must NOT match.
    /// Sanity check the formula doesn't over-suppress small real responses.
    #[test]
    fn layer2_does_not_flag_real_endpoint() {
        let mut m = WildcardMap::new();
        m.insert(
            "x.com".into(),
            WildcardSig {
                content_length: -1,
                content_type: "text/html".into(),
                snippet_md5: String::new(),
                k: Some(3),
                base: Some(200),
                tolerance: 10,
                normalized_snippet_md5: String::new(),
            },
        );
        // Real /login.aspx returns 43-byte body. Path_len = 11.
        // Layer 2 expected = 3*11 + 200 = 233. Actual = 43. Diff = 190 ≫ 10.
        assert!(!m.matches("x.com", 43, "text/html", "real-md5", 11));
    }

    /// Layer 2 with K outside sane range [1, 20] → reject (probably noise).
    #[test]
    fn detect_layer2_rejects_insane_k() {
        let samples = vec![
            s(100, "text/html", "a", 10),
            s(100_000, "text/html", "b", 20), // K = 99,900/10 = 9990
            s(200_000, "text/html", "c", 30),
        ];
        assert!(detect(&samples, 10).is_none());
    }

    /// Layer 2 requires varying path_lens — all-same-length samples can't
    /// compute slope.
    #[test]
    fn detect_layer2_requires_varying_path_lens() {
        let samples = vec![
            s(100, "text/html", "a", 32),
            s(200, "text/html", "b", 32),
            s(300, "text/html", "c", 32),
        ];
        assert!(detect(&samples, 10).is_none());
    }

    // ── Layer 1b (v0.4.5) — same CT + CL, body varies ────────────────

    /// Content-aware Layer 1b: same CT, near-constant CL, bodies differ ONLY
    /// in a per-request nonce → normalized content agrees → detected, and the
    /// normalized hash is stored (not size-only).
    #[test]
    fn detect_layer1b_content_aware_nonce() {
        let body = |nonce: &str| {
            format!(
                "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1>\
                 <p>The requested resource was not found on this server.</p>\
                 <hr><p>request id {nonce}</p></body></html>"
            )
        };
        let samples = vec![
            sb(393, "text/html", "md5-A", 17, &body("0123456789abcdef0123456789abcdef")),
            sb(393, "text/html", "md5-B", 33, &body("fedcba9876543210fedcba9876543210")),
            sb(393, "text/html", "md5-C", 65, &body("aaaa1111bbbb2222cccc3333dddd4444")),
        ];
        let sig = detect(&samples, 10).expect("content-aware Layer 1b should fire");
        assert!(sig.k.is_none(), "not a Layer 2 match");
        assert!(sig.snippet_md5.is_empty(), "L1b stores empty exact-md5");
        assert!(!sig.normalized_snippet_md5.is_empty(), "L1b stores normalized hash");
        assert_eq!(sig.content_length, 393);
        assert_eq!(sig.content_type, "text/html");
    }

    /// Content-aware L1b tolerates small CL drift while bodies normalize equal.
    #[test]
    fn detect_layer1b_tolerates_cl_drift() {
        let body = |nonce: &str| {
            format!(
                "<html><body><h1>Forbidden</h1><p>access denied you do not have \
                 permission for this requested resource on this server</p>\
                 <p>trace {nonce}</p></body></html>"
            )
        };
        let samples = vec![
            sb(390, "text/html", "md5-A", 17, &body("0123456789abcdef")),
            sb(395, "text/html", "md5-B", 33, &body("fedcba9876543210")),
            sb(393, "text/html", "md5-C", 65, &body("abcdef0123456789")),
        ];
        let sig = detect(&samples, 10).expect("L1b should tolerate small CL drift");
        assert!(sig.snippet_md5.is_empty());
        assert!(!sig.normalized_snippet_md5.is_empty());
    }

    /// Content-aware L1b runtime: a probe whose body normalizes to the stored
    /// hash IS suppressed; a real same-size page with DIFFERENT content is NOT
    /// (the "no missing results" guarantee); wrong CT is NOT.
    #[test]
    fn matches_layer1b_content_aware_no_miss() {
        let body = |nonce: &str| {
            format!(
                "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1>\
                 <p>The requested resource was not found on this server.</p>\
                 <hr><p>request id {nonce}</p></body></html>"
            )
        };
        let samples = vec![
            sb(393, "text/html", "md5-A", 17, &body("0123456789abcdef0123456789abcdef")),
            sb(393, "text/html", "md5-B", 33, &body("fedcba9876543210fedcba9876543210")),
            sb(393, "text/html", "md5-C", 65, &body("aaaa1111bbbb2222cccc3333dddd4444")),
        ];
        let sig = detect(&samples, 10).expect("L1b sig");
        let mut m = WildcardMap::new();
        m.insert("x.com".into(), sig);
        // Same catchall template, brand-new nonce → suppressed.
        assert!(m.matches_body(
            "x.com", 393, "text/html", "z", 7,
            &body("99998888777766665555444433332222"),
        ));
        // Real same-size page, genuinely different content → NOT suppressed.
        assert!(!m.matches_body(
            "x.com", 393, "text/html", "z", 7,
            "<html><body><h1>Welcome admin</h1><p>secret internal dashboard here</p></body></html>",
        ));
        // Wrong CT → not suppressed.
        assert!(!m.matches_body(
            "x.com", 393, "application/json", "z", 7,
            &body("1111222233334444aaaabbbbccccdddd"),
        ));
    }

    /// Layer 1b must NOT fire when content types differ across samples.
    #[test]
    fn detect_layer1b_requires_same_ct() {
        let body = |n: &str| {
            format!("<html><body>error not found on this server request {n}</body></html>")
        };
        let samples = vec![
            sb(393, "text/html", "md5-A", 17, &body("0123456789abcdef")),
            sb(393, "application/json", "md5-B", 33, &body("fedcba9876543210")),
            sb(393, "text/html", "md5-C", 65, &body("abcdef0123456789")),
        ];
        assert!(detect(&samples, 10).is_none());
    }

    /// Layer 1 must beat Layer 1b: when md5 agrees, use L1 (stronger signal).
    #[test]
    fn detect_layer1_beats_layer1b() {
        let samples = vec![
            s(393, "text/html", "same-md5", 17),
            s(393, "text/html", "same-md5", 33),
            s(393, "text/html", "same-md5", 65),
        ];
        let sig = detect(&samples, 10).unwrap();
        assert_eq!(sig.snippet_md5, "same-md5", "L1 wins when md5 agrees");
    }

    /// Content-aware L1b must NOT fire when CL spread is too wide (>256):
    /// such size chaos should remain path-sensitive, not a wildcard.
    #[test]
    fn detect_catchall_rejects_wide_spread() {
        let body = |n: &str| {
            format!("<html><body>not found resource on this server request {n}</body></html>")
        };
        let samples = vec![
            sb(100, "text/html", "a", 17, &body("0123456789abcdef")),
            sb(500, "text/html", "b", 33, &body("fedcba9876543210")),
            sb(150, "text/html", "c", 65, &body("abcdef0123456789")),
        ];
        assert!(detect(&samples, 10).is_none());
    }

    /// Token-ratio guard: bodies whose NORMALIZED hashes collide (everything
    /// volatile blanked) but whose RAW token-sets are structurally different
    /// (<0.90 similarity) must NOT be treated as a wildcard.
    #[test]
    fn detect_catchall_rejects_structurally_different() {
        let samples = vec![
            sb(40, "text/html", "a", 17, "<x>0123456789abcdef0123456789abcdef</x>"),
            sb(40, "text/html", "b", 33, "<x>fedcba9876543210fedcba9876543210</x>"),
            sb(40, "text/html", "c", 65, "<x>aaaa1111bbbb2222cccc3333dddd4444</x>"),
        ];
        // Normalized hashes agree (hex blanked) but token ratio ≈0.5 → rejected;
        // constant CL also means Layer 2 can't fit → overall None.
        assert!(detect(&samples, 10).is_none());
    }
}
