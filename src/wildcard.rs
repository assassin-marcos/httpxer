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

use std::collections::HashMap;

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
        }
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

    // ── Layer 1: static catchall (allow CL tolerance for jitter). ─────
    let layer1_ok = samples.iter().all(|s| {
        (s.content_length - first.content_length).abs() <= tolerance
            && s.content_type == first.content_type
            && s.snippet_md5 == first.snippet_md5
    });
    if layer1_ok {
        return Some(WildcardSig {
            content_length: first.content_length,
            content_type: first.content_type.clone(),
            snippet_md5: first.snippet_md5.clone(),
            k: None,
            base: None,
            tolerance,
        });
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

    /// True if this probe matches the recorded wildcard signature for
    /// this host. Checks BOTH Layer 1 (static catchall) and Layer 2
    /// (path-echo linear formula). `probe_path_len` is the byte length
    /// of the URL path the probe was sent to (e.g. `/admin` → 6).
    pub fn matches(&self, host: &str, cl: i64, ct: &str, md5: &str, probe_path_len: usize) -> bool {
        let Some(sig) = self.inner.get(host) else { return false };
        let tol = sig.tolerance;
        // Layer 1 — static catchall match (CT + md5 exact, CL within tolerance).
        if sig.content_type == ct
            && sig.snippet_md5 == md5
            && (sig.content_length - cl).abs() <= tol
        {
            return true;
        }
        // Layer 2 — path-echo linear formula match. Only fires when
        // pre-flight detected a (k, base) relationship.
        if let (Some(k), Some(base)) = (sig.k, sig.base) {
            if sig.content_type == ct {
                let expected = k * probe_path_len as i64 + base;
                if (expected - cl).abs() <= tol {
                    return true;
                }
            }
        }
        false
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
        }
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
            s(251, "text/html", "md5-A", 17),  // 3*17 + 200 = 251
            s(299, "text/html", "md5-B", 33),  // 3*33 + 200 = 299
            s(395, "text/html", "md5-C", 65),  // 3*65 + 200 = 395
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
            s(250, "text/html", "md5-A", 17),  // expected 251, off by -1
            s(301, "text/html", "md5-B", 33),  // expected 299, off by +2
            s(394, "text/html", "md5-C", 65),  // expected 395, off by -1
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

    /// Truly path-sensitive server — neither layer fits → None.
    #[test]
    fn detect_returns_none_when_neither_layer_fits() {
        let samples = vec![
            s(100, "text/html", "abc", 17),
            s(500, "text/html", "xyz", 33),  // unrelated CL jump
            s(150, "text/html", "qrs", 65),  // not on a line either
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
            },
        );
        // Probe at /foo (path_len=4) — expected CL = 12+200 = 212.
        assert!(m.matches("x.com", 212, "text/html", "any-md5", 4));
        assert!(m.matches("x.com", 220, "text/html", "any-md5", 4));  // within tol
        assert!(!m.matches("x.com", 230, "text/html", "any-md5", 4)); // out of tol
        // Different CT → no match even if CL fits.
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
            s(100_000, "text/html", "b", 20),  // K = 99,900/10 = 9990
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
}
