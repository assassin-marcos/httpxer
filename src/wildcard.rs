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

/// Per-host wildcard fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WildcardSig {
    pub content_length: i64,
    pub content_type: String,
    pub snippet_md5: String,
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

    /// True if this `(content_length, content_type, snippet_md5)` matches the
    /// recorded wildcard signature for this host.
    pub fn matches(&self, host: &str, cl: i64, ct: &str, md5: &str) -> bool {
        match self.inner.get(host) {
            Some(sig) => {
                sig.content_length == cl && sig.content_type == ct && sig.snippet_md5 == md5
            }
            None => false,
        }
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
    #[test]
    fn map_keys_dont_collide_across_path_prefixes() {
        let mut m = WildcardMap::new();
        m.insert(
            "https://x.com/api".into(),
            WildcardSig {
                content_length: 100,
                content_type: "text/html".into(),
                snippet_md5: "aaa".into(),
            },
        );
        m.insert(
            "https://x.com/admin".into(),
            WildcardSig {
                content_length: 200,
                content_type: "text/html".into(),
                snippet_md5: "bbb".into(),
            },
        );
        assert_eq!(m.len(), 2, "different path-prefixes must stay distinct");
        assert!(m.matches("https://x.com/api", 100, "text/html", "aaa"));
        assert!(m.matches("https://x.com/admin", 200, "text/html", "bbb"));
        // No cross-contamination.
        assert!(!m.matches("https://x.com/api", 200, "text/html", "bbb"));
    }

    #[test]
    fn match_only_when_all_three_align() {
        let mut m = WildcardMap::new();
        m.insert(
            "x.com".into(),
            WildcardSig {
                content_length: 100,
                content_type: "text/html".into(),
                snippet_md5: "abc".into(),
            },
        );
        assert!(m.matches("x.com", 100, "text/html", "abc"));
        assert!(!m.matches("x.com", 100, "text/html", "xyz"));
        assert!(!m.matches("x.com", 100, "application/json", "abc"));
        assert!(!m.matches("x.com", 101, "text/html", "abc"));
        assert!(!m.matches("y.com", 100, "text/html", "abc"));
    }
}
