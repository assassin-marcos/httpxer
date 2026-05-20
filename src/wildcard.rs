//! Per-host wildcard detection.
//!
//! For each host, the fuzz orchestrator first probes `/<32 random hex chars>`.
//! If the response is 200/3xx with a body, record
//! `(content_length, content_type, snippet_md5)` and use it as a fingerprint —
//! any subsequent fuzz hit with the SAME triple is flagged `is_wildcard:true`.
//!
//! Verified by the kayak.com smoke test (2026-05-20):
//! - `rights.kayak.com` returns identical 555-byte CrowdRiff 404 HTML for
//!   every path — without this, ffuf flags `debug.log`, `error.log`,
//!   `errors.log`, `terraform.tfvars` as false positives.
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
