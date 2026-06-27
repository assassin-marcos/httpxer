//! Native, conservative, content-confirmed 401/403 bypass (v0.4.5).
//!
//! When a probe hits `401`/`403` on a directory-shaped path, the fuzz worker
//! retries it with a small battery of well-known access-control bypass
//! techniques (path-override headers + path mutations). A retry is reported
//! ONLY when it returns 2xx/3xx, its (normalized) content DIFFERS from the
//! original block page, AND it doesn't match the host catchall — so we never
//! emit a fake-200. It is auto-on but conservative: a per-host path budget
//! bounds traffic, each path stops at the first confirmed bypass, and `--safe`
//! disables it entirely.
//!
//! This module holds the technique table + the per-host budget; the dispatch
//! loop lives in `fuzz.rs` so it reuses the impersonation pool via
//! `dispatch_one`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Max distinct 401/403 *paths* a single host may spend bypass attempts on.
/// Bounds traffic / WAF exposure on auth-heavy hosts (Codex's concern).
pub const PER_HOST_PATH_BUDGET: usize = 40;

static HOST_BUDGET: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

/// Charge one bypass-path attempt against `host`'s budget. Returns `false`
/// (skip bypass for this path) once the host has spent its budget.
pub fn charge_host(host: &str) -> bool {
    let m = HOST_BUDGET.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(), // a poisoned mutex still has a usable count
    };
    let n = g.entry(host.to_string()).or_insert(0);
    if *n >= PER_HOST_PATH_BUDGET {
        return false;
    }
    *n += 1;
    true
}

/// One bypass variant: a human label, extra request headers, and the request
/// path to send.
pub struct Variant {
    pub label: &'static str,
    pub headers: Vec<(String, String)>,
    pub path: String,
}

/// Curated, conservative bypass variants for a 401/403 at `path` (≤4 per path,
/// per Codex). Header-override techniques first (highest signal), then one
/// path-mutation. The caller dispatches them in order and stops at the first
/// content-confirmed success.
pub fn variants(path: &str) -> Vec<Variant> {
    let base = path.trim_end_matches('/');
    vec![
        Variant {
            label: "X-Original-URL",
            headers: vec![("X-Original-URL".into(), path.to_string())],
            path: path.to_string(),
        },
        Variant {
            label: "X-Rewrite-URL",
            headers: vec![("X-Rewrite-URL".into(), path.to_string())],
            path: path.to_string(),
        },
        Variant {
            label: "X-Forwarded-For",
            headers: vec![("X-Forwarded-For".into(), "127.0.0.1".into())],
            path: path.to_string(),
        },
        Variant {
            label: "path-semicolon",
            headers: vec![],
            path: format!("{}/..;/", base),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_capped_and_target_the_path() {
        let v = variants("/admin");
        assert!(v.len() <= 4, "≤4 attempts per path (traffic guard)");
        // header-override techniques carry the real path, not "/"
        assert!(v
            .iter()
            .any(|x| x.label == "X-Original-URL" && x.headers[0].1 == "/admin"));
    }

    #[test]
    fn per_host_budget_caps_attempts() {
        let host = "budget-test.example";
        let mut ok = 0;
        for _ in 0..(PER_HOST_PATH_BUDGET + 10) {
            if charge_host(host) {
                ok += 1;
            }
        }
        assert_eq!(ok, PER_HOST_PATH_BUDGET, "host budget must cap attempts");
    }
}
