//! Wappalyzer-style tech detection using projectdiscovery/wappalyzergo
//! fingerprints (the exact dataset httpx uses, so output is parity-compatible).
//!
//! Pattern syntax (Wappalyzer convention):
//!   "Apache(?:/(\\d[\\d.]+))?(?:\\s|$)\\;version:\\1"
//!     │                                  │
//!     └─── regex ─────────────────────────┴── suffix: \;version:\N means
//!                                              "version = capture group N"
//!
//! We cover five server-observable vectors: headers, cookies, meta, HTML and
//! script source URLs. We deliberately skip `js` (needs a JS engine) and `dom`
//! (needs a real HTML parser); those vectors are minority hits and httpx
//! itself only runs them with a headless-browser config.

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;

/// Compiled pattern with an optional capture group whose match becomes the
/// detected version string. `re == None` means "presence detection" — used
/// for header/cookie/meta patterns with an empty regex part.
struct CompiledPattern {
    re: Option<Regex>,
    version_group: Option<usize>,
}

fn compile_pattern(raw: &str) -> Option<CompiledPattern> {
    // Split off `\;version:\N` / `\;confidence:N` suffixes.
    let mut parts = raw.splitn(2, "\\;");
    let regex_str = parts.next()?;
    let mut version_group: Option<usize> = None;
    if let Some(suffixes) = parts.next() {
        for p in suffixes.split("\\;") {
            let candidate = p
                .strip_prefix("version:\\")
                .or_else(|| p.strip_prefix("version:"));
            if let Some(s) = candidate {
                if let Ok(n) = s.parse::<usize>() {
                    version_group = Some(n);
                }
            }
        }
    }
    if regex_str.is_empty() {
        return Some(CompiledPattern {
            re: None,
            version_group,
        });
    }
    let re = regex::RegexBuilder::new(regex_str)
        .case_insensitive(true)
        .multi_line(true)
        .size_limit(10 * 1024 * 1024)
        .build()
        .ok()?;
    Some(CompiledPattern {
        re: Some(re),
        version_group,
    })
}

fn pattern_strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(arr) => arr
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => vec![],
    }
}

struct AppFingerprint {
    name: String,
    // (header_name_lowercase, pattern)
    headers: Vec<(String, CompiledPattern)>,
    // (cookie_name, pattern)  — case-sensitive cookies per Wappalyzer convention
    cookies: Vec<(String, CompiledPattern)>,
    // (meta_name_lowercase, pattern)
    meta: Vec<(String, CompiledPattern)>,
    html: Vec<CompiledPattern>,
    script_src: Vec<CompiledPattern>,
    implies: Vec<String>,
}

pub struct TechEngine {
    apps: Vec<AppFingerprint>,
    script_src_extract: Regex,
    meta_extract: Regex,
}

impl TechEngine {
    pub fn from_json(json_str: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(json_str).context("parse wappalyzer JSON")?;
        let apps_obj = v
            .get("apps")
            .and_then(|a| a.as_object())
            .context("missing 'apps' object in fingerprints JSON")?;

        let mut apps: Vec<AppFingerprint> = Vec::with_capacity(apps_obj.len());
        let mut skipped_patterns = 0usize;
        let mut detectable_apps = 0usize;
        let mut compiled_patterns = 0usize;

        for (name, def) in apps_obj {
            let mut fp = AppFingerprint {
                name: name.clone(),
                headers: vec![],
                cookies: vec![],
                meta: vec![],
                html: vec![],
                script_src: vec![],
                implies: vec![],
            };

            // headers / cookies / meta — all object {name: pattern}
            for (field, target) in [
                ("headers", PatternTarget::Headers),
                ("cookies", PatternTarget::Cookies),
                ("meta", PatternTarget::Meta),
            ] {
                if let Some(obj) = def.get(field).and_then(|x| x.as_object()) {
                    for (k, p) in obj {
                        // Wappalyzer headers/cookies/meta entries can be a
                        // single pattern OR an array of independent
                        // alternatives. Compile EACH array entry so the
                        // alternatives past [0] aren't silently dropped.
                        let raws: Vec<String> = match p {
                            Value::String(s) => vec![s.clone()],
                            Value::Array(arr) => arr
                                .iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect(),
                            _ => continue,
                        };
                        for raw in raws {
                            match compile_pattern(&raw) {
                                Some(c) => {
                                    let key = match target {
                                        PatternTarget::Cookies => k.clone(),
                                        _ => k.to_ascii_lowercase(),
                                    };
                                    match target {
                                        PatternTarget::Headers => {
                                            fp.headers.push((key, c))
                                        }
                                        PatternTarget::Cookies => {
                                            fp.cookies.push((key, c))
                                        }
                                        PatternTarget::Meta => fp.meta.push((key, c)),
                                    }
                                }
                                None => skipped_patterns += 1,
                            }
                        }
                    }
                }
            }

            // html / scriptSrc — string or array of strings
            if let Some(field) = def.get("html") {
                for s in pattern_strings(field) {
                    match compile_pattern(&s) {
                        Some(c) if c.re.is_some() => fp.html.push(c),
                        Some(_) => {} // skip empty html patterns — they'd match everything
                        None => skipped_patterns += 1,
                    }
                }
            }
            if let Some(field) = def.get("scriptSrc") {
                for s in pattern_strings(field) {
                    match compile_pattern(&s) {
                        Some(c) if c.re.is_some() => fp.script_src.push(c),
                        Some(_) => {}
                        None => skipped_patterns += 1,
                    }
                }
            }

            // implies — array of names (sometimes with `\;confidence:N` suffix)
            if let Some(field) = def.get("implies") {
                for s in pattern_strings(field) {
                    let n = s.split("\\;").next().unwrap_or(&s).to_string();
                    if !n.is_empty() {
                        fp.implies.push(n);
                    }
                }
            }

            let app_patterns = fp.headers.len()
                + fp.cookies.len()
                + fp.meta.len()
                + fp.html.len()
                + fp.script_src.len();
            if app_patterns > 0 {
                detectable_apps += 1;
                compiled_patterns += app_patterns;
            }
            apps.push(fp);
        }

        eprintln!(
            "[+] tech-detect: {} definitions; {} detectable apps; {} compiled patterns{}",
            apps.len(),
            detectable_apps,
            compiled_patterns,
            if skipped_patterns > 0 {
                format!(" ({} unsupported regex patterns skipped)", skipped_patterns)
            } else {
                String::new()
            }
        );

        Ok(Self {
            apps,
            script_src_extract: Regex::new(r#"(?i)<script[^>]+src\s*=\s*["']([^"']+)["']"#)
                .unwrap(),
            meta_extract: Regex::new(
                r#"(?i)<meta[^>]+name\s*=\s*["']([^"']+)["'][^>]*content\s*=\s*["']([^"']*)["']"#,
            )
            .unwrap(),
        })
    }

    fn extract_script_srcs(&self, body: &str) -> Vec<String> {
        self.script_src_extract
            .captures_iter(body)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect()
    }

    fn extract_meta_tags(&self, body: &str) -> Vec<(String, String)> {
        self.meta_extract
            .captures_iter(body)
            .filter_map(|c| {
                let n = c.get(1)?.as_str().to_ascii_lowercase();
                let v = c.get(2)?.as_str().to_string();
                Some((n, v))
            })
            .collect()
    }

    /// Run all fingerprints against the response. Returns (app_name, optional_version)
    /// pairs sorted by name. First-match-wins per app across the detection vectors —
    /// headers → cookies → scriptSrc → meta → html (cheapest to costliest).
    pub fn detect(
        &self,
        headers: &[(String, String)], // (lowercase header name, value)
        cookies: &[(String, String)], // (cookie name, value)
        body: &str,
    ) -> Vec<(String, Option<String>)> {
        let script_srcs = self.extract_script_srcs(body);
        let meta_tags = self.extract_meta_tags(body);

        let mut hits: HashMap<String, Option<String>> = HashMap::new();
        for app in &self.apps {
            let mut version: Option<String> = None;
            let mut matched = false;

            // 1. headers
            'h: for (hn, pat) in &app.headers {
                for (h, v) in headers {
                    if h != hn {
                        continue;
                    }
                    match &pat.re {
                        None => {
                            matched = true;
                            break 'h;
                        }
                        Some(re) => {
                            if let Some(caps) = re.captures(v) {
                                matched = true;
                                if let Some(g) = pat.version_group {
                                    version = caps.get(g).map(|m| m.as_str().to_string());
                                }
                                break 'h;
                            }
                        }
                    }
                }
            }

            // 2. cookies
            if !matched {
                'c: for (cn, pat) in &app.cookies {
                    for (k, v) in cookies {
                        if k != cn {
                            continue;
                        }
                        match &pat.re {
                            None => {
                                matched = true;
                                break 'c;
                            }
                            Some(re) => {
                                if let Some(caps) = re.captures(v) {
                                    matched = true;
                                    if let Some(g) = pat.version_group {
                                        version = caps.get(g).map(|m| m.as_str().to_string());
                                    }
                                    break 'c;
                                }
                            }
                        }
                    }
                }
            }

            // 3. scriptSrc
            if !matched {
                'src: for pat in &app.script_src {
                    let Some(re) = &pat.re else { continue };
                    for s in &script_srcs {
                        if let Some(caps) = re.captures(s) {
                            matched = true;
                            if let Some(g) = pat.version_group {
                                version = caps.get(g).map(|m| m.as_str().to_string());
                            }
                            break 'src;
                        }
                    }
                }
            }

            // 4. meta
            if !matched {
                'mt: for (mn, pat) in &app.meta {
                    match &pat.re {
                        None => {
                            if meta_tags.iter().any(|(n, _)| n == mn) {
                                matched = true;
                                break 'mt;
                            }
                        }
                        Some(re) => {
                            for (n, v) in &meta_tags {
                                if n != mn {
                                    continue;
                                }
                                if let Some(caps) = re.captures(v) {
                                    matched = true;
                                    if let Some(g) = pat.version_group {
                                        version = caps.get(g).map(|m| m.as_str().to_string());
                                    }
                                    break 'mt;
                                }
                            }
                        }
                    }
                }
            }

            // 5. html (costliest — full-body regex scan)
            if !matched {
                for pat in &app.html {
                    let Some(re) = &pat.re else { continue };
                    if let Some(caps) = re.captures(body) {
                        matched = true;
                        if let Some(g) = pat.version_group {
                            version = caps.get(g).map(|m| m.as_str().to_string());
                        }
                        break;
                    }
                }
            }

            if matched {
                hits.insert(app.name.clone(), version);
            }
        }

        // Resolve implies — shallow (no transitive). Implied techs carry no version.
        let to_add: Vec<String> = self
            .apps
            .iter()
            .filter(|a| hits.contains_key(&a.name))
            .flat_map(|a| a.implies.iter().cloned())
            .filter(|n| !hits.contains_key(n))
            .collect();
        for n in to_add {
            hits.entry(n).or_insert(None);
        }

        let mut out: Vec<(String, Option<String>)> = hits.into_iter().collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

#[derive(Copy, Clone)]
enum PatternTarget {
    Headers,
    Cookies,
    Meta,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: header patterns supplied as a JSON array used to drop
    /// every entry past `[0]`. Build a minimal fingerprint set with two
    /// array-form alternatives and confirm BOTH are compiled and matchable.
    #[test]
    fn array_form_header_patterns_compile_every_entry() {
        let json = r#"{
            "apps": {
                "DemoApp": {
                    "headers": {
                        "X-Demo": ["foo", "bar(?:/([\\d.]+))?\\;version:\\1"]
                    }
                }
            }
        }"#;
        let engine = TechEngine::from_json(json).expect("engine builds");

        // First alternative — bare `foo` matches.
        let hits_foo =
            engine.detect(&[("x-demo".into(), "foo".into())], &[], "");
        assert!(
            hits_foo.iter().any(|(n, _)| n == "DemoApp"),
            "expected DemoApp to match the FIRST array pattern"
        );

        // Second alternative — the version-capturing one was previously
        // dropped silently. It must now match AND extract the version.
        let hits_bar =
            engine.detect(&[("x-demo".into(), "bar/2.5".into())], &[], "");
        let bar_hit = hits_bar.iter().find(|(n, _)| n == "DemoApp");
        assert!(bar_hit.is_some(), "expected DemoApp to match the SECOND array pattern");
        assert_eq!(
            bar_hit.unwrap().1.as_deref(),
            Some("2.5"),
            "version capture from the second array pattern was lost"
        );
    }
}

/// Render matches as httpx-compatible `"Name:Version, Name, Name:Version"`.
pub fn render_tech(matches: &[(String, Option<String>)]) -> String {
    matches
        .iter()
        .map(|(name, ver)| match ver {
            Some(v) if !v.is_empty() => format!("{}:{}", name, v),
            _ => name.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}
