//! Auth / custom-header support for fuzz + crawl modes.
//!
//! Three knobs the user can drive:
//!   - `-H / --header "Name: Value"` — repeatable static header
//!   - `--bearer TOKEN` — shortcut for `Authorization: Bearer TOKEN`
//!   - `--cookie "Name=Value"` — repeatable; all pairs are joined into ONE
//!     fixed `Cookie:` header replayed verbatim on every request.
//!
//! There is no cookie jar. The wreq clients in `probe::init_pool` are built
//! WITHOUT `.cookie_store(true)`, so a `Set-Cookie` in a response is never
//! ingested and never sent back on a later request. `--cookie` is therefore a
//! static credential replay, not a session: if the target hands out a session
//! cookie mid-scan, subsequent probes will NOT carry it.
//!
//! The parsed headers/cookies are stored once on the `AuthCtx` and applied
//! at request-build time inside `dispatch_one`. Validation happens at CLI
//! parse so a typo fails loudly at startup before the scan begins.

use anyhow::{bail, Result};
use wreq::header::{HeaderMap, HeaderName, HeaderValue};

/// Parsed auth context — built once at startup, shared across probes via
/// `Arc<AuthCtx>`. Owns its `HeaderMap` so the per-probe attach is a clone
/// of pre-validated values (no re-parse cost per request).
#[derive(Debug, Default, Clone)]
pub struct AuthCtx {
    /// Pre-validated headers ready to splat onto every request.
    pub headers: HeaderMap,
    /// Cookie pairs from `--cookie`. Joined into a single `Cookie:` header
    /// (see `initial_cookie_header`) and sent unchanged on every request —
    /// no jar, no per-domain matching, no `Set-Cookie` ingestion.
    pub initial_cookies: Vec<(String, String)>,
}

impl AuthCtx {
    /// Build from CLI inputs.
    /// `headers` = each entry is `"Name: Value"`.
    /// `bearer` = optional token → becomes `Authorization: Bearer TOKEN`.
    /// `cookies` = each entry is `"Name=Value"`.
    pub fn from_cli(
        headers: &[String],
        bearer: Option<&str>,
        cookies: &[String],
    ) -> Result<Self> {
        let mut map = HeaderMap::new();

        // Custom -H headers — validate name + value at parse time.
        for raw in headers {
            let (name, value) = split_header(raw)?;
            let hn = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| anyhow::anyhow!("invalid header name '{}': {}", name, e))?;
            let hv = HeaderValue::from_str(&value)
                .map_err(|e| anyhow::anyhow!("invalid header value for '{}': {}", name, e))?;
            map.insert(hn, hv);
        }

        // --bearer shortcut.
        if let Some(tok) = bearer {
            let tok = tok.trim();
            if tok.is_empty() {
                bail!("--bearer token must not be empty");
            }
            let hv = HeaderValue::from_str(&format!("Bearer {}", tok))
                .map_err(|e| anyhow::anyhow!("invalid bearer token: {}", e))?;
            map.insert(wreq::header::AUTHORIZATION, hv);
        }

        // --cookie entries — split on first '=' so values containing '='
        // survive intact.
        let mut initial_cookies: Vec<(String, String)> = Vec::with_capacity(cookies.len());
        for raw in cookies {
            let (name, value) = split_cookie(raw)?;
            initial_cookies.push((name, value));
        }

        Ok(Self {
            headers: map,
            initial_cookies,
        })
    }

    /// True iff anything was actually configured. Lets the orchestrator
    /// skip the cookie-jar setup cost on plain anonymous scans.
    pub fn is_active(&self) -> bool {
        !self.headers.is_empty() || !self.initial_cookies.is_empty()
    }

    /// Render initial cookies as a single `Cookie:` header value (the
    /// classic `name1=val1; name2=val2` join). Used to seed the jar on
    /// the first request — wreq picks up the values into the store once
    /// the request lands.
    pub fn initial_cookie_header(&self) -> Option<String> {
        if self.initial_cookies.is_empty() {
            return None;
        }
        Some(
            self.initial_cookies
                .iter()
                .map(|(n, v)| format!("{}={}", n, v))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

fn split_header(raw: &str) -> Result<(String, String)> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("header '{}' missing ':' separator", raw))?;
    let name = name.trim().to_string();
    let value = value.trim().to_string();
    if name.is_empty() {
        bail!("header name in '{}' is empty", raw);
    }
    Ok((name, value))
}

fn split_cookie(raw: &str) -> Result<(String, String)> {
    let (name, value) = raw
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("cookie '{}' missing '=' separator", raw))?;
    let name = name.trim().to_string();
    let value = value.trim().to_string();
    if name.is_empty() {
        bail!("cookie name in '{}' is empty", raw);
    }
    Ok((name, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_parse_basic() {
        let ctx = AuthCtx::from_cli(
            &["X-Custom: hello world".to_string(), "X-Api-Key: abc".to_string()],
            None,
            &[],
        )
        .unwrap();
        assert!(ctx.is_active());
        assert_eq!(ctx.headers.get("X-Custom").unwrap(), "hello world");
        assert_eq!(ctx.headers.get("X-Api-Key").unwrap(), "abc");
    }

    #[test]
    fn header_with_trailing_whitespace_trimmed() {
        let ctx = AuthCtx::from_cli(
            &["  X-Forwarded-For  :   127.0.0.1  ".to_string()],
            None,
            &[],
        )
        .unwrap();
        assert_eq!(ctx.headers.get("X-Forwarded-For").unwrap(), "127.0.0.1");
    }

    #[test]
    fn header_missing_colon_fails() {
        let err = AuthCtx::from_cli(&["bogus_header_no_colon".to_string()], None, &[]).unwrap_err();
        assert!(err.to_string().contains("missing ':'"));
    }

    #[test]
    fn bearer_token_becomes_authorization_header() {
        let ctx = AuthCtx::from_cli(&[], Some("eyJhbGciOiJIUzI1NiJ9.xyz"), &[]).unwrap();
        assert_eq!(
            ctx.headers.get(wreq::header::AUTHORIZATION).unwrap(),
            "Bearer eyJhbGciOiJIUzI1NiJ9.xyz"
        );
    }

    #[test]
    fn bearer_empty_fails() {
        assert!(AuthCtx::from_cli(&[], Some("   "), &[]).is_err());
    }

    #[test]
    fn cookies_parsed_and_joined() {
        let ctx = AuthCtx::from_cli(
            &[],
            None,
            &["sid=abc123".to_string(), "csrf=tokenXYZ".to_string()],
        )
        .unwrap();
        assert_eq!(ctx.initial_cookies.len(), 2);
        assert_eq!(
            ctx.initial_cookie_header().unwrap(),
            "sid=abc123; csrf=tokenXYZ"
        );
    }

    #[test]
    fn cookie_value_with_equals_preserved() {
        // base64 / JWT cookies often contain '=' padding — split_once('=')
        // must keep the value side intact.
        let ctx = AuthCtx::from_cli(
            &[],
            None,
            &["token=eyJ.AAA=BBB=".to_string()],
        )
        .unwrap();
        assert_eq!(ctx.initial_cookies[0].1, "eyJ.AAA=BBB=");
    }

    #[test]
    fn empty_inputs_inactive() {
        let ctx = AuthCtx::from_cli(&[], None, &[]).unwrap();
        assert!(!ctx.is_active());
        assert!(ctx.initial_cookie_header().is_none());
    }
}
