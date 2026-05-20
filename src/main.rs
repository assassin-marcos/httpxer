//! httpxer — native HTTP-enrichment replacement for ProjectDiscovery's
//! httpx. Reads a hostname-per-line list, probes each via HTTP(S), emits
//! NDJSON matching httpx's JSON shape with Wappalyzer-grade tech-detect
//! and live CDN tagging.
//!
//! Architecture:
//!   stdin/file -> dedupe -> (parallel) DNS A+CNAME, CDN fetch -> probe
//!     (Semaphore-gated, spawn_blocking) -> tech-detect -> NDJSON stream
//!
//! Output schema mirrors the user's existing format:
//!   subdomain, domain, scan_id, source_tools, ip, cname, cdn,
//!   status_code, content_length, word_count, server, location, title,
//!   final_url, redirect_chain, tech, error
//!
//! The probe stack (probe.rs) is a port of portwave's Pass-C: rotating
//! browser UAs, permissive TLS, 2 MiB streamed body cap, retry-once +
//! scheme-flip wrapper. Identical reliability characteristics.

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;

mod cdn;
mod dns;
mod fuzz;
mod probe;
mod techdetect;
mod update;
mod wildcard;

/// Embedded Wappalyzer fingerprint snapshot — same JSON httpx uses. Refresh
/// with `--fingerprints <path>` pointing at a freshly-downloaded copy from
/// https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/main/fingerprints_data.json
const EMBEDDED_FINGERPRINTS: &str = include_str!("../fingerprints.json");

#[derive(Parser, Debug)]
#[command(
    name = "httpxer",
    version,
    about = "Native httpx-enrichment replacement — status/title/server/CL/redirect/CDN/Wappalyzer."
)]
struct Args {
    /// Input file (one hostname/URL per line, "-" for stdin)
    #[arg(short = 'l', long, alias = "list",
          required_unless_present_any = ["update", "check_update", "uninstall"])]
    input: Option<String>,

    /// Output NDJSON file
    #[arg(short = 'o', long, alias = "output",
          required_unless_present_any = ["update", "check_update", "uninstall"])]
    output: Option<String>,

    /// Concurrent HTTP probes (matches httpx -t default)
    #[arg(short = 't', long, default_value_t = 250)]
    threads: usize,

    /// Per-probe HTTP timeout (ms)
    #[arg(long, default_value_t = 5000)]
    timeout_ms: u64,

    /// Don't follow redirects (default: follow up to --max-redirects hops, matches httpx -fr)
    #[arg(long)]
    no_follow_redirects: bool,

    /// Maximum redirect hops to follow when redirect-following is on.
    /// Matches httpx's `-mr` default of 10. Multi-hop SSO flows
    /// (corporate-managed Google → Okta SAML, etc.) commonly need 4-6 hops
    /// before the final auth page resolves — the previous default of 3 was
    /// stopping at the IdP-handoff page and missing the destination tech
    /// stack (e.g. `Okta:x.y.z`, `Nginx` on okta.com).
    #[arg(long, default_value_t = 10)]
    max_redirects: usize,

    /// Concurrent DNS lookups
    #[arg(long, default_value_t = 100)]
    dns_concurrency: usize,

    /// DNS timeout per lookup (seconds)
    #[arg(long, default_value_t = 3)]
    dns_timeout: u64,

    /// Embed in every output record under "domain"
    #[arg(long)]
    domain: Option<String>,

    /// Embed in every output record under "scan_id"
    #[arg(long)]
    scan_id: Option<String>,

    /// Embed in every output record under "source_tools" (e.g. "subfinder,amass")
    #[arg(long)]
    source_tools: Option<String>,

    /// Skip CDN range fetching (cdn field will always be empty)
    #[arg(long)]
    no_cdn: bool,

    /// Skip Wappalyzer tech-detect (faster + smaller output; tech field will be empty)
    #[arg(long)]
    no_tech: bool,

    /// Load fingerprints from this path instead of the embedded snapshot
    #[arg(long)]
    fingerprints: Option<String>,

    /// Don't resume — overwrite output file (default: skip hosts already in output)
    #[arg(long)]
    no_resume: bool,

    /// Disable browser TLS impersonation (use a plain wreq client). WAFs will
    /// see a non-Chrome JA4 fingerprint, which is fine on un-fronted targets
    /// and a few % faster on cold-start. Default: impersonate Chrome/Firefox/
    /// Safari/Edge with a random profile per probe.
    #[arg(long)]
    no_impersonate: bool,

    /// Include response body (capped at 2 MiB) in each output record under
    /// the `body` field. Useful for debugging fingerprint-echo endpoints
    /// (tls.peet.ws, ja3er.com) or archiving raw HTML. Off by default —
    /// keeps output files small.
    #[arg(long)]
    with_body: bool,

    // ── Fuzz-mode flags (v0.3.0+) ──────────────────────────────────────
    // Presence of `-path / --paths` switches the binary from enrich mode
    // (1 probe per host) into fuzz mode (host × wordlist Cartesian probe).
    // All flags below are inert in enrich mode.
    /// Wordlist file (one path per line) — when set, switches to fuzz mode
    /// (host × path probe). Empty paths and `#` comments are skipped.
    #[arg(
        short = 'p',
        long = "paths",
        alias = "path",
        help_heading = "Fuzz mode"
    )]
    paths: Option<String>,

    /// (fuzz) Comma-separated status codes to emit
    #[arg(
        long = "match-codes",
        alias = "mc",
        default_value = "200,301,302,307,308,401,403",
        help_heading = "Fuzz mode"
    )]
    match_codes: String,

    /// (fuzz) Body preview length in bytes (HTML-entity-encoded in output)
    #[arg(
        long = "body-preview",
        default_value_t = 8192,
        help_heading = "Fuzz mode"
    )]
    body_preview: usize,

    /// (fuzz) Wildcard suppression policy: strict|mark|off
    #[arg(
        long = "wildcard-policy",
        default_value = "strict",
        help_heading = "Fuzz mode"
    )]
    wildcard_policy: String,

    /// (fuzz) Shortcut for `--wildcard-policy off`
    #[arg(long = "no-wildcard", help_heading = "Fuzz mode")]
    no_wildcard: bool,

    /// (fuzz) Per-host requests/sec ceiling. 0 = disabled (default).
    #[arg(long = "rate-limit", default_value_t = 0.0, help_heading = "Fuzz mode")]
    rate_limit: f64,

    /// (fuzz) Retry count on network error
    #[arg(long = "retries", default_value_t = 1, help_heading = "Fuzz mode")]
    retries: u32,

    /// (fuzz) Emit status_code=0 records (connection errors). Off by default.
    #[arg(long = "include-errors", help_heading = "Fuzz mode")]
    include_errors: bool,

    /// (fuzz) HTTP or SOCKS5 proxy URL. Currently a no-op pending pool-
    /// builder support; reserved for the v0.3.x point release that adds
    /// per-pool proxy wiring. Setting it flips `via_proxy:true` in output.
    #[arg(long = "proxy", help_heading = "Fuzz mode")]
    proxy: Option<String>,

    // ── Self-management ────────────────────────────────────────────────
    /// Install the latest release (replaces this binary in place)
    #[arg(short = 'u', long, help_heading = "Self-management")]
    update: bool,

    /// Check for updates and exit (no install)
    #[arg(short = 'c', long, help_heading = "Self-management")]
    check_update: bool,

    /// Uninstall httpxer (deletes this binary + the version-check cache)
    #[arg(short = 'X', long, help_heading = "Self-management")]
    uninstall: bool,

    /// Skip the uninstall confirmation prompt
    #[arg(short = 'y', long, help_heading = "Self-management")]
    yes: bool,

    /// Suppress the "update available" startup banner
    #[arg(long, help_heading = "Self-management")]
    no_update_check: bool,

    /// Quiet mode (alias for --no-update-check + --no-art — useful when piping)
    #[arg(short = 'q', long, help_heading = "Self-management")]
    quiet: bool,

    /// Suppress the ASCII-art startup banner (banner is always skipped when
    /// stderr is not a TTY, so piped output is never polluted regardless)
    #[arg(long, help_heading = "Self-management")]
    no_art: bool,

    // ── httpx compatibility no-ops ───────────────────────────────────────
    // These flags are accepted with the same single-dash spelling httpx uses
    // (e.g. `-sc`, `-fr`, `-no-color`) so the existing retrohack invocation
    // doesn't need rewriting. All the features they toggle on in httpx are
    // ALREADY on in httpxer (we always emit status_code, content_length,
    // word_count, server, location, title, tech, ip, cname in JSON). The
    // fields below are intentionally unused.
    /// httpx compat (no-op — redirects are followed by default; pass --no-follow-redirects to disable)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    fr: bool,
    /// httpx compat (no-op — status_code is always in the JSON output)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    sc: bool,
    /// httpx compat (no-op — content_length is always in the JSON output)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    cl: bool,
    /// httpx compat (no-op — word_count is always in the JSON output)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    wc: bool,
    /// httpx compat (no-op — server header is always in the JSON output)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    server: bool,
    /// httpx compat (no-op — Location header is always in the JSON output)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    location: bool,
    /// httpx compat (no-op — <title> is always in the JSON output)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    title: bool,
    /// httpx compat (no-op — Wappalyzer tech-detect is always on; use --no-tech to disable)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    td: bool,
    /// httpx compat (no-op — ip is always in the JSON output)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    ip: bool,
    /// httpx compat (no-op — cname is always in the JSON output)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    cname: bool,
    /// httpx compat (no-op — output is always NDJSON, one record per line)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    json: bool,
    /// httpx compat (no-op — stderr is already plain text, no ANSI)
    #[arg(long = "no-color", help_heading = "httpx compatibility (no-ops)")]
    no_color: bool,
    /// httpx compat (no-op — httpxer doesn't print per-record stderr noise)
    #[arg(long, help_heading = "httpx compatibility (no-ops)")]
    silent: bool,
}

/// Convert Go-style single-dash long flags (`-fr`, `-sc`, `-no-color`) into
/// clap's double-dash form (`--fr`, `--sc`, `--no-color`) so the user can
/// paste their existing httpx invocation verbatim. Single-char short flags
/// (`-l`, `-o`, `-t`) and negative numbers are left untouched. argv[0]
/// (the binary path) is always passed through unchanged.
fn normalize_args<I: IntoIterator<Item = String>>(args: I) -> Vec<String> {
    args.into_iter()
        .enumerate()
        .map(|(i, a)| {
            if i == 0 {
                return a;
            }
            let bytes = a.as_bytes();
            // Match: starts with single `-`, has ≥3 chars total, first char
            // after the dash is alpha (rules out `-3.5`-style negatives),
            // and the rest is identifier-ish.
            if bytes.len() >= 3
                && bytes[0] == b'-'
                && bytes[1] != b'-'
                && bytes[1].is_ascii_alphabetic()
                && a[1..]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                format!("-{}", a)
            } else {
                a
            }
        })
        .collect()
}

#[derive(Serialize)]
struct EnrichRecord {
    subdomain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_tools: Option<String>,

    /// First resolved A/AAAA. Empty string when DNS failed.
    ip: String,
    /// First CNAME under `subdomain`, or "" when host is directly A.
    cname: String,
    /// CDN provider tag (cloudflare/cloudfront/fastly/google), or "" if none / unknown.
    cdn: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    word_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    final_url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    redirect_chain: Vec<String>,

    /// Wappalyzer detection joined as `"Name:Version, Name, Name:Version"`.
    /// Empty string when --no-tech or zero matches.
    tech: String,

    /// Raw response body, ≤2 MiB. Only present when --with-body is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,

    /// Reason this record didn't enrich (dns / http). Absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn read_hosts(path: &str) -> Result<Vec<String>> {
    let mut lines: Vec<String> = Vec::new();
    let push = |lines: &mut Vec<String>, l: String| {
        let l = l.trim().to_string();
        if !l.is_empty() && !l.starts_with('#') {
            lines.push(l);
        }
    };
    if path == "-" {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines().map_while(Result::ok) {
            push(&mut lines, line);
        }
    } else {
        let f = std::fs::File::open(path).with_context(|| format!("open {}", path))?;
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            push(&mut lines, line);
        }
    }
    let mut seen = HashSet::new();
    lines.retain(|h| seen.insert(h.clone()));
    Ok(lines)
}

fn read_existing_subdomains(path: &str) -> HashSet<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    let mut out = HashSet::new();
    for line in content.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(s) = v.get("subdomain").and_then(|s| s.as_str()) {
                out.insert(s.to_string());
            }
        }
    }
    out
}

/// Strip scheme + path so `https://foo.com/bar` becomes `foo.com`.
fn extract_host(input: &str) -> String {
    let s = input
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host_end = s.find('/').unwrap_or(s.len());
    s[..host_end].to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse_from(normalize_args(std::env::args()));

    // Self-management early-exits — handle before we touch input files / DNS / network.
    if args.update {
        return update::run_update().await;
    }
    if args.check_update {
        return update::run_check_update().await;
    }
    if args.uninstall {
        return update::run_uninstall(args.yes);
    }

    // Refresh the update-check cache BEFORE the banner renders, so the
    // inline (outdated)/(latest) tag reflects the current GitHub state
    // rather than a value from hours ago. 120 s skip-window means the
    // common case is zero network here.
    if !args.no_update_check && !args.quiet {
        update::refresh_update_cache_best_effort().await;
    }

    // ASCII-art startup banner (TTY-only, opt-out via --no-art / --quiet).
    let show_art = !args.quiet && !args.no_art && update::stderr_is_tty();
    if show_art {
        update::print_banner();
    }

    // Yellow "[!] update available" stderr alert with What's-new notes —
    // shown in addition to the banner's inline (outdated) tag because
    // (a) the inline tag is muted/easy to miss and (b) users who piped
    // through `tee` or scrollback need the notes to know what changed.
    if !args.no_update_check && !args.quiet {
        if let Some(latest) = update::cached_latest_version() {
            if update::version_is_newer(&latest, env!("CARGO_PKG_VERSION")) {
                let notes = tokio::task::spawn_blocking({
                    let cur = env!("CARGO_PKG_VERSION").to_string();
                    move || update::fetch_release_notes_since(&cur)
                })
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default();
                update::print_update_banner(&latest, &notes);
            }
        }
    }

    let input_path = args
        .input
        .as_deref()
        .context("missing -l/--list input file")?;
    let output_path = args.output.as_deref().context("missing -o/--output path")?;

    // 1. Read + dedupe input.
    let mut hosts = read_hosts(input_path)?;
    let initial = hosts.len();
    eprintln!("[+] input: {} unique hosts", initial);

    // 2a. FUZZ MODE — triggered by `-path / --paths <wordlist>`.
    //     Bypasses enrich-mode's DNS/CDN/tech-detect path entirely and
    //     issues a host × path Cartesian probe through the same wreq
    //     pool, with per-request `redirect::Policy::none()` so 3xx is a
    //     finding (not chased). Output schema matches retroh4ck-prober
    //     v0.1.0 — see `src/fuzz.rs` for the FuzzRecord layout.
    if let Some(paths_path) = args.paths.as_deref() {
        let words = fuzz::read_words(paths_path)?;
        eprintln!("[+] wordlist: {} unique paths", words.len());

        // Build wildcard policy from flags. `--no-wildcard` overrides.
        let policy = fuzz::WildcardPolicy::from_cli(&args.wildcard_policy, args.no_wildcard)?;

        // Build the impersonation pool once — fuzz uses the same pool
        // enrich does, so the init logic is identical.
        probe::init_pool(args.timeout_ms, args.no_impersonate);
        if !args.no_impersonate {
            eprintln!("[+] TLS impersonation: rotating real-browser JA3/JA4 + HTTP/2 fingerprints");
        } else {
            eprintln!("[+] TLS impersonation: DISABLED (--no-impersonate)");
        }

        let match_codes: Vec<u16> = args
            .match_codes
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect();
        if match_codes.is_empty() {
            anyhow::bail!(
                "--match-codes parsed to zero codes (got '{}')",
                args.match_codes
            );
        }

        let cfg = fuzz::FuzzCfg {
            match_codes,
            body_preview_bytes: args.body_preview,
            wildcard_policy: policy,
            include_errors: args.include_errors,
            retries: args.retries,
            via_proxy: args.proxy.is_some(),
            threads: args.threads,
            timeout_ms: args.timeout_ms,
            rate_limit_rps: args.rate_limit,
        };

        fuzz::run(&hosts, &words, cfg, output_path, args.no_resume, policy).await?;
        return Ok(());
    }

    // 2. Resume: skip already-processed entries from the existing output file.
    if !args.no_resume {
        let done = read_existing_subdomains(output_path);
        if !done.is_empty() {
            hosts.retain(|h| !done.contains(&extract_host(h)));
            eprintln!(
                "[+] resume: {} already processed, {} remaining",
                initial - hosts.len(),
                hosts.len()
            );
        }
    } else {
        let _ = std::fs::remove_file(output_path);
    }
    if hosts.is_empty() {
        eprintln!("[+] nothing to do — exiting");
        return Ok(());
    }

    // 3. Load tech-detect engine (or not).
    let tech_engine: Option<techdetect::TechEngine> = if args.no_tech {
        None
    } else {
        let json = match args.fingerprints.as_deref() {
            Some(p) => std::fs::read_to_string(p).with_context(|| format!("read {}", p))?,
            None => EMBEDDED_FINGERPRINTS.to_string(),
        };
        Some(techdetect::TechEngine::from_json(&json).context("load fingerprints")?)
    };

    // 4. Kick off CDN fetch in the background while DNS resolves.
    let cdn_fut = cdn::load_cdn_table(args.no_cdn);

    // 5. DNS resolve everything (A+AAAA+CNAME).
    let resolver = dns::build_resolver(args.dns_timeout);
    let host_strings: Vec<String> = hosts.iter().map(|h| extract_host(h)).collect();
    eprintln!(
        "[+] resolving {} hosts ({} concurrent)…",
        host_strings.len(),
        args.dns_concurrency
    );
    let dns_results = dns::resolve_many(resolver, host_strings, args.dns_concurrency).await;

    let cdn_table = cdn_fut.await;
    eprintln!("[+] CDN table: {} ranges", cdn_table.len());

    let dns_map: std::collections::HashMap<String, dns::DnsRecord> = dns_results
        .into_iter()
        .map(|r| (r.host.clone(), r))
        .collect();

    // 6. Init the impersonation client pool (one pre-built wreq::Client per
    //    Chrome/Firefox/Safari/Edge emulation profile). Each probe later
    //    picks a slot at random so the WAF sees a different real-browser
    //    JA4 fingerprint per request.
    probe::init_pool(args.timeout_ms, args.no_impersonate);
    if !args.no_impersonate {
        eprintln!("[+] TLS impersonation: rotating real-browser JA3/JA4 + HTTP/2 fingerprints");
    } else {
        eprintln!("[+] TLS impersonation: DISABLED (--no-impersonate)");
    }
    let follow = !args.no_follow_redirects;
    let max_redirects = args.max_redirects;

    // 7. Append-open output (resume-safe).
    let mut out_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(output_path)
        .with_context(|| format!("open output {}", output_path))?;

    // 8. Fan out probes via Semaphore + FuturesUnordered + spawn_blocking.
    use futures::stream::{FuturesUnordered, StreamExt};
    use tokio::sync::Semaphore;
    let sem = Arc::new(Semaphore::new(args.threads.max(1)));
    let cdn_table = Arc::new(cdn_table);
    let tech_engine = Arc::new(tech_engine);
    let domain_arc = Arc::new(args.domain.clone());
    let scan_id_arc = Arc::new(args.scan_id.clone());
    let source_tools_arc = Arc::new(args.source_tools.clone());
    let with_body = args.with_body;

    eprintln!(
        "[+] probing {} hosts ({} concurrent)…",
        hosts.len(),
        args.threads
    );

    let mut set: FuturesUnordered<tokio::task::JoinHandle<EnrichRecord>> = FuturesUnordered::new();
    let total = hosts.len();

    for input in hosts {
        let host = extract_host(&input);
        let dns_rec = dns_map.get(&host).cloned();
        let cdn_table = cdn_table.clone();
        let tech_engine = tech_engine.clone();
        let domain = domain_arc.clone();
        let scan_id = scan_id_arc.clone();
        let source_tools = source_tools_arc.clone();
        let sem = sem.clone();
        let url_or_host = input.clone();

        set.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.ok();

            let ip = dns_rec
                .as_ref()
                .and_then(|r| r.ips.first().map(|i| i.to_string()))
                .unwrap_or_default();
            let cname = dns_rec
                .as_ref()
                .and_then(|r| r.cname.clone())
                .unwrap_or_default();
            let cdn = dns_rec
                .as_ref()
                .and_then(|r| r.ips.first().copied())
                .and_then(|ip| cdn_table.lookup(ip).map(String::from))
                .unwrap_or_default();
            let dns_error = dns_rec.as_ref().and_then(|r| r.error.clone());

            let mut rec = EnrichRecord {
                subdomain: host.clone(),
                domain: (*domain).clone(),
                scan_id: (*scan_id).clone(),
                source_tools: (*source_tools).clone(),
                ip,
                cname,
                cdn,
                status_code: None,
                content_length: None,
                word_count: None,
                server: None,
                location: None,
                title: None,
                final_url: None,
                redirect_chain: vec![],
                tech: String::new(),
                body: None,
                error: None,
            };

            // No A/AAAA → record DNS failure, skip probe.
            if dns_rec.as_ref().map(|r| r.ips.is_empty()).unwrap_or(true) {
                rec.error = Some(dns_error.unwrap_or_else(|| "dns: no records".into()));
                return rec;
            }

            // wreq is async-only — no spawn_blocking. Just await directly.
            let probe_res =
                if url_or_host.starts_with("http://") || url_or_host.starts_with("https://") {
                    probe::http_probe_with_retry(&url_or_host, follow, max_redirects).await
                } else {
                    probe::probe_hostname(&url_or_host, follow, max_redirects).await
                };

            match probe_res {
                None => rec.error = Some("http: no response".into()),
                Some(r) => {
                    rec.status_code = Some(r.status_code);
                    rec.content_length = r.content_length;
                    rec.word_count = Some(r.word_count);
                    rec.server = r.server;
                    rec.location = r.location;
                    rec.title = r.title;
                    rec.final_url = r.final_url;
                    rec.redirect_chain = r.chain;
                    if let Some(engine) = tech_engine.as_ref() {
                        let matches = engine.detect(&r.headers, &r.cookies, &r.body);
                        rec.tech = techdetect::render_tech(&matches);
                    }
                    if with_body {
                        rec.body = Some(r.body);
                    }
                }
            }
            rec
        }));
    }

    // 9. Drain — write NDJSON as each completes (crash-safe, no buffered tail).
    let mut completed = 0usize;
    while let Some(joined) = set.next().await {
        if let Ok(rec) = joined {
            writeln!(out_file, "{}", serde_json::to_string(&rec)?)?;
            completed += 1;
            if completed % 50 == 0 || completed == total {
                eprintln!("  [{}/{}]", completed, total);
            }
        }
    }
    out_file.flush()?;
    eprintln!("[+] done: wrote {} records to {}", completed, output_path);
    Ok(())
}
