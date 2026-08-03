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
use clap::{CommandFactory, Parser};
use serde::Serialize;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;

mod auth;
mod backup_fuzz;
mod bypass;
mod cdn;
mod crawl;
mod dns;
mod fuzz;
mod probe;
mod recurse;
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
    about = "Fast HTTP probing, technology detection, and smart path fuzzing.",
    long_about = r#"Fast HTTP probing, technology detection, and smart path fuzzing.

MODE
  No -w    Probe hosts: status, title, headers, technology, IP, and CDN
  With -w  Fuzz paths: wildcard filtering, backup checks, recursion, and crawl"#,
    after_help = r#"QUICK EXAMPLES
  [PROBE]    httpxer -u https://example.com
  [LIVE]     httpxer -l hosts.txt --live-only -o live.txt
  [URLS]     httpxer -l hosts.txt --urls-only -o live-urls.txt
  [TECH]     httpxer -u https://example.com --tech default
  [HEADERS]  httpxer -u https://example.com --rh
  [FUZZ]     httpxer -u https://example.com -w common.txt -o hits.txt
  [DEEP]     httpxer -u https://example.com -w common.txt --deep 3
  [AUTH]     httpxer -u https://example.com --bearer "$TOKEN"
  [PROXY]    httpxer -u https://example.com --proxy proxies.txt
  [BACKUP]   httpxer -u https://example.com -w common.txt --backup dry-run

Use `httpxer --help` for advanced options and more examples."#,
    after_long_help = r#"PRACTICAL EXAMPLES

  PROBE AND TECHNOLOGY
    httpxer -u https://example.com
    httpxer -l hosts.txt --tech default -o hosts.jsonl
    httpxer -l hosts.txt --tech off -o hosts.jsonl
    httpxer -l hosts.txt --live-only -o live.txt
    httpxer -l hosts.txt --urls-only --tech off --no-cdn -o live-urls.txt

  HEADERS AND BODY
    httpxer -u https://example.com --rh
    httpxer -u https://example.com --rh --with-body -o response.jsonl

  PATH FUZZING
    httpxer -u https://example.com -w common.txt -o hits.txt
    httpxer -u https://example.com -w admin.txt,api.txt --status '2xx,3xx,!429,!503'
    httpxer -l hosts.txt -w common.txt -t 50 --rate-limit 10 -o hits.jsonl

  RECURSION AND CRAWL
    httpxer -u https://example.com -w common.txt --recurse 3
    httpxer -u https://example.com -w common.txt --crawl 3
    httpxer -u https://example.com -w common.txt --deep 3

  AUTHENTICATION
    httpxer -u https://example.com --bearer "$TOKEN"
    httpxer -u https://example.com -H 'X-API-Key: secret' --cookie 'sid=abc'

  PROXY AND ROTATION
    httpxer -u https://example.com --proxy http://user:pass@127.0.0.1:8080
    httpxer -l hosts.txt --proxy proxies.txt -o hosts.jsonl

  BACKUP AND WILDCARD REVIEW
    httpxer -u https://example.com -w common.txt --backup dry-run
    httpxer -u https://example.com -w common.txt --wildcard mark -o review.jsonl
    httpxer -u https://example.com -w common.txt --safe

  PIPELINES AND OUTPUT
    cat hosts.txt | httpxer -l - --httpx-compat -o hosts.jsonl
    httpxer -u https://example.com -w common.txt -o hits.txt

`.txt` output is plain `STATUS SIZE URL` (plus title in probe mode); other extensions use JSONL.
Full recipes: https://github.com/assassin-marcos/httpxer"#
)]
struct Args {
    /// Host/URL file, or `-` for stdin (alternative: `-u`)
    #[arg(short = 'l', long, alias = "list",
          required_unless_present_any = ["update", "check_update", "uninstall", "target"],
          help_heading = "Targets")]
    input: Option<String>,

    /// Save results (`.txt` is plain text; other extensions use JSONL)
    #[arg(short = 'o', long, alias = "output", help_heading = "Output")]
    output: Option<String>,

    /// Concurrent HTTP requests
    #[arg(short = 't', long, default_value_t = 250, help_heading = "Network")]
    threads: usize,

    /// Request timeout in milliseconds
    #[arg(visible_alias = "to", long, default_value_t = 5000, help_heading = "Network")]
    timeout_ms: u64,

    /// Don't follow redirects (default: follow up to --max-redirects hops, matches httpx -fr)
    #[arg(visible_alias = "nfr", long, hide_short_help = true, help_heading = "Network")]
    no_follow_redirects: bool,

    /// (enrich) Max redirect hops to chase. SSO chains often need 4-6.
    #[arg(visible_alias = "mr", long, default_value_t = 10, hide_short_help = true, help_heading = "Network")]
    max_redirects: usize,

    /// Concurrent DNS lookups
    #[arg(visible_alias = "dc", long, default_value_t = 100, hide_short_help = true, help_heading = "Network")]
    dns_concurrency: usize,

    /// DNS timeout per lookup (seconds)
    #[arg(visible_alias = "dt", long, default_value_t = 3, hide_short_help = true, help_heading = "Network")]
    dns_timeout: u64,

    /// Embed in every output record under "domain"
    #[arg(long, hide_short_help = true, help_heading = "Output")]
    domain: Option<String>,

    /// Embed in every output record under "scan_id"
    #[arg(visible_alias = "sid", long, hide_short_help = true, help_heading = "Output")]
    scan_id: Option<String>,

    /// Embed in every output record under "source_tools" (e.g. "subfinder,amass")
    #[arg(visible_alias = "stools", long, hide_short_help = true, help_heading = "Output")]
    source_tools: Option<String>,

    /// Disable CDN detection in probe mode
    #[arg(long, help_heading = "Probe mode")]
    no_cdn: bool,

    /// Emit only hosts that returned an HTTP or HTTPS response
    #[arg(long, help_heading = "Probe mode")]
    live_only: bool,

    /// Write each responsive input origin, one per line; implies --live-only
    #[arg(long, help_heading = "Probe mode")]
    urls_only: bool,

    /// Skip tech detection (legacy spelling; prefer `--tech off`)
    #[arg(long, hide_short_help = true, help_heading = "Probe mode")]
    no_tech: bool,

    /// Load a fingerprint JSON file (legacy spelling; prefer `--tech FILE`)
    #[arg(long, hide_short_help = true, help_heading = "Probe mode")]
    fingerprints: Option<String>,

    /// Technology detection: `default`, `off`, or a fingerprint JSON file
    #[arg(long, value_name = "MODE|FILE", help_heading = "Probe mode")]
    tech: Option<String>,

    /// Don't resume — overwrite output file (default: skip hosts already in output)
    #[arg(long, hide_short_help = true, help_heading = "Output")]
    no_resume: bool,

    /// Disable browser TLS impersonation (use a plain wreq client). WAFs will
    /// see a non-Chrome JA4 fingerprint, which is fine on un-fronted targets
    /// and a few % faster on cold-start. Default: impersonate Chrome/Firefox/
    /// Safari/Edge with a random profile per probe.
    #[arg(visible_alias = "ni", long, hide_short_help = true, help_heading = "Network")]
    no_impersonate: bool,

    /// Include response body (capped at 2 MiB) in each output record under
    /// the `body` field. Useful for debugging fingerprint-echo endpoints
    /// (tls.peet.ws, ja3er.com) or archiving raw HTML. Off by default —
    /// keeps output files small.
    #[arg(visible_alias = "wb", long, hide_short_help = true, help_heading = "Output")]
    with_body: bool,

    /// Emit enrich-mode records in ProjectDiscovery httpx's JSON shape
    /// instead of the default httpxer shape. Differences in compat mode:
    /// `input` (URL with scheme) replaces `subdomain`; `a` / `aaaa` arrays
    /// replace the single `ip` string; `cname` becomes an array; `tech`
    /// becomes a string array (split from the comma-joined form);
    /// `webserver` is emitted alongside `server`; `host_ip` is added as
    /// the first A record (or first AAAA when no A is present).
    /// Inert in fuzz mode (the fuzz schema is already httpx-shaped).
    #[arg(long = "httpx-compat", visible_alias = "hc", hide_short_help = true, help_heading = "Output")]
    httpx_compat: bool,

    // ── Fuzz-mode flags (v0.3.0+) ──────────────────────────────────────
    // Presence of `-path / --paths` switches the binary from enrich mode
    // (1 probe per host) into fuzz mode (host × wordlist Cartesian probe).
    // All flags below are inert in enrich mode.
    /// Wordlist file(s); setting `-w` enables fuzz mode
    #[arg(
        short = 'p',
        long = "paths",
        visible_short_alias = 'w',
        alias = "path",
        visible_alias = "wordlist",
        alias = "wordlists",
        help_heading = "Fuzz mode"
    )]
    paths: Option<String>,

    /// (fuzz) Legacy include-only status list; prefer `--status`
    #[arg(long = "match-codes", hide_short_help = true, help_heading = "Fuzz mode")]
    match_codes: Option<String>,

    /// Statuses to keep, for example `2xx,3xx,!429`
    #[arg(long = "status", value_name = "SELECTOR", help_heading = "Fuzz mode")]
    status: Option<String>,

    /// (fuzz) Body preview length in bytes (HTML-entity-encoded in output)
    #[arg(
        long = "body-preview", visible_alias = "bp",
        default_value_t = 8192,
        hide_short_help = true,
        help_heading = "Fuzz mode"
    )]
    body_preview: usize,

    /// Catchall handling for 2xx/3xx and blanket 401/403: strict, mark, or off
    #[arg(
        long = "wildcard", visible_alias = "wildcard-policy", alias = "wp",
        default_value = "strict",
        help_heading = "Fuzz mode"
    )]
    wildcard_policy: String,

    /// (fuzz) Shortcut for `--wildcard-policy off`
    #[arg(long = "no-wildcard", hide = true)]
    no_wildcard: bool,

    /// Disable automatic 401/403 bypass checks
    #[arg(long = "safe", help_heading = "Fuzz mode")]
    safe: bool,

    /// Maximum requests per second per host; `0` disables the limit
    #[arg(long = "rate-limit", visible_alias = "rl", default_value_t = 0.0, help_heading = "Fuzz mode")]
    rate_limit: f64,

    /// (fuzz) Retry count on network error
    #[arg(long = "retries", default_value_t = 1, hide_short_help = true, help_heading = "Fuzz mode")]
    retries: u32,

    /// (fuzz) Emit status_code=0 records (connection errors). Off by default.
    #[arg(long = "include-errors", visible_alias = "ie", hide_short_help = true, help_heading = "Fuzz mode")]
    include_errors: bool,

    // ── Host-derived backup discovery (v0.6.0) ──────────────────────────
    // Runs automatically in fuzz mode. A wordlist cannot express
    // `www.target.com.zip` because the name depends on the target's own
    // host, so those candidates are generated per-host at runtime.
    //
    // Everything this mode does is decided at runtime from what the host
    // actually is: extension ordering follows the detected stack, the
    // candidate budget scales with how fast the host answers, and backup
    // directories are only expanded into after one is shown to exist. The
    // three flags below are the only decisions a human can usefully make.
    /// Automatic backup checks: `auto`, `off`, or `dry-run`
    #[arg(
        long = "backup",
        default_value = "auto",
        value_parser = ["auto", "off", "dry-run"],
        help_heading = "Backup discovery"
    )]
    backup: String,

    /// Legacy shortcut for `--backup off`.
    #[arg(long = "no-backup-fuzz", hide = true)]
    no_backup_fuzz: bool,

    /// Legacy shortcut for `--backup dry-run`.
    #[arg(long = "backup-dry-run", hide = true)]
    backup_dry_run: bool,

    /// (backup) Extra base-name tokens, comma-separated. The one thing the
    /// tool cannot infer: an internal project name unrelated to the
    /// hostname (e.g. `--backup-tokens acmecorp,internal-portal`).
    #[arg(long = "backup-tokens", value_name = "LIST", hide_short_help = true, help_heading = "Backup discovery")]
    backup_tokens: Option<String>,

    /// (fuzz) Legacy status-code exclusions; prefer `--status '2xx,!429'`.
    #[arg(
        long = "exclude",
        alias = "exclude-codes",
        alias = "exclude-status",
        hide_short_help = true,
        help_heading = "Fuzz mode"
    )]
    exclude_codes: Option<String>,

    /// (fuzz) Alias of `--match-codes` for dirsearch-muscle-memory users.
    #[arg(short = 'i', long = "include", hide_short_help = true, help_heading = "Fuzz mode")]
    include_status: Option<String>,

    // ── Recursion (v0.3.7) ─────────────────────────────────────────────
    /// Re-fuzz discovered directories (default depth: 3)
    #[arg(
        long = "recurse",
        visible_alias = "recursive",
        value_name = "DEPTH",
        num_args = 0..=1,
        default_missing_value = "3",
        help_heading = "Recursion"
    )]
    recurse: Option<u8>,

    /// Legacy short spelling for `--recurse` (default depth 3)
    #[arg(short = 'r', hide = true)]
    recursive: bool,

    /// Legacy recursion depth spelling; using it alone enables recursion
    #[arg(
        short = 'R',
        long = "recursion-depth", visible_alias = "rd",
        hide_short_help = true,
        help_heading = "Recursion"
    )]
    recursion_depth: Option<u8>,

    /// (recursion) Also recurse on 200 + autoindex marker (`Index of /`).
    #[arg(long = "recurse-on-200", visible_alias = "r200", hide_short_help = true, help_heading = "Recursion")]
    recurse_on_200: bool,

    /// (recursion) Also recurse on 403 (off by default — WAF noise prone).
    #[arg(long = "recurse-on-403", visible_alias = "r403", hide_short_help = true, help_heading = "Recursion")]
    recurse_on_403: bool,

    /// (recursion) Hard cap on discovered directories per input host.
    #[arg(long = "max-dirs-per-host", visible_alias = "md", default_value_t = 200, hide_short_help = true, help_heading = "Recursion")]
    max_dirs_per_host: usize,

    /// REMOVED in v0.5.0 — was never enforced. The counter behind it
    /// (`HostBudget::try_inc_probe`) was only ever called from unit tests, so
    /// the flag silently did nothing: a scan with `--max-probes-per-host 10`
    /// still issued 1260 probes in testing. Recursion is bounded by
    /// `--max-dirs-per-host` (which IS enforced) plus `-R`. Still parsed so
    /// existing scripts don't hard-fail; using it prints a deprecation notice.
    #[arg(long = "max-probes-per-host", hide = true)]
    max_probes_per_host: Option<usize>,

    /// (recursion) Override the built-in --exclude-subdirs default list
    /// (asset/traversal noise). Comma-separated. Empty string = disable
    /// excludes entirely.
    #[arg(long = "exclude-subdirs", visible_alias = "xs", hide_short_help = true, help_heading = "Recursion")]
    exclude_subdirs: Option<String>,

    /// (recursion) Append to the built-in --exclude-subdirs list
    /// (doesn't replace defaults; just adds).
    #[arg(long = "add-excludes", visible_alias = "xa", hide_short_help = true, help_heading = "Recursion")]
    add_excludes: Option<String>,

    /// (recursion) How exclude entries match: `segment` (default — last
    /// path component equals an entry, case-insensitive) or `substring`
    /// (any entry appears anywhere in the path). Substring is dirsearch-
    /// muscle-memory compat and catches encoded traversal noise
    /// (`%2e%2e`, `%3b`, `..//`) hidden mid-path.
    #[arg(long = "exclude-mode", visible_alias = "xm", default_value = "segment", hide_short_help = true, help_heading = "Recursion")]
    exclude_mode: String,

    /// (fuzz) Exact content-length(s) to drop from output. Comma-separated
    /// bytes — accepts trailing `B`. Mirrors dirsearch `--exclude-sizes`.
    /// Empty = no size filter.
    #[arg(long = "exclude-sizes", visible_alias = "es", default_value = "", hide_short_help = true, help_heading = "Fuzz mode")]
    exclude_sizes: String,

    /// (fuzz) Probe `/` once at startup and add its content-length to
    /// `--exclude-sizes` automatically. Catches fake-200 catchall pages
    /// that return the homepage for every path (a pattern the wildcard
    /// detector usually catches, but this is the explicit dirsearch
    /// pattern from `ROOT_SIZE=$(curl ...)`).
    #[arg(long = "exclude-root-size", visible_alias = "ers", hide_short_help = true, help_heading = "Fuzz mode")]
    exclude_root_size: bool,

    /// Output file format. `json` writes one full JSONL record. `plain`
    /// writes a compact status/size/URL line (plus title in probe mode).
    /// Auto-detected from `-o` (`.txt` → `plain`, otherwise `json`).
    #[arg(long = "format", hide_short_help = true, help_heading = "Output")]
    format: Option<String>,

    /// Suppress the live findings display on stderr. By default, every
    /// emitted finding prints to the terminal when `-o` is used. Pass this
    /// to rely on the output file only; `-q` also hides progress summaries.
    #[arg(long = "no-live", hide_short_help = true, help_heading = "Output")]
    no_live: bool,

    /// Print response headers and include them in JSONL output
    #[arg(
        long = "response-headers",
        visible_alias = "rh",
        visible_alias = "irh",
        help_heading = "Output"
    )]
    response_headers: bool,

    // ── Crawl (v0.3.7) ─────────────────────────────────────────────────
    /// Discover paths from HTML, robots.txt, and sitemaps
    #[arg(
        long = "crawl",
        value_name = "DEPTH",
        num_args = 0..=1,
        default_missing_value = "3",
        help_heading = "Crawl"
    )]
    crawl: Option<u8>,

    /// Enable recursion and crawling together
    #[arg(
        long = "deep",
        value_name = "DEPTH",
        num_args = 0..=1,
        default_missing_value = "3",
        help_heading = "Crawl"
    )]
    deep: Option<u8>,

    /// (crawl) Max crawl depth. Default = `--recursion-depth`.
    #[arg(long = "crawl-depth", visible_alias = "cd", hide_short_help = true, help_heading = "Crawl")]
    crawl_depth: Option<u8>,

    /// (crawl) Cap on URLs extracted per response (default 200).
    #[arg(long = "max-links-per-page", visible_alias = "mlp", default_value_t = 200, hide_short_help = true, help_heading = "Crawl")]
    max_links_per_page: usize,

    /// (crawl) Override the same-host default scope. Comma-separated host
    /// patterns. Supports `*.example.com` wildcard suffix.
    /// Built-in third-party deny list (Google/Cloudflare/CDN hosts) still
    /// applies regardless.
    #[arg(long = "scope", hide_short_help = true, help_heading = "Crawl")]
    scope: Option<String>,

    // ── Misc fuzz behavior (v0.3.7) ────────────────────────────────────
    /// (fuzz) Follow redirects and classify the terminal response (advanced)
    #[arg(long = "fuzz-follow-redirects", visible_alias = "ffr", hide_short_help = true, help_heading = "Fuzz mode")]
    fuzz_follow_redirects: bool,

    // ── Auth (v0.3.7) ──────────────────────────────────────────────────
    /// Add a request header; repeatable (`Name: Value`)
    #[arg(short = 'H', long = "header", help_heading = "Auth")]
    headers: Vec<String>,

    /// Add `Authorization: Bearer TOKEN`
    #[arg(long = "bearer", help_heading = "Auth")]
    bearer: Option<String>,

    /// Add a cookie; repeatable (`Name=Value`)
    #[arg(
        long = "cookie",
        help_heading = "Auth",
        long_help = "Add a fixed cookie; repeatable (`Name=Value`). Response cookies are not stored or replayed."
    )]
    cookies: Vec<String>,

    // ── Convenience ─────────────────────────────────────────────────────
    /// One target URL or hostname (alternative to `-l`)
    #[arg(short = 'u', long = "target", help_heading = "Targets")]
    target: Option<String>,

    /// Use one proxy URL or rotate entries from a proxy file
    #[arg(
        long = "proxy",
        value_name = "URL|FILE",
        help_heading = "Network",
        long_help = "Use one proxy URL or rotate a file per request. Files use one endpoint per line; blank lines and `#` comments are ignored. Mixed `http://`, `https://`, `socks4[a]://`, and `socks5[h]://` entries are accepted. Put HTTP/HTTPS/SOCKS5 credentials in the URL (`scheme://user:pass@host:port`); SOCKS4 authentication is unsupported. A bare `host:port` defaults to HTTP; prefix a path with `@` to force file mode."
    )]
    proxy: Option<String>,

    // ── Self-management ────────────────────────────────────────────────
    /// Install the latest published release
    #[arg(short = 'U', long, help_heading = "Self-management")]
    update: bool,

    /// Check for a newer release
    #[arg(short = 'c', long, help_heading = "Self-management")]
    check_update: bool,

    /// Uninstall httpxer (deletes this binary + the version-check cache)
    #[arg(short = 'X', long, hide_short_help = true, help_heading = "Self-management")]
    uninstall: bool,

    /// Skip the uninstall confirmation prompt
    #[arg(short = 'y', long, hide_short_help = true, help_heading = "Self-management")]
    yes: bool,

    /// Suppress the "update available" startup banner
    #[arg(visible_alias = "nuc", long, hide_short_help = true, help_heading = "Self-management")]
    no_update_check: bool,

    /// Hide banner, live findings, and progress
    #[arg(short = 'q', long, help_heading = "Self-management")]
    quiet: bool,

    /// Suppress the ASCII-art startup banner (banner is always skipped when
    /// stderr is not a TTY, so piped output is never polluted regardless)
    #[arg(long, hide_short_help = true, help_heading = "Self-management")]
    no_art: bool,

    // ── httpx compatibility no-ops ───────────────────────────────────────
    // These flags are accepted with the same single-dash spelling httpx uses
    // (e.g. `-sc`, `-fr`, `-no-color`) so the existing retrohack invocation
    // doesn't need rewriting. All the features they toggle on in httpx are
    // ALREADY on in httpxer (we always emit status_code, content_length,
    // word_count, server, location, title, tech, ip, cname in JSON). The
    // fields below are intentionally unused.
    /// httpx compat (no-op — redirects are followed by default; pass --no-follow-redirects to disable)
    #[arg(long, hide = true)]
    fr: bool,
    /// httpx compat (no-op — status_code is always in the JSON output)
    #[arg(long, hide = true)]
    sc: bool,
    /// httpx compat (no-op — content_length is always in the JSON output)
    #[arg(long, hide = true)]
    cl: bool,
    /// httpx compat (no-op — word_count is always in the JSON output)
    #[arg(long, hide = true)]
    wc: bool,
    /// httpx compat (no-op — server header is always in the JSON output)
    #[arg(long, hide = true)]
    server: bool,
    /// httpx compat (no-op — Location header is always in the JSON output)
    #[arg(long, hide = true)]
    location: bool,
    /// httpx compat (no-op — <title> is always in the JSON output)
    #[arg(long, hide = true)]
    title: bool,
    /// httpx compat (no-op — Wappalyzer tech-detect is always on; use --no-tech to disable)
    #[arg(long, hide = true)]
    td: bool,
    /// httpx compat (no-op — ip is always in the JSON output)
    #[arg(long, hide = true)]
    ip: bool,
    /// httpx compat (no-op — cname is always in the JSON output)
    #[arg(long, hide = true)]
    cname: bool,
    /// httpx compat (no-op — output is always NDJSON, one record per line)
    #[arg(long, hide = true)]
    json: bool,
    /// Disable ANSI colour in terminal output (also honours the conventional
    /// `NO_COLOR` env var). v0.5.0 — this used to be a documented no-op that
    /// falsely claimed httpxer emitted no ANSI; it now genuinely suppresses it.
    #[arg(long = "no-color", hide_short_help = true, help_heading = "Output")]
    no_color: bool,
    /// httpx compat (no-op — httpxer doesn't print per-record stderr noise)
    #[arg(long, hide = true)]
    silent: bool,
}

/// Convert known Go-style single-dash long flags (`-fr`, `-sc`, `-no-color`)
/// into clap's double-dash form. Only names registered with clap are rewritten:
/// this preserves valid attached short values (`-t150`, `-R3`) and short-flag
/// clusters (`-rq`). Everything after `--` is passed through verbatim.
fn normalize_args<I: IntoIterator<Item = String>>(args: I) -> Vec<String> {
    let command = Args::command();
    let mut known_long_names: HashSet<String> = HashSet::new();
    for arg in command.get_arguments() {
        if let Some(name) = arg.get_long() {
            known_long_names.insert(name.to_string());
        }
        if let Some(aliases) = arg.get_all_aliases() {
            known_long_names.extend(aliases.into_iter().map(str::to_string));
        }
    }

    let mut normalized = Vec::new();
    let mut positional_only = false;
    for (index, arg) in args.into_iter().enumerate() {
        if index == 0 {
            normalized.push(arg);
            continue;
        }
        if positional_only {
            normalized.push(arg);
            continue;
        }
        if arg == "--" {
            positional_only = true;
            normalized.push(arg);
            continue;
        }
        let replacement = arg
            .strip_prefix('-')
            .filter(|name| !name.starts_with('-'))
            .filter(|name| known_long_names.contains(*name))
            .map(|name| format!("--{}", name));
        normalized.push(replacement.unwrap_or(arg));
    }
    normalized
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
    /// CDN provider tag (cloudflare/cloudfront/fastly/google/aws), or ""
    /// if none / unknown.
    cdn: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_length: Option<u64>,
    /// Response Content-Type header (e.g. "text/html; charset=utf-8").
    /// Absent when the response had no such header.
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    word_count: Option<usize>,
    /// Body line count (httpx parity — emitted as `lines`).
    #[serde(skip_serializing_if = "Option::is_none")]
    lines: Option<usize>,
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

    /// Wall-clock probe time as Go-formatted duration ("662.326051ms",
    /// "1.5s"). Absent when the probe didn't complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<String>,

    /// True when `--proxy URL` was set — every probe in this record's
    /// scan family was routed through the configured upstream. Always
    /// emitted so downstream consumers can rely on the field's presence.
    via_proxy: bool,

    /// Raw response body, ≤2 MiB. Only present when --with-body is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,

    /// v0.4.10 — full response headers of the FINAL hop, emitted only under
    /// `--response-headers` / `--rh` (empty otherwise → skipped, so default
    /// enrich output is byte-identical). JSON object: lowercase keys,
    /// duplicate headers folded with ", ". Same shape as fuzz mode.
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "fuzz::serialize_response_headers",
        default
    )]
    response_headers: Vec<(String, String)>,

    /// Reason this record didn't enrich (dns / http). Absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,

    // ── Internal state for httpx-compat conversion ─────────────────────
    // These fields carry the raw DNS slice + the original input string
    // (with scheme intact) plus URL components broken out, so the
    // `--httpx-compat` writer can reshape the record without losing
    // information. They are `#[serde(skip)]` so the default JSONL shape
    // is byte-compatible with pre-v0.3.1 output (modulo the new
    // `content_type` / `lines` / `time` fields, which are omitted when
    // absent thanks to `skip_serializing_if`).
    #[serde(skip)]
    raw_ipv4: Vec<String>,
    #[serde(skip)]
    raw_ipv6: Vec<String>,
    #[serde(skip)]
    raw_input: String,
    #[serde(skip)]
    successful_input_url: Option<String>,
    #[serde(skip)]
    raw_scheme: String,
    #[serde(skip)]
    raw_port: String,
    #[serde(skip)]
    raw_path: String,
}

/// ProjectDiscovery httpx-shaped enrich record. Selected when
/// `--httpx-compat` is set. Field names + array shapes mirror what `httpx
/// -fr -sc -cl -wc -server -location -title -td -ip -cname -json` emits,
/// so existing httpx consumers (and ingest pipelines that key off `host`)
/// can read httpxer output unchanged.
///
/// Loadbearing parity rules vs the default `EnrichRecord` shape:
///   - `input` = BARE HOSTNAME (matches httpx) — `subdomain`'s value.
///   - `host`  = bare hostname (NEW — was previously missing, broke DB
///              ingest paths that keyed off `host`).
///   - `url`   = full URL with scheme (NEW — what `input` used to hold).
///   - `scheme`/`port`/`path` broken out (httpx emits each one).
///   - `a` + `aaaa` arrays replace the single `ip` string.
///   - `cname` becomes a string array.
///   - `tech` becomes a string array (split from comma-joined form).
///   - `webserver` is emitted alongside `server`.
///   - `host_ip` = first A (or first AAAA when no A).
///   - `cdn_name` / `cdn_type` replace the single `cdn` string
///     (httpx categorizes provider names: cloudflare/cloudfront/fastly →
///     `cdn`, aws/google → `cloud`).
///   - `words` (httpx field name) replaces `word_count`; `lines`,
///     `content_type`, `time`, `timestamp`, `method`, `failed` added.
#[derive(Serialize, Debug)]
struct HttpxCompatRecord {
    /// RFC3339 UTC capture timestamp. Set at record-construction time so
    /// records that take longer in tech-detect still get a wall-clock
    /// emission stamp.
    timestamp: String,

    /// Bare hostname — `httpx`'s `input` semantics. Renamed from the
    /// pre-v0.3.5 URL-with-scheme value (which now lives under `url`).
    input: String,
    /// Full URL with scheme — matches httpx's `url`.
    url: String,
    /// Bare hostname — same value as `input`. httpx emits both so DB
    /// pipelines that key off `host` work without normalising upstream.
    host: String,
    scheme: String,
    /// Port number as string — explicit value when the input URL carried
    /// one, otherwise the scheme default ("443" / "80").
    port: String,
    /// Request path — `/` for bare-hostname inputs.
    path: String,
    /// HTTP method — always "GET" for enrich-mode probes.
    method: &'static str,

    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_tools: Option<String>,

    /// IPv4 A records (httpx emits the full list, not just the first).
    a: Vec<String>,
    /// IPv6 AAAA records.
    aaaa: Vec<String>,
    /// CNAME chain — array form to match httpx.
    cname: Vec<String>,
    /// First A record, or first AAAA when there is no A.
    host_ip: String,
    /// CDN provider tag (cloudflare/cloudfront/fastly/google/aws), or ""
    /// if none. Kept for backwards compat with pre-v0.3.5 consumers.
    cdn: String,
    /// Same value as `cdn` — httpx's field name.
    cdn_name: String,
    /// CDN category: `cdn` (cloudflare/cloudfront/fastly), `cloud`
    /// (aws/google), or "" when unknown / no match.
    cdn_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_length: Option<u64>,
    /// Response Content-Type header (httpx parity field name).
    content_type: String,
    /// httpx's `words` field — renamed from `word_count`.
    #[serde(rename = "words", skip_serializing_if = "Option::is_none")]
    word_count: Option<usize>,
    /// Body line count.
    #[serde(skip_serializing_if = "Option::is_none")]
    lines: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    /// httpx alias of `server`. Emitted whenever `server` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    webserver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    final_url: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    redirect_chain: Vec<String>,

    /// `tech` as a string array — split from `EnrichRecord.tech`'s
    /// comma-joined form on `", "`.
    tech: Vec<String>,

    /// Wall-clock probe time as Go-formatted duration ("662.326051ms",
    /// "1.5s"). Empty string when the probe didn't complete (so the
    /// field is always emitted — httpx parity).
    time: String,
    /// True when no successful HTTP response was captured (DNS failure,
    /// network error, etc.). Always emitted.
    failed: bool,

    /// True when `--proxy URL` was set. Always emitted.
    via_proxy: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// httpx-style CDN category: ProjectDiscovery's cdncheck tags providers
/// as `cdn` (Cloudflare / CloudFront / Fastly) or `cloud` (AWS / GCP /
/// Azure). Returns "" for unknown / no-match.
fn cdn_type_for(name: &str) -> &'static str {
    match name {
        "cloudflare" | "cloudfront" | "fastly" => "cdn",
        "aws" | "google" => "cloud",
        _ => "",
    }
}

impl HttpxCompatRecord {
    /// Reshape a default `EnrichRecord` into the httpx-compatible record.
    /// Drains the raw DNS slice + raw input + URL components the
    /// EnrichRecord carries on the side; everything else is a direct
    /// field map.
    fn from_enrich(rec: EnrichRecord) -> Self {
        let tech: Vec<String> = if rec.tech.is_empty() {
            Vec::new()
        } else {
            rec.tech
                .split(", ")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };
        let cname_arr: Vec<String> = if rec.cname.is_empty() {
            Vec::new()
        } else {
            vec![rec.cname]
        };
        // host_ip: first A, falling back to first AAAA when no A exists.
        let host_ip = rec
            .raw_ipv4
            .first()
            .cloned()
            .or_else(|| rec.raw_ipv6.first().cloned())
            .unwrap_or_default();
        let cdn_type = cdn_type_for(&rec.cdn).to_string();
        let cdn_name = rec.cdn.clone();
        let failed = rec.status_code.is_none();
        let time = rec.time.clone().unwrap_or_default();
        // Nanosecond-precision RFC3339 (matches httpx's
        // `2026-05-20T15:46:41.082345879+08:00` format; we emit UTC `Z`).
        let timestamp =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        HttpxCompatRecord {
            timestamp,
            input: rec.subdomain.clone(),
            url: rec.raw_input,
            host: rec.subdomain,
            scheme: rec.raw_scheme,
            port: rec.raw_port,
            path: rec.raw_path,
            method: "GET",
            domain: rec.domain,
            scan_id: rec.scan_id,
            source_tools: rec.source_tools,
            a: rec.raw_ipv4,
            aaaa: rec.raw_ipv6,
            cname: cname_arr,
            host_ip,
            cdn: rec.cdn,
            cdn_name,
            cdn_type,
            status_code: rec.status_code,
            content_length: rec.content_length,
            content_type: rec.content_type.unwrap_or_default(),
            word_count: rec.word_count,
            lines: rec.lines,
            server: rec.server.clone(),
            webserver: rec.server,
            location: rec.location,
            title: rec.title,
            final_url: rec.final_url,
            redirect_chain: rec.redirect_chain,
            tech,
            time,
            failed,
            via_proxy: rec.via_proxy,
            body: rec.body,
            error: rec.error,
        }
    }
}

/// Parse a URL into `(scheme, port, path)` strings. For bare hostnames or
/// unparseable inputs, falls back to `("https", "443", "/")` since enrich
/// mode defaults to `https://` for scheme-less list entries.
fn parse_url_parts(url: &str) -> (String, String, String) {
    if let Ok(u) = url::Url::parse(url) {
        let scheme = u.scheme().to_string();
        let port = u
            .port_or_known_default()
            .map(|p| p.to_string())
            .unwrap_or_default();
        let path = {
            let p = u.path();
            if p.is_empty() { "/" } else { p }.to_string()
        };
        return (scheme, port, path);
    }
    ("https".to_string(), "443".to_string(), "/".to_string())
}

fn observed_probe_url(input: &str, final_url: Option<&str>, via_https: bool) -> String {
    if let Some(final_url) = final_url {
        return final_url.to_string();
    }
    let scheme = if via_https { "https" } else { "http" };
    if let Ok(mut parsed) = url::Url::parse(input) {
        if parsed.set_scheme(scheme).is_ok() {
            return parsed.to_string();
        }
    }
    format!("{}://{}", scheme, input.trim_end_matches('/'))
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
    // v0.5.2 — resume only makes sense for a REGULAR file. `-o /dev/stdout`,
    // `/dev/stderr`, a pipe or any char device would otherwise be opened for
    // READING here: on a TTY that blocks on the keyboard, so the scan hung
    // right after "[+] input: N unique hosts" with no explanation. A char
    // device has no prior results to resume from anyway.
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {}
        // Missing file = normal first run (read_to_string would fail below
        // anyway); anything non-regular = nothing to resume from.
        Ok(_) => return HashSet::new(),
        Err(_) => return HashSet::new(),
    }
    let Ok(file) = std::fs::File::open(path) else {
        return HashSet::new();
    };
    let mut out = HashSet::new();
    for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            for key in ["subdomain", "host", "input", "url"] {
                if let Some(s) = v.get(key).and_then(|s| s.as_str()) {
                    let host = extract_host(s);
                    if !host.is_empty() {
                        out.insert(host);
                        break;
                    }
                }
            }
            continue;
        }
        // Enrich plain output is `STATUS SIZE URL [TITLE]`; `--urls-only`
        // writes just URL. Accept both so text outputs remain resume-aware.
        let mut fields = line.split_whitespace();
        let first = fields.next();
        let second = fields.next();
        let third = fields.next();
        let candidate = third.or_else(|| if second.is_none() { first } else { None });
        if let Some(url) = candidate {
            let host = extract_host(url);
            if !host.is_empty() {
                out.insert(host);
            }
        }
    }
    out
}

const DEFAULT_MATCH_CODES: &str = "200,301,302,307,308,401,403";

#[derive(Debug, Clone, PartialEq, Eq)]
struct TechSelection {
    enabled: bool,
    fingerprints_path: Option<String>,
}

fn resolve_tech_selection(
    tech: Option<&str>,
    no_tech: bool,
    fingerprints: Option<&str>,
) -> Result<TechSelection> {
    if tech.is_some() && (no_tech || fingerprints.is_some()) {
        anyhow::bail!(
            "--tech cannot be combined with legacy --no-tech or --fingerprints"
        );
    }
    if let Some(value) = tech {
        return match value.trim().to_ascii_lowercase().as_str() {
            "default" | "embedded" => Ok(TechSelection {
                enabled: true,
                fingerprints_path: None,
            }),
            "off" | "none" => Ok(TechSelection {
                enabled: false,
                fingerprints_path: None,
            }),
            _ if value.trim().is_empty() => anyhow::bail!(
                "--tech needs `default`, `off`, or a fingerprint JSON path"
            ),
            _ => Ok(TechSelection {
                enabled: true,
                fingerprints_path: Some(value.trim().to_string()),
            }),
        };
    }
    Ok(TechSelection {
        enabled: !no_tech,
        fingerprints_path: if no_tech {
            None
        } else {
            fingerprints.map(str::to_string)
        },
    })
}

fn parse_exact_status_list(value: &str, flag: &str) -> Result<Vec<u16>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut codes = HashSet::new();
    for raw in value.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            anyhow::bail!("{} contains an empty status token", flag);
        }
        let code = token
            .parse::<u16>()
            .with_context(|| format!("{} contains invalid status '{}'", flag, token))?;
        if !(100..=999).contains(&code) {
            anyhow::bail!("{} status {} is outside 100..999", flag, code);
        }
        codes.insert(code);
    }
    let mut codes: Vec<u16> = codes.into_iter().collect();
    codes.sort_unstable();
    Ok(codes)
}

fn expand_status_selector(token: &str) -> Result<Vec<u16>> {
    let lower = token.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    if bytes.len() == 3
        && (b'1'..=b'9').contains(&bytes[0])
        && bytes[1] == b'x'
        && bytes[2] == b'x'
    {
        let start = u16::from(bytes[0] - b'0') * 100;
        return Ok((start..=start + 99).collect());
    }
    let code = lower
        .parse::<u16>()
        .with_context(|| format!("invalid status selector '{}'", token))?;
    if !(100..=999).contains(&code) {
        anyhow::bail!("status selector {} is outside 100..999", code);
    }
    Ok(vec![code])
}

fn parse_status_selector(value: &str) -> Result<(Vec<u16>, Vec<u16>)> {
    let mut included = HashSet::new();
    let mut excluded = HashSet::new();
    for raw in value.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            anyhow::bail!("--status contains an empty selector");
        }
        let (negated, token) = match raw.strip_prefix('!') {
            Some(token) if !token.is_empty() => (true, token),
            Some(_) => anyhow::bail!("--status contains a bare '!'") ,
            None => (false, raw),
        };
        for code in expand_status_selector(token)? {
            if negated {
                excluded.insert(code);
            } else {
                included.insert(code);
            }
        }
    }
    if included.is_empty() {
        anyhow::bail!("--status needs at least one positive code or class");
    }
    let mut included: Vec<u16> = included.into_iter().collect();
    let mut excluded: Vec<u16> = excluded.into_iter().collect();
    included.sort_unstable();
    excluded.sort_unstable();
    Ok((included, excluded))
}

fn resolve_status_filters(
    status: Option<&str>,
    match_codes: Option<&str>,
    include_status: Option<&str>,
    exclude_codes: Option<&str>,
) -> Result<(Vec<u16>, Vec<u16>)> {
    if let Some(selector) = status {
        if match_codes.is_some() || include_status.is_some() || exclude_codes.is_some() {
            anyhow::bail!(
                "--status cannot be combined with --match-codes, --include, or --exclude"
            );
        }
        return parse_status_selector(selector);
    }
    let include = include_status
        .or(match_codes)
        .unwrap_or(DEFAULT_MATCH_CODES);
    let match_codes = parse_exact_status_list(include, "--include/--match-codes")?;
    if match_codes.is_empty() {
        anyhow::bail!("the status include list cannot be empty");
    }
    let exclude_codes = parse_exact_status_list(exclude_codes.unwrap_or(""), "--exclude")?;
    Ok((match_codes, exclude_codes))
}

fn parse_exclude_sizes(value: &str) -> Result<Vec<i64>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut sizes = HashSet::new();
    for raw in value.split(',') {
        let token = raw.trim().trim_end_matches(['B', 'b']);
        if token.is_empty() {
            anyhow::bail!("--exclude-sizes contains an empty size");
        }
        let size = token
            .parse::<i64>()
            .with_context(|| format!("--exclude-sizes contains invalid size '{}'", raw.trim()))?;
        if size < 0 {
            anyhow::bail!("--exclude-sizes cannot contain negative values");
        }
        sizes.insert(size);
    }
    let mut sizes: Vec<i64> = sizes.into_iter().collect();
    sizes.sort_unstable();
    Ok(sizes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackupMode {
    Auto,
    Off,
    DryRun,
}

fn resolve_backup_mode(
    backup: &str,
    legacy_off: bool,
    legacy_dry_run: bool,
) -> Result<BackupMode> {
    if legacy_off && legacy_dry_run {
        anyhow::bail!("--no-backup-fuzz conflicts with --backup-dry-run");
    }
    if backup != "auto" && (legacy_off || legacy_dry_run) {
        anyhow::bail!("--backup cannot be combined with legacy backup mode flags");
    }
    if legacy_off {
        return Ok(BackupMode::Off);
    }
    if legacy_dry_run {
        return Ok(BackupMode::DryRun);
    }
    match backup {
        "auto" => Ok(BackupMode::Auto),
        "off" => Ok(BackupMode::Off),
        "dry-run" => Ok(BackupMode::DryRun),
        other => anyhow::bail!("invalid --backup '{}' (want auto|off|dry-run)", other),
    }
}

fn resolve_scan_depths(args: &Args) -> (u8, bool, u8) {
    let recursion_depth = args
        .recursion_depth
        .or(args.recurse)
        .or(args.deep)
        .or_else(|| args.recursive.then_some(3))
        .unwrap_or(0);
    let crawl_enabled = args.crawl.is_some() || args.crawl_depth.is_some() || args.deep.is_some();
    let crawl_depth = args
        .crawl_depth
        .or(args.crawl)
        .or(args.deep)
        .unwrap_or(0);
    (recursion_depth, crawl_enabled, crawl_depth)
}

fn backup_sidecar_path(output: Option<&str>) -> String {
    output
        .map(|path| format!("{}.backup.jsonl", path))
        .unwrap_or_else(|| "httpxer-backup.jsonl".to_string())
}

fn validate_output_destination(path: &str, user_named: bool) -> Result<()> {
    if !user_named {
        return Ok(());
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open output {}", path))?;
    Ok(())
}

fn write_realtime_line<W: Write>(output: &mut W, line: &str) -> std::io::Result<()> {
    writeln!(output, "{}", line)?;
    output.flush()
}

fn format_enrich_size(bytes: Option<u64>) -> String {
    let Some(bytes) = bytes else {
        return "--".to_string();
    };
    let value = bytes as f64;
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    if value < KB {
        format!("{}B", bytes)
    } else if value < MB {
        format!("{:.0}KB", value / KB)
    } else if value < GB {
        format!("{:.1}MB", value / MB)
    } else {
        format!("{:.1}GB", value / GB)
    }
}

fn sanitize_plain_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>()
        .trim()
        .to_string()
}

fn format_enrich_plain(record: &EnrichRecord) -> String {
    let status = record
        .status_code
        .map(|status| status.to_string())
        .unwrap_or_else(|| "ERR".to_string());
    let size = format_enrich_size(record.content_length);
    let url = sanitize_plain_field(
        record
            .final_url
            .as_deref()
            .unwrap_or(record.raw_input.as_str()),
    );
    let detail = record
        .title
        .as_deref()
        .or(record.error.as_deref())
        .map(sanitize_plain_field)
        .filter(|value| !value.is_empty());
    match detail {
        Some(detail) => format!("{:>3} {:>7}  {}  {}", status, size, url, detail),
        None => format!("{:>3} {:>7}  {}", status, size, url),
    }
}

fn format_enrich_url_origin(record: &EnrichRecord) -> String {
    let candidate = record
        .successful_input_url
        .as_deref()
        .unwrap_or(record.raw_input.as_str());
    let Ok(parsed) = url::Url::parse(candidate) else {
        return sanitize_plain_field(candidate);
    };
    let Some(host) = parsed.host_str() else {
        return sanitize_plain_field(candidate);
    };
    let host = if host.starts_with('[') && host.ends_with(']') {
        host.to_string()
    } else if host.contains(':') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    match parsed.port() {
        Some(port) => format!("{}://{}:{}", parsed.scheme(), host, port),
        None => format!("{}://{}", parsed.scheme(), host),
    }
}

fn write_enrich_result<W: Write>(
    joined: std::result::Result<EnrichRecord, tokio::task::JoinError>,
    output: &mut W,
    output_format: fuzz::OutputFormat,
    httpx_compat: bool,
    live_only: bool,
    urls_only: bool,
    live_findings: bool,
    processed: &mut usize,
    emitted: &mut usize,
    total: usize,
    quiet: bool,
) -> Result<()> {
    match joined {
        Ok(record) => {
            *processed += 1;
            if !(live_only || urls_only) || record.status_code.is_some() {
                let display_line = format_enrich_plain(&record);
                let output_line = if urls_only {
                    format_enrich_url_origin(&record)
                } else {
                    match output_format {
                        fuzz::OutputFormat::Plain => display_line.clone(),
                        fuzz::OutputFormat::Json if httpx_compat => {
                            serde_json::to_string(&HttpxCompatRecord::from_enrich(record))?
                        }
                        fuzz::OutputFormat::Json => serde_json::to_string(&record)?,
                    }
                };
                write_realtime_line(output, &output_line)?;
                *emitted += 1;
                if live_findings {
                    eprintln!("{}", display_line);
                }
            }
        }
        Err(error) => {
            *processed += 1;
            eprintln!("[!] probe task did not complete: {}", error);
        }
    }
    if !quiet && (*processed % 50 == 0 || *processed == total) {
        eprintln!("  [{}/{}]", *processed, total);
    }
    Ok(())
}

fn validate_mode_specific_args(args: &Args) -> Result<()> {
    if args.paths.is_some() {
        if args.live_only || args.urls_only {
            anyhow::bail!(
                "--live-only and --urls-only are probe-only and cannot be used with `-w WORDLIST`"
            );
        }
        return Ok(());
    }
    if args.urls_only && (args.format.is_some() || args.httpx_compat) {
        anyhow::bail!("--urls-only cannot be combined with --format or --httpx-compat");
    }
    let mut fuzz_only = Vec::new();
    if args.status.is_some() { fuzz_only.push("--status"); }
    if args.match_codes.is_some() { fuzz_only.push("--match-codes"); }
    if args.include_status.is_some() { fuzz_only.push("--include"); }
    if args.exclude_codes.is_some() { fuzz_only.push("--exclude"); }
    if args.recurse.is_some() || args.recursive || args.recursion_depth.is_some() {
        fuzz_only.push("--recurse");
    }
    if args.crawl.is_some() || args.crawl_depth.is_some() { fuzz_only.push("--crawl"); }
    if args.deep.is_some() { fuzz_only.push("--deep"); }
    if args.backup != "auto" || args.no_backup_fuzz || args.backup_dry_run {
        fuzz_only.push("--backup");
    }
    if args.backup_tokens.is_some() { fuzz_only.push("--backup-tokens"); }
    if args.safe { fuzz_only.push("--safe"); }
    if args.rate_limit != 0.0 { fuzz_only.push("--rate-limit"); }
    if args.retries != 1 { fuzz_only.push("--retries"); }
    if args.include_errors { fuzz_only.push("--include-errors"); }
    if args.recurse_on_200 || args.recurse_on_403 { fuzz_only.push("--recurse-on-*"); }
    if args.exclude_subdirs.is_some() || args.add_excludes.is_some() || args.exclude_mode != "segment" {
        fuzz_only.push("--exclude-subdirs/--exclude-mode");
    }
    if !args.exclude_sizes.is_empty() || args.exclude_root_size {
        fuzz_only.push("--exclude-sizes/--exclude-root-size");
    }
    if args.scope.is_some() || args.max_links_per_page != 200 { fuzz_only.push("--scope/--max-links-per-page"); }
    if args.fuzz_follow_redirects { fuzz_only.push("--fuzz-follow-redirects"); }
    if args.no_wildcard || args.wildcard_policy != "strict" { fuzz_only.push("--wildcard"); }
    fuzz_only.sort_unstable();
    fuzz_only.dedup();
    if !fuzz_only.is_empty() {
        anyhow::bail!(
            "fuzz-only option(s) {} require `-w WORDLIST`",
            fuzz_only.join(", ")
        );
    }
    Ok(())
}

/// Decide whether to draw the ASCII banner BEFORE clap parses argv.
/// We can't read parsed `args.quiet` / `args.no_art` here (parsing hasn't
/// happened yet — that's the whole point — clap exiting on missing args
/// would otherwise skip the banner), so we scan the raw argv directly.
///
/// Suppressed when:
///   - stderr is not a TTY (piped output stays clean)
///   - any of `-q`, `--quiet`, `--no-art` literally appears in argv
///
/// Note: `--no-update-check` does NOT suppress the banner — it only
/// suppresses the "[!] update available" follow-up line. The ASCII art
/// is the program's signature; we want it on every TTY invocation.
fn banner_should_show_early(argv: &[String]) -> bool {
    if !update::stderr_is_tty() {
        return false;
    }
    for a in argv {
        if a == "-q" || a == "--quiet" || a == "--no-art" {
            return false;
        }
    }
    true
}

/// v0.4.1 — pre-scan argv for flags that suppress the network update
/// check (mirror of `banner_should_show_early`, but for the GitHub
/// API hit that refreshes the cache). Same constraint: we can't read
/// parsed `args.no_update_check` yet because clap hasn't run.
fn update_check_allowed_early(argv: &[String]) -> bool {
    for (index, a) in argv.iter().enumerate() {
        if a == "-q" || a == "--quiet" || a == "--no-update-check" {
            return false;
        }
        if a == "--backup-dry-run"
            || a == "--backup=dry-run"
            || (a == "--backup" && argv.get(index + 1).is_some_and(|v| v == "dry-run"))
        {
            return false;
        }
    }
    true
}

/// Extract the endpoint authority used for record and resume identity. Keep a
/// non-default port so services on the same DNS name remain distinct.
fn extract_host(input: &str) -> String {
    let candidate = if input.starts_with("https://") || input.starts_with("http://") {
        input.to_string()
    } else {
        format!("https://{}", input)
    };
    let Ok(url) = url::Url::parse(&candidate) else {
        return String::new();
    };
    let Some(host) = url.host_str() else {
        return String::new();
    };
    match url.port() {
        Some(port) if host.contains(':') => format!("[{}]:{}", host, port),
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    }
}

/// DNS accepts a hostname only, never an authority containing a port.
fn extract_dns_host(input: &str) -> String {
    let candidate = if input.starts_with("https://") || input.starts_with("http://") {
        input.to_string()
    } else {
        format!("https://{}", input)
    };
    url::Url::parse(&candidate)
        .ok()
        .and_then(|url| url.host_str().map(ToString::to_string))
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<()> {
    // v0.3.8: print the ASCII banner BEFORE clap parsing so it appears on
    // EVERY invocation — including `httpxer` with no args (clap missing-
    // arg error), `httpxer --version`, `httpxer --help`, and bad-flag
    // typos. The previous order (parse → banner) meant clap exited on any
    // parse failure before the banner could draw.
    //
    // Suppression is opt-in via a raw-argv pre-scan (we can't read parsed
    // `args.quiet` yet — clap hasn't run). Cheap O(argv-len) scan; sub-µs.
    let raw_argv: Vec<String> = std::env::args().collect();
    let normalized_argv = normalize_args(raw_argv);
    let want_banner = banner_should_show_early(&normalized_argv);
    let allow_update_check = update_check_allowed_early(&normalized_argv);

    // v0.4.1: refresh the update cache BEFORE the banner so the
    // `(outdated → vX.Y.Z)` tag is accurate on the FIRST invocation
    // (not just the second one). `refresh_update_cache_best_effort` has
    // an internal 120 s skip-window so back-to-back calls are
    // network-free, and a 2.5 s hard cap so this never blocks startup
    // for long. Skipped when `-q` / `--quiet` / `--no-update-check`.
    if want_banner && allow_update_check {
        update::refresh_update_cache_best_effort().await;
    }
    if want_banner {
        update::print_banner();
    }

    let args = Args::parse_from(normalized_argv);

    // v0.4.10 — `--max-probes-per-host` was removed: it was never enforced
    // (the counter behind it was only called from unit tests, so the flag
    // silently did nothing). Still parsed so existing scripts don't hard-fail;
    // say so loudly once instead of pretending it works.
    if args.max_probes_per_host.is_some() {
        eprintln!(
            "[!] --max-probes-per-host was REMOVED in v0.5.0 (it was never enforced — a no-op). \
             Ignoring it. Recursion is bounded by --max-dirs-per-host (enforced) and -R; \
             drop the flag from your scripts."
        );
    }

    // v0.5.0 — honour --no-color and the conventional NO_COLOR env var.
    if args.no_color || std::env::var_os("NO_COLOR").is_some() {
        fuzz::set_no_color();
    }

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
    validate_mode_specific_args(&args)?;

    // Parse and validate one proxy URL or a mixed proxy file before target
    // traffic starts. Diagnostics expose counts and schemes, never credentials.
    let proxy_config = args
        .proxy
        .as_deref()
        .map(probe::ProxyConfig::from_spec)
        .transpose()?;
    let proxy_enabled = proxy_config.is_some();
    if let Some(config) = proxy_config.as_ref() {
        if !args.quiet {
            eprintln!(
                "[+] proxy: {} endpoint(s) from {} ({}); rotating per request",
                config.len(),
                config.source_label(),
                config.scheme_summary(),
            );
        }
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

    // v0.5.3 — `-o` is OPTIONAL. With no output file, records stream to stdout
    // so `httpxer -u host --rh` works standalone and stays pipeable into jq.
    // Resume already skips non-regular paths (v0.5.2), so pointing at the
    // stdout device can't block on a read.
    let stdout_sink = if cfg!(windows) { "CON" } else { "/dev/stdout" };
    let output_path = args.output.as_deref().unwrap_or(stdout_sink);
    // `--no-resume` truncates the output by deleting it first. Only ever delete
    // a path the USER named: when `-o` is omitted the sink above is
    // `/dev/stdout`, which on Linux is a symlink to `/proc/self/fd/1`, and
    // `unlink(2)` never follows the final symlink component — it would remove
    // the `/dev/stdout` link itself (silently EACCES as a normal user, but
    // succeeding, system-wide, when httpxer is run as root). Nothing to
    // truncate on a stream anyway.
    let user_named_output = args.output.is_some();

    // 1. Read + dedupe input. `-u TARGET` is a one-host shortcut that
    //    short-circuits the file read entirely. When BOTH `-u` and `-l`
    //    are passed, the target gets prepended to the file's list (then
    //    deduped).
    let mut hosts: Vec<String> = Vec::new();
    if let Some(t) = args.target.as_deref() {
        hosts.push(t.to_string());
    }
    if let Some(p) = args.input.as_deref() {
        hosts.extend(read_hosts(p)?);
    }
    // Dedupe while preserving first-seen order.
    let mut seen_inputs: HashSet<String> = HashSet::new();
    hosts.retain(|h| seen_inputs.insert(h.clone()));
    let initial = hosts.len();
    if initial == 0 {
        anyhow::bail!("no input — pass `-u URL` or `-l file`");
    }
    eprintln!("[+] input: {} unique hosts", initial);

    // v0.5.0 — auth is built BEFORE the mode split so `-H` / `--bearer` /
    // `--cookie` apply to BOTH enrich and fuzz. Previously `AuthCtx` was
    // constructed inside the fuzz block, so enrich-mode probes went out
    // unauthenticated with no warning (a silent, dangerous no-op). Syntax is
    // validated here too, so a malformed `-H` now fails loudly in either mode.
    let auth_ctx = auth::AuthCtx::from_cli(&args.headers, args.bearer.as_deref(), &args.cookies)?;
    let extra_headers: Vec<(String, String)> = auth_ctx
        .headers
        .iter()
        .map(|(n, v)| (n.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let initial_cookie_header = auth_ctx.initial_cookie_header();
    // Install for the enrich probe path (fuzz passes them via FuzzCfg instead).
    probe::init_auth(extra_headers.clone(), initial_cookie_header.clone());
    if auth_ctx.is_active() {
        eprintln!(
            "[+] auth: {} header(s){}",
            extra_headers.len(),
            if initial_cookie_header.is_some() {
                " + cookie"
            } else {
                ""
            }
        );
    }

    let tech_selection = resolve_tech_selection(
        args.tech.as_deref(),
        args.no_tech,
        args.fingerprints.as_deref(),
    )?;
    if args.no_tech && args.fingerprints.is_some() {
        eprintln!(
            "[!] --fingerprints is ignored because --no-tech was passed \
             (tech-detect is off, so no fingerprint file is loaded)"
        );
    }

    // 2a. FUZZ MODE — triggered by `-path / --paths <wordlist>`.
    //     Bypasses enrich-mode's DNS/CDN/tech-detect path entirely and
    //     issues a host × path Cartesian probe through the same wreq
    //     pool, with per-request `redirect::Policy::none()` so 3xx is a
    //     finding (not chased). Output schema matches retroh4ck-prober
    //     v0.1.0 — see `src/fuzz.rs` for the FuzzRecord layout.
    if let Some(paths_path) = args.paths.as_deref() {
        if args.tech.is_some() || args.no_tech || args.fingerprints.is_some() {
            eprintln!("[!] technology detection options are enrich-only and do not affect fuzz records");
        }
        let words = fuzz::read_words(paths_path)?;
        eprintln!("[+] wordlist: {} unique paths", words.len());

        // Resolve and validate every fuzz-mode control before creating the
        // HTTP pool or issuing backup/root-size requests.
        let backup_mode = resolve_backup_mode(
            &args.backup,
            args.no_backup_fuzz,
            args.backup_dry_run,
        )?;
        if matches!(backup_mode, BackupMode::Off) && args.backup_tokens.is_some() {
            anyhow::bail!("--backup-tokens cannot be used with --backup off");
        }
        let policy = fuzz::WildcardPolicy::from_cli(&args.wildcard_policy, args.no_wildcard)?;
        let (match_codes, exclude_codes) = resolve_status_filters(
            args.status.as_deref(),
            args.match_codes.as_deref(),
            args.include_status.as_deref(),
            args.exclude_codes.as_deref(),
        )?;
        let exclude_subdirs = recurse::build_exclude_set(
            args.exclude_subdirs.as_deref(),
            args.add_excludes.as_deref(),
        );
        let exclude_mode = recurse::ExcludeMode::from_cli(&args.exclude_mode)?;
        let exclude_sizes = parse_exclude_sizes(&args.exclude_sizes)?;
        let scope_hosts: Vec<String> = args
            .scope
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let (recursion_depth, crawl_enabled, crawl_depth) = resolve_scan_depths(&args);
        let output_format = match args.format.as_deref() {
            Some(value) => fuzz::OutputFormat::from_cli(value)?,
            None => fuzz::OutputFormat::from_path(output_path),
        };
        if args.threads == 0 {
            anyhow::bail!("--threads must be at least 1");
        }
        if args.rate_limit.is_sign_negative() || !args.rate_limit.is_finite() {
            anyhow::bail!("--rate-limit must be a finite value greater than or equal to 0");
        }

        let request_limiter = Arc::new(fuzz::ratelimit::HostRateLimiter::new(args.rate_limit));
        let backup_cfg = backup_fuzz::BackupCfg {
            token_extra: args
                .backup_tokens
                .as_deref()
                .map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|token| !token.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            current_year: chrono::Utc::now()
                .format("%Y")
                .to_string()
                .parse()
                .unwrap_or(2026),
            ..Default::default()
        };

        // A backup preview is a terminal mode: print candidates, send no
        // target or update-check requests, and never continue into fuzzing.
        if matches!(backup_mode, BackupMode::DryRun) {
            eprintln!(
                "[+] backup discovery: maximum candidate preview \
                 [dry-run; no requests; live auto may lower the URL budget]"
            );
            let opts = backup_fuzz::PhaseOpts {
                cfg: backup_cfg,
                dry_run: true,
                concurrency: args.threads,
                request: backup_fuzz::RequestCtx {
                    limiter: request_limiter,
                    extra_headers,
                    cookie_header: initial_cookie_header,
                },
            };
            backup_fuzz::run_phase(&hosts, &opts, |_| Ok(())).await?;
            return Ok(());
        }

        validate_output_destination(output_path, user_named_output)?;

        // Build the impersonation pool once — fuzz uses the same pool
        // enrich does, so the init logic is identical.
        probe::init_pool(args.timeout_ms, args.no_impersonate, proxy_config)?;
        if !args.no_impersonate {
            eprintln!(
                "[+] TLS impersonation: stable real-browser JA3/JA4 + HTTP/2 profile per host"
            );
        } else {
            eprintln!("[+] TLS impersonation: DISABLED (--no-impersonate)");
        }

        // Backup phase runs before the wordlist sweep so a jackpot archive
        // surfaces immediately rather than after a long path scan.
        if matches!(backup_mode, BackupMode::Auto) {
            let opts = backup_fuzz::PhaseOpts {
                cfg: backup_cfg,
                dry_run: false,
                concurrency: args.threads,
                request: backup_fuzz::RequestCtx {
                    limiter: request_limiter.clone(),
                    extra_headers: extra_headers.clone(),
                    cookie_header: initial_cookie_header.clone(),
                },
            };
            eprintln!("[+] backup discovery: host-derived candidates, auto-tuned per host");
            let path = backup_sidecar_path(args.output.as_deref());
            let mut backup_output: Option<std::fs::File> = None;
            let mut backup_header_printed = false;
            let show_backup_live = !args.no_live && !args.quiet;
            let found = backup_fuzz::run_phase(&hosts, &opts, |finding| {
                if show_backup_live {
                    backup_fuzz::print_confirmed_finding(finding, &mut backup_header_printed);
                }
                if backup_output.is_none() {
                    backup_output = Some(
                        std::fs::OpenOptions::new()
                            .create(true)
                            .write(true)
                            .truncate(true)
                            .open(&path)
                            .with_context(|| format!("open backup output {}", path))?,
                    );
                }
                let output = backup_output.as_mut().expect("backup output just opened");
                serde_json::to_writer(&mut *output, finding)?;
                writeln!(output)?;
                output.flush()?;
                Ok(())
            })
            .await?;
            if found > 0 {
                eprintln!("[+] backup findings: {} → {}", found, path);
            }
        }

        // --exclude-root-size: probe `/` once and add its CL to exclude_sizes.
        // v0.4.5 — measure the root page through the SAME impersonation pool,
        // `-H` headers and Accept profile the fuzz probes use, so the learned
        // size matches what fuzz actually sees. (The old plain non-impersonated
        // client could measure a different response on TLS-/header-sensitive
        // edges — a real inconsistency.) Pool is already initialised above via
        // `probe::init_pool`. Redirects off (matches fuzz default — a 3xx root
        // is a finding, not a body to measure).
        let mut exclude_sizes_by_origin: std::collections::HashMap<String, Vec<i64>> =
            std::collections::HashMap::new();
        if args.exclude_root_size {
            for h in &hosts {
                let url = if h.starts_with("http://") || h.starts_with("https://") {
                    h.trim_end_matches('/').to_string()
                } else {
                    format!("https://{}", h)
                };
                let Some(slot) = probe::pick_pool_slot_for(&fuzz::bare_host(&url)) else {
                    continue;
                };
                let response = probe::retry_wreq_pool_once(|| async {
                    let mut req = slot
                        .get(&url)
                        .redirect(wreq::redirect::Policy::none())
                        .header("Accept-Language", slot.accept_lang)
                        .header(
                            "Accept",
                            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                        );
                    for (n, v) in &extra_headers {
                        req = req.header(n.as_str(), v.as_str());
                    }
                    if let Some(cookie) = initial_cookie_header.as_deref() {
                        req = req.header("Cookie", cookie);
                    }
                    request_limiter.acquire(&fuzz::bare_host(&url)).await;
                    req.send().await
                })
                .await;
                match response {
                    Ok(Ok(resp)) => {
                        if !matches!(resp.status().as_u16(), 200..=399) {
                            continue;
                        }
                        let cl = resp
                            .headers()
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.parse::<i64>().ok());
                        let size = match cl {
                            Some(n) => n,
                            None => match probe::read_body_capped(resp, 256 * 1024).await {
                                Ok(b) if b.len() < 256 * 1024 => b.len() as i64,
                                Err(_) => -1,
                                _ => -1,
                            },
                        };
                        let origin = fuzz::origin_key(&url);
                        let root_sizes = exclude_sizes_by_origin.entry(origin).or_default();
                        if size > 0 && !root_sizes.contains(&size) {
                            eprintln!(
                                "[+] root-size {} → excluding {} bytes for this origin",
                                url, size
                            );
                            root_sizes.push(size);
                        }
                    }
                    Ok(Err(e)) => eprintln!(
                        "[!] root-size probe failed for {}: {} (skipping)",
                        url, e
                    ),
                    Err(()) => eprintln!(
                        "[!] root-size probe exhausted connection-pool retry for {} (skipping)",
                        url
                    ),
                }
            }
        }

        // Explicit dictionary entries are user intent and are always probed.
        // These patterns only prevent discovered directories from expanding
        // into another full wordlist pass.
        if (recursion_depth > 0 || crawl_enabled) && !exclude_subdirs.is_empty() {
            eprintln!(
                "[+] recursion excludes: {} patterns ({} mode; explicit wordlist entries remain enabled)",
                exclude_subdirs.len(),
                exclude_mode.as_str(),
            );
        }

        // Redirect following is an explicit advanced override. Crawling keeps
        // the original 3xx response for wildcard/output identity and queues
        // its Location as a separate discovery instead.
        let fuzz_follow_redirects = !args.no_follow_redirects && args.fuzz_follow_redirects;
        if args.no_follow_redirects && args.fuzz_follow_redirects {
            eprintln!(
                "[!] --no-follow-redirects overrides --fuzz-follow-redirects"
            );
        }

        let cfg = fuzz::FuzzCfg {
            match_codes,
            exclude_codes,
            body_preview_bytes: args.body_preview,
            wildcard_samples: 3,
            include_errors: args.include_errors,
            retries: args.retries,
            via_proxy: proxy_enabled,
            threads: args.threads,
            timeout_ms: args.timeout_ms,
            request_limiter: request_limiter.clone(),
            recursion_depth,
            recurse_on_200: args.recurse_on_200,
            recurse_on_403: args.recurse_on_403,
            // Auth-dir recursion is auto-on for 401. A 403 remains opt-in via
            // --recurse-on-403 because path-sensitive WAF denials are noisy.
            recurse_on_auth: true,
            // v0.4.5 — native 401/403 bypass is auto-on unless `--safe`.
            bypass_enabled: !args.safe,
            max_dirs_per_host: args.max_dirs_per_host,
            recursion_excludes: exclude_subdirs,
            recursion_exclude_mode: exclude_mode,
            crawl_enabled,
            crawl_depth,
            crawl_robots: true,
            crawl_sitemap: true,
            max_links_per_page: args.max_links_per_page,
            scope_hosts,
            exclude_sizes,
            exclude_sizes_by_origin,
            fuzz_follow_redirects,
            // Honour `--max-redirects` in fuzz mode too (was hardcoded to 10;
            // 10 is also the flag's default, so unchanged unless passed).
            max_redirects: args.max_redirects,
            initial_cookie_header: auth_ctx.initial_cookie_header(),
            extra_headers,
            output_format,
            live_findings: !args.no_live && !args.quiet,
            show_progress: !args.quiet,
            response_headers: args.response_headers,
            // Pipeline provenance tags — enrich mode already embedded these in
            // every record; fuzz mode used to drop them because the FuzzCfg is
            // built (and `run` returns) before the enrich path is reached.
            domain: args.domain.clone(),
            scan_id: args.scan_id.clone(),
            source_tools: args.source_tools.clone(),
        };

        // `no_resume` only drives the truncate-by-delete inside `run`; gate it
        // on the user having named an output file (see `user_named_output`).
        fuzz::run(
            &hosts,
            &words,
            cfg,
            output_path,
            args.no_resume && user_named_output,
            policy,
        )
        .await?;
        return Ok(());
    }

    let output_format = match args.format.as_deref() {
        Some(value) => fuzz::OutputFormat::from_cli(value)?,
        None => fuzz::OutputFormat::from_path(output_path),
    };

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
    } else if user_named_output {
        let _ = std::fs::remove_file(output_path);
    }
    if hosts.is_empty() {
        eprintln!("[+] nothing to do — exiting");
        return Ok(());
    }

    // 3. Load tech-detect engine (or not).
    let tech_engine: Option<techdetect::TechEngine> = if !tech_selection.enabled {
        None
    } else {
        let json = match tech_selection.fingerprints_path.as_deref() {
            Some(p) => std::fs::read_to_string(p).with_context(|| format!("read {}", p))?,
            None => EMBEDDED_FINGERPRINTS.to_string(),
        };
        Some(techdetect::TechEngine::from_json(&json).context("load fingerprints")?)
    };

    // 4. Kick off CDN fetch in the background while DNS resolves.
    let cdn_fut = cdn::load_cdn_table(args.no_cdn);

    // 5. DNS resolve everything (A+AAAA+CNAME).
    let resolver = dns::build_resolver(args.dns_timeout);
    let host_strings: Vec<String> = hosts.iter().map(|h| extract_dns_host(h)).collect();
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
    probe::init_pool(args.timeout_ms, args.no_impersonate, proxy_config)?;
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
    // v0.4.10 — copied out of `args` so it can move into each probe task.
    let want_response_headers = args.response_headers;
    let via_proxy = proxy_enabled;

    eprintln!(
        "[+] probing {} hosts ({} concurrent)…",
        hosts.len(),
        args.threads
    );

    let mut set: FuturesUnordered<tokio::task::JoinHandle<EnrichRecord>> = FuturesUnordered::new();
    let total = hosts.len();
    let max_inflight = args.threads.max(1);
    let mut processed = 0usize;
    let mut emitted = 0usize;
    let httpx_compat = args.httpx_compat;
    let live_only = args.live_only;
    let urls_only = args.urls_only;
    let live_findings = user_named_output && !args.no_live && !args.quiet;

    for input in hosts {
        let host = extract_host(&input);
        let dns_host = extract_dns_host(&input);
        let dns_rec = dns_map.get(&dns_host).cloned();
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

            // Split the DNS slice into IPv4/IPv6 for the `--httpx-compat`
            // path. Stored on the record as `#[serde(skip)]` so the default
            // shape is unaffected; converted at writer time.
            let (raw_ipv4, raw_ipv6): (Vec<String>, Vec<String>) = match dns_rec.as_ref() {
                Some(r) => {
                    let mut v4 = Vec::new();
                    let mut v6 = Vec::new();
                    for ip in r.ips.iter() {
                        match ip {
                            std::net::IpAddr::V4(a) => v4.push(a.to_string()),
                            std::net::IpAddr::V6(a) => v6.push(a.to_string()),
                        }
                    }
                    (v4, v6)
                }
                None => (Vec::new(), Vec::new()),
            };
            // `raw_input` mirrors httpx's `url` field — scheme + host. When
            // the user passed a bare hostname we default to `https://`
            // (matches httpx's scheme-less list behaviour).
            let raw_input =
                if url_or_host.starts_with("http://") || url_or_host.starts_with("https://") {
                    url_or_host.trim_end_matches('/').to_string()
                } else {
                    format!("https://{}", url_or_host.trim_end_matches('/'))
                };
            let (raw_scheme, raw_port, raw_path) = parse_url_parts(&raw_input);

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
                content_type: None,
                word_count: None,
                lines: None,
                server: None,
                location: None,
                title: None,
                final_url: None,
                redirect_chain: vec![],
                tech: String::new(),
                time: None,
                via_proxy,
                body: None,
                response_headers: Vec::new(),
                error: None,
                raw_ipv4,
                raw_ipv6,
                raw_input,
                successful_input_url: None,
                raw_scheme,
                raw_port,
                raw_path,
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
                    rec.successful_input_url = Some(r.probe_url.clone());
                    rec.content_length = r.content_length;
                    rec.content_type = r.content_type;
                    rec.word_count = Some(r.word_count);
                    rec.lines = Some(r.line_count);
                    rec.server = r.server;
                    rec.location = r.location;
                    rec.title = r.title;
                    rec.final_url = Some(observed_probe_url(
                        &url_or_host,
                        r.final_url.as_deref(),
                        r.via_https,
                    ));
                    rec.redirect_chain = r.chain;
                    rec.time = Some(probe::format_elapsed_go(r.elapsed));
                    // If the final URL we settled on differs in scheme /
                    // port / path from the input, surface the FINAL values
                    // — that's what httpx does (`scheme`/`port`/`path`
                    // reflect the URL whose response we're describing).
                    if let Some(final_url) = rec.final_url.as_deref() {
                        let (s, p, pth) = parse_url_parts(final_url);
                        rec.raw_scheme = s;
                        rec.raw_port = p;
                        rec.raw_path = pth;
                    }
                    if let Some(engine) = tech_engine.as_ref() {
                        let matches = engine.detect(&r.headers, &r.cookies, &r.body);
                        rec.tech = techdetect::render_tech(&matches);
                    }
                    // v0.4.10 — `--response-headers` in ENRICH mode. Headers were
                    // already captured for tech-detect (probe.rs), so this costs
                    // nothing extra; previously the flag was silently ignored
                    // outside fuzz mode. Printed per-host to stderr as well, so
                    // `httpxer -u https://x --rh` is useful without an -o file.
                    if want_response_headers {
                        if !r.headers.is_empty() {
                            let mut out = String::new();
                            use std::fmt::Write as _;
                            let _ = writeln!(
                                out,
                                "{} [{}]",
                                rec.final_url.as_deref().unwrap_or(&rec.subdomain),
                                r.status_code
                            );
                            for (k, v) in &r.headers {
                                let _ = writeln!(out, "      {}: {}", k, v);
                            }
                            eprint!("{}", out);
                        }
                        rec.response_headers = r.headers;
                    }
                    if with_body {
                        rec.body = Some(r.body);
                    }
                }
            }
            rec
        }));

        // Keep completed response bodies and records bounded by concurrency.
        // Previously every input host was spawned before the first result was
        // drained, so a very large host list could retain one task per host.
        if set.len() >= max_inflight {
            if let Some(joined) = set.next().await {
                write_enrich_result(
                    joined,
                    &mut out_file,
                    output_format,
                    httpx_compat,
                    live_only,
                    urls_only,
                    live_findings,
                    &mut processed,
                    &mut emitted,
                    total,
                    args.quiet,
                )?;
            }
        }
    }

    // 9. Drain — write each record as it completes (crash-safe, no buffered
    //    tail). JSON output is reshaped just before serialisation when
    //    `--httpx-compat` is set; plain output uses the compact live line.
    while let Some(joined) = set.next().await {
        write_enrich_result(
            joined,
            &mut out_file,
            output_format,
            httpx_compat,
            live_only,
            urls_only,
            live_findings,
            &mut processed,
            &mut emitted,
            total,
            args.quiet,
        )?;
    }
    out_file.flush()?;
    eprintln!(
        "[+] done: processed {} hosts; wrote {} records to {}",
        processed, emitted, output_path
    );
    let (pool_retries, pool_failures) = probe::wreq_pool_panic_stats();
    if pool_retries > 0 {
        eprintln!(
            "[+] connection-pool resilience: {} probe(s) hit the wreq pool race and were retried; {} still failed after retry",
            pool_retries, pool_failures
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic EnrichRecord with both IPv4 and IPv6 in the raw
    /// DNS slice, plus a comma-joined tech list — enough to exercise every
    /// field the httpx-compat conversion reshapes.
    fn sample_enrich() -> EnrichRecord {
        EnrichRecord {
            subdomain: "target.com".into(),
            domain: Some("target.com".into()),
            scan_id: Some("scan_1".into()),
            source_tools: Some("subfinder".into()),
            ip: "1.2.3.4".into(),
            cname: "alias.example.com".into(),
            cdn: "cloudflare".into(),
            status_code: Some(200),
            content_length: Some(1234),
            content_type: Some("text/html".into()),
            word_count: Some(56),
            lines: Some(7),
            server: Some("nginx".into()),
            location: None,
            title: Some("Example".into()),
            final_url: Some("https://target.com/".into()),
            redirect_chain: vec!["https://target.com".into()],
            tech: "Nginx, HSTS, HTTP/3".into(),
            time: Some("100ms".into()),
            via_proxy: true,
            body: None,
            response_headers: Vec::new(),
            error: None,
            raw_ipv4: vec!["1.2.3.4".into(), "1.2.3.5".into()],
            raw_ipv6: vec!["2001:db8::1".into()],
            raw_input: "https://target.com".into(),
            successful_input_url: Some("https://target.com".into()),
            raw_scheme: "https".into(),
            raw_port: "443".into(),
            raw_path: "/".into(),
        }
    }

    /// Default enrich shape: `subdomain` present, `tech` is a string,
    /// `ip` is the singular first-resolved IP. No httpx-only fields leak.
    #[test]
    fn enrich_default_shape_has_subdomain_and_string_tech() {
        let rec = sample_enrich();
        let s = serde_json::to_string(&rec).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["subdomain"], "target.com");
        assert_eq!(v["ip"], "1.2.3.4");
        assert_eq!(v["cname"], "alias.example.com");
        assert_eq!(v["tech"], "Nginx, HSTS, HTTP/3");
        // No httpx-only fields in the default shape.
        assert!(v.get("input").is_none());
        assert!(v.get("a").is_none());
        assert!(v.get("aaaa").is_none());
        assert!(v.get("host_ip").is_none());
        assert!(v.get("webserver").is_none());
        // The `#[serde(skip)]` internals must not leak either.
        assert!(v.get("raw_ipv4").is_none());
        assert!(v.get("raw_ipv6").is_none());
        assert!(v.get("raw_input").is_none());
    }

    /// httpx-compat shape: `input` = bare hostname (parity with httpx),
    /// `host` mirrors it, `url` carries the full URL, `scheme`/`port`/`path`
    /// are broken out. `a` + `aaaa` arrays, `cname` + `tech` arrays,
    /// `webserver` mirrors `server`, `host_ip` is the first A, `cdn_name` +
    /// `cdn_type` accompany `cdn`. `words` replaces `word_count` (httpx
    /// field name); `lines`, `content_type`, `time`, `timestamp`, `method`,
    /// `failed` are present.
    #[test]
    fn compat_shape_matches_httpx_field_names() {
        let rec = sample_enrich();
        let compat = HttpxCompatRecord::from_enrich(rec);
        let s = serde_json::to_string(&compat).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        // Loadbearing DB-bug-fix invariants:
        assert!(v.get("subdomain").is_none());
        assert_eq!(v["input"], "target.com", "input must be bare hostname");
        assert_eq!(v["host"], "target.com", "host must be bare hostname");
        assert_eq!(v["url"], "https://target.com", "url is the full URL");
        // URL components broken out.
        assert_eq!(v["scheme"], "https");
        assert_eq!(v["port"], "443");
        assert_eq!(v["path"], "/");
        assert_eq!(v["method"], "GET");
        // ip → a / aaaa arrays.
        assert!(v.get("ip").is_none());
        assert_eq!(v["a"], serde_json::json!(["1.2.3.4", "1.2.3.5"]));
        assert_eq!(v["aaaa"], serde_json::json!(["2001:db8::1"]));
        // cname → array.
        assert_eq!(v["cname"], serde_json::json!(["alias.example.com"]));
        // tech → array (split on `, `).
        assert_eq!(v["tech"], serde_json::json!(["Nginx", "HSTS", "HTTP/3"]));
        // webserver + server both present, same value.
        assert_eq!(v["server"], "nginx");
        assert_eq!(v["webserver"], "nginx");
        // host_ip = first A.
        assert_eq!(v["host_ip"], "1.2.3.4");
        // CDN trio.
        assert_eq!(v["cdn"], "cloudflare");
        assert_eq!(v["cdn_name"], "cloudflare");
        assert_eq!(v["cdn_type"], "cdn");
        // Response stats.
        assert_eq!(v["status_code"], 200);
        assert_eq!(v["content_length"], 1234);
        assert_eq!(v["content_type"], "text/html");
        // word_count → "words" rename.
        assert_eq!(v["words"], 56);
        assert!(v.get("word_count").is_none());
        assert_eq!(v["lines"], 7);
        // Title + final URL.
        assert_eq!(v["title"], "Example");
        assert_eq!(v["final_url"], "https://target.com/");
        assert_eq!(
            v["redirect_chain"],
            serde_json::json!(["https://target.com"])
        );
        // Probe-status fields.
        assert_eq!(v["time"], "100ms");
        assert_eq!(v["failed"], false);
        assert!(v["timestamp"].as_str().unwrap().contains("T"));
        // Embedded metadata.
        assert_eq!(v["via_proxy"], true);
        assert_eq!(v["domain"], "target.com");
        assert_eq!(v["scan_id"], "scan_1");
        assert_eq!(v["source_tools"], "subfinder");
    }

    /// `cdn_type_for` maps the four provider names httpxer recognises onto
    /// the `cdn` / `cloud` categories ProjectDiscovery's cdncheck uses.
    #[test]
    fn cdn_type_categories_match_httpx() {
        assert_eq!(cdn_type_for("cloudflare"), "cdn");
        assert_eq!(cdn_type_for("cloudfront"), "cdn");
        assert_eq!(cdn_type_for("fastly"), "cdn");
        assert_eq!(cdn_type_for("aws"), "cloud");
        assert_eq!(cdn_type_for("google"), "cloud");
        assert_eq!(cdn_type_for(""), "");
        assert_eq!(cdn_type_for("unknown"), "");
    }

    /// `failed:true` records carry an empty `time` string but the field
    /// must still be present (httpx parity — `failed` and `time` are
    /// always emitted).
    #[test]
    fn compat_shape_marks_failed_records() {
        let mut rec = sample_enrich();
        rec.status_code = None;
        rec.time = None;
        rec.error = Some("dns: no records".into());
        let compat = HttpxCompatRecord::from_enrich(rec);
        let s = serde_json::to_string(&compat).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["failed"], true);
        assert_eq!(v["time"], "");
        assert_eq!(v["error"], "dns: no records");
    }

    /// Endpoint identity strips path/query/fragment but preserves a
    /// non-default port for resume and output records.
    #[test]
    fn extract_host_strips_path_query_fragment() {
        assert_eq!(extract_host("https://foo.com/bar"), "foo.com");
        assert_eq!(extract_host("http://foo.com?x=1"), "foo.com");
        assert_eq!(extract_host("https://foo.com#section"), "foo.com");
        assert_eq!(extract_host("https://foo.com?x=1#section"), "foo.com");
        assert_eq!(extract_host("https://foo.com:8080/bar"), "foo.com:8080");
        assert_eq!(extract_host("foo.com:8080/path"), "foo.com:8080");
        assert_eq!(extract_host("foo.com:443"), "foo.com");
        assert_eq!(extract_host("foo.com:80"), "foo.com:80");
        assert_eq!(extract_host("foo.com"), "foo.com");
    }

    #[test]
    fn observed_probe_url_tracks_https_to_http_fallback() {
        assert_eq!(
            observed_probe_url("target.test:8080", None, false),
            "http://target.test:8080"
        );
        assert_eq!(
            observed_probe_url("target.test", None, true),
            "https://target.test"
        );
        assert_eq!(
            observed_probe_url("https://target.test:8443/path", None, false),
            "http://target.test:8443/path"
        );
        assert_eq!(
            observed_probe_url(
                "https://target.test",
                Some("http://redirect.test/final"),
                true,
            ),
            "http://redirect.test/final"
        );
    }

    #[test]
    fn dns_host_strips_ports_without_collapsing_endpoint_identity() {
        assert_eq!(extract_dns_host("https://foo.com:8080/bar"), "foo.com");
        assert_eq!(extract_dns_host("foo.com:8443/path"), "foo.com");
        assert_ne!(
            extract_host("foo.com:8080"),
            extract_host("foo.com:8443")
        );
    }

    #[test]
    fn resume_reader_accepts_native_and_httpx_compat_records() {
        let path = std::env::temp_dir().join(format!(
            "httpxer-enrich-resume-{}-{}.jsonl",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::write(
            &path,
            concat!(
                "{\"subdomain\":\"native.test\"}\n",
                "{\"host\":\"compat.test\",\"input\":\"compat.test\"}\n",
                "{\"input\":\"https://input.test:8443/a\"}\n",
                "200     1KB  https://plain.test/  Plain title\n",
                "https://url-only.test/\n"
            ),
        )
        .unwrap();
        let hosts = read_existing_subdomains(path.to_str().unwrap());
        assert!(hosts.contains("native.test"));
        assert!(hosts.contains("compat.test"));
        assert!(hosts.contains("input.test:8443"));
        assert!(hosts.contains("plain.test"));
        assert!(hosts.contains("url-only.test"));
        let _ = std::fs::remove_file(path);
    }

    /// `banner_should_show_early` suppresses on suppression flags, lets
    /// everything else through. The TTY arm is environment-dependent
    /// (cargo test runs without a TTY); we test the flag-scan logic by
    /// asserting suppression flags ALWAYS return false regardless of TTY.
    #[test]
    fn banner_suppression_flags_block_banner() {
        // Suppression flags must always return false (TTY or no TTY).
        assert!(!banner_should_show_early(&["httpxer".into(), "-q".into()]));
        assert!(!banner_should_show_early(&["httpxer".into(), "--quiet".into()]));
        assert!(!banner_should_show_early(&["httpxer".into(), "--no-art".into()]));
        // Multi-arg cases — suppression flag anywhere blocks.
        assert!(!banner_should_show_early(&[
            "httpxer".into(),
            "-u".into(),
            "https://x.com".into(),
            "--no-art".into(),
            "-o".into(),
            "out.json".into(),
        ]));
    }

    /// host_ip falls back to the first AAAA when no A record exists.
    /// Empty tech maps to `[]`, not `[""]`. Empty cname maps to `[]`.
    #[test]
    fn compat_shape_handles_edge_cases() {
        let mut rec = sample_enrich();
        rec.raw_ipv4.clear();
        rec.tech.clear();
        rec.cname.clear();
        let compat = HttpxCompatRecord::from_enrich(rec);
        let s = serde_json::to_string(&compat).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        // host_ip falls back to first AAAA.
        assert_eq!(v["host_ip"], "2001:db8::1");
        assert_eq!(v["a"], serde_json::json!([]));
        assert_eq!(v["aaaa"], serde_json::json!(["2001:db8::1"]));
        // Empty tech → empty array, not `[""]`.
        assert_eq!(v["tech"], serde_json::json!([]));
        // Empty cname → empty array.
        assert_eq!(v["cname"], serde_json::json!([]));
    }

    fn cli(parts: &[&str]) -> Vec<String> {
        std::iter::once("httpxer".to_string())
            .chain(parts.iter().map(|part| part.to_string()))
            .collect()
    }

    #[test]
    fn normalize_preserves_attached_values_and_short_clusters() {
        assert_eq!(normalize_args(cli(&["-t150", "-u", "x.test"])), cli(&["-t150", "-u", "x.test"]));
        assert_eq!(normalize_args(cli(&["-R3", "-u", "x.test"])), cli(&["-R3", "-u", "x.test"]));
        assert_eq!(normalize_args(cli(&["-rq", "-u", "x.test"])), cli(&["-rq", "-u", "x.test"]));
    }

    #[test]
    fn normalize_only_rewrites_registered_compatibility_names() {
        assert_eq!(normalize_args(cli(&["-fr", "-u", "x.test"])), cli(&["--fr", "-u", "x.test"]));
        assert_eq!(normalize_args(cli(&["-path", "words.txt", "-u", "x.test"])), cli(&["--path", "words.txt", "-u", "x.test"]));
        assert_eq!(normalize_args(cli(&["--", "-fr"])), cli(&["--", "-fr"]));
    }

    #[test]
    fn clap_accepts_attached_and_clustered_short_syntax() {
        let args = Args::try_parse_from(normalize_args(cli(&[
            "-t150", "-rq", "-R3", "-u", "x.test",
        ])))
        .unwrap();
        assert_eq!(args.threads, 150);
        assert!(args.recursive);
        assert!(args.quiet);
        assert_eq!(args.recursion_depth, Some(3));
    }

    #[test]
    fn status_selector_supports_classes_and_inline_exclusions() {
        let (included, excluded) = parse_status_selector("2xx,301,302,!204,!429").unwrap();
        assert!(included.contains(&200));
        assert!(included.contains(&299));
        assert!(included.contains(&301));
        assert_eq!(excluded, vec![204, 429]);
        assert_eq!(parse_status_selector("6xx").unwrap().0.len(), 100);
        assert!(parse_status_selector("!4xx").is_err());
        assert!(parse_status_selector("200,bad").is_err());
    }

    #[test]
    fn canonical_status_rejects_legacy_filter_mix() {
        assert!(resolve_status_filters(Some("2xx"), Some("200"), None, None).is_err());
        let (included, excluded) = resolve_status_filters(None, None, None, None).unwrap();
        assert_eq!(included, vec![200, 301, 302, 307, 308, 401, 403]);
        assert!(excluded.is_empty());
    }

    #[test]
    fn backup_mode_resolves_legacy_aliases_without_ambiguity() {
        assert_eq!(resolve_backup_mode("auto", false, false).unwrap(), BackupMode::Auto);
        assert_eq!(resolve_backup_mode("off", false, false).unwrap(), BackupMode::Off);
        assert_eq!(resolve_backup_mode("auto", false, true).unwrap(), BackupMode::DryRun);
        assert!(resolve_backup_mode("off", false, true).is_err());
        assert!(resolve_backup_mode("auto", true, true).is_err());
    }

    #[test]
    fn depth_shortcuts_preserve_legacy_and_new_forms() {
        let legacy = Args::try_parse_from(normalize_args(cli(&[
            "-r", "-R", "2", "-u", "x.test",
        ])))
        .unwrap();
        assert_eq!(resolve_scan_depths(&legacy), (2, false, 0));

        let deep = Args::try_parse_from(normalize_args(cli(&[
            "--deep", "4", "-u", "x.test",
        ])))
        .unwrap();
        assert_eq!(resolve_scan_depths(&deep), (4, true, 4));

        let crawl = Args::try_parse_from(normalize_args(cli(&[
            "--crawl", "-u", "x.test",
        ])))
        .unwrap();
        assert_eq!(resolve_scan_depths(&crawl), (0, true, 3));
    }

    #[test]
    fn tech_selection_and_backup_sidecar_are_explicit() {
        assert_eq!(
            resolve_tech_selection(Some("off"), false, None).unwrap(),
            TechSelection { enabled: false, fingerprints_path: None }
        );
        assert_eq!(
            resolve_tech_selection(Some("custom.json"), false, None).unwrap(),
            TechSelection { enabled: true, fingerprints_path: Some("custom.json".into()) }
        );
        assert!(resolve_tech_selection(Some("off"), true, None).is_err());
        assert_eq!(backup_sidecar_path(None), "httpxer-backup.jsonl");
        assert_eq!(backup_sidecar_path(Some("hits.jsonl")), "hits.jsonl.backup.jsonl");
    }

    #[test]
    fn backup_dry_run_suppresses_startup_update_check() {
        assert!(!update_check_allowed_early(&cli(&["--backup", "dry-run"])));
        assert!(!update_check_allowed_early(&cli(&["--backup=dry-run"])));
        assert!(!update_check_allowed_early(&cli(&["--backup-dry-run"])));
    }

    #[test]
    fn fuzz_only_options_fail_in_enrich_mode() {
        let args = Args::try_parse_from(normalize_args(cli(&[
            "-u", "x.test", "--deep", "2",
        ])))
        .unwrap();
        assert!(validate_mode_specific_args(&args).is_err());

        let args = Args::try_parse_from(normalize_args(cli(&[
            "-u", "x.test", "-w", "words.txt", "--deep", "2",
        ])))
        .unwrap();
        assert!(validate_mode_specific_args(&args).is_ok());
    }

    #[test]
    fn live_only_is_probe_only_and_plain_format_works_in_probe_mode() {
        let args = Args::try_parse_from(normalize_args(cli(&[
            "-u", "x.test", "--live-only", "--format", "plain",
        ])))
        .unwrap();
        assert!(args.live_only);
        assert!(validate_mode_specific_args(&args).is_ok());
        assert_eq!(
            fuzz::OutputFormat::from_cli(args.format.as_deref().unwrap()).unwrap(),
            fuzz::OutputFormat::Plain
        );

        let fuzz_args = Args::try_parse_from(normalize_args(cli(&[
            "-u", "x.test", "-w", "words.txt", "--live-only",
        ])))
        .unwrap();
        assert!(validate_mode_specific_args(&fuzz_args).is_err());
    }

    #[test]
    fn urls_only_is_probe_only_and_rejects_structured_output_flags() {
        let args = Args::try_parse_from(normalize_args(cli(&[
            "-u", "x.test", "--urls-only",
        ])))
        .unwrap();
        assert!(args.urls_only);
        assert!(validate_mode_specific_args(&args).is_ok());

        let fuzz_args = Args::try_parse_from(normalize_args(cli(&[
            "-u", "x.test", "-w", "words.txt", "--urls-only",
        ])))
        .unwrap();
        assert!(validate_mode_specific_args(&fuzz_args).is_err());

        let format_args = Args::try_parse_from(normalize_args(cli(&[
            "-u", "x.test", "--urls-only", "--format", "json",
        ])))
        .unwrap();
        assert!(validate_mode_specific_args(&format_args).is_err());
    }

    #[test]
    fn legacy_dirsearch_style_command_still_parses() {
        let args = Args::try_parse_from(normalize_args(cli(&[
            "-u", "https://x.test", "-w", "a.txt,b.txt", "-t150", "-r", "-R3",
            "--recurse-on-200", "--max-dirs-per-host", "1000", "--add-excludes",
            "assets,images", "--exclude-mode", "substring", "--exclude-root-size",
            "--wildcard-policy", "strict", "--crawl", "-i", "200,301,302,307,308",
            "--exclude", "429,503", "--retries", "2", "-q", "-o", "out.txt",
        ])))
        .unwrap();
        assert_eq!(args.threads, 150);
        assert_eq!(resolve_scan_depths(&args), (3, true, 3));
        assert_eq!(resolve_backup_mode(&args.backup, args.no_backup_fuzz, args.backup_dry_run).unwrap(), BackupMode::Auto);
        let (included, excluded) = resolve_status_filters(
            args.status.as_deref(),
            args.match_codes.as_deref(),
            args.include_status.as_deref(),
            args.exclude_codes.as_deref(),
        )
        .unwrap();
        assert_eq!(included, vec![200, 301, 302, 307, 308]);
        assert_eq!(excluded, vec![429, 503]);
    }

    #[test]
    fn short_help_is_task_oriented_and_hides_advanced_flags() {
        let mut command = Args::command();
        let mut output = Vec::new();
        command.write_help(&mut output).unwrap();
        let help = String::from_utf8(output).unwrap();

        for tag in [
            "[PROBE]",
            "[LIVE]",
            "[URLS]",
            "[TECH]",
            "[HEADERS]",
            "[FUZZ]",
            "[PROXY]",
            "[BACKUP]",
        ] {
            assert!(help.contains(tag), "short help is missing {tag}");
        }
        assert!(help.contains("Use `httpxer --help` for advanced options"));
        assert!(!help.contains("--dns-concurrency"));
        assert!(!help.contains("--exclude-root-size"));
    }

    #[test]
    fn long_help_keeps_advanced_options_and_practical_examples() {
        let mut command = Args::command();
        let mut output = Vec::new();
        command.write_long_help(&mut output).unwrap();
        let help = String::from_utf8(output).unwrap();

        for section in [
            "PRACTICAL EXAMPLES",
            "PROBE AND TECHNOLOGY",
            "HEADERS AND BODY",
            "PATH FUZZING",
            "RECURSION AND CRAWL",
            "PROXY AND ROTATION",
        ] {
            assert!(help.contains(section), "long help is missing {section}");
        }
        assert!(help.contains("--dns-concurrency"));
        assert!(help.contains("--exclude-root-size"));
        assert!(help.contains("--with-body"));
    }

    #[test]
    fn enrich_plain_output_contains_status_url_and_safe_title() {
        let mut rec = sample_enrich();
        rec.title = Some("Example\nInjected".into());
        let line = format_enrich_plain(&rec);
        assert_eq!(line, "200     1KB  https://target.com/  Example Injected");
        assert!(!line.contains('\n'));
    }

    #[test]
    fn enrich_live_only_skips_failed_records_and_advances_progress() {
        let mut rec = sample_enrich();
        rec.status_code = None;
        rec.content_length = None;
        rec.final_url = None;
        rec.title = None;
        rec.error = Some("dns: no records".into());

        let mut output = Vec::new();
        let mut processed = 0;
        let mut emitted = 0;
        write_enrich_result(
            Ok(rec),
            &mut output,
            fuzz::OutputFormat::Plain,
            false,
            true,
            false,
            false,
            &mut processed,
            &mut emitted,
            1,
            true,
        )
        .unwrap();

        assert!(output.is_empty());
        assert_eq!(processed, 1);
        assert_eq!(emitted, 0);
    }

    #[test]
    fn enrich_plain_output_keeps_failures_without_live_only() {
        let mut rec = sample_enrich();
        rec.status_code = None;
        rec.content_length = None;
        rec.final_url = None;
        rec.title = None;
        rec.error = Some("dns: no records".into());

        let mut output = Vec::new();
        let mut processed = 0;
        let mut emitted = 0;
        write_enrich_result(
            Ok(rec),
            &mut output,
            fuzz::OutputFormat::Plain,
            false,
            false,
            false,
            false,
            &mut processed,
            &mut emitted,
            1,
            true,
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "ERR      --  https://target.com  dns: no records\n"
        );
        assert_eq!(processed, 1);
        assert_eq!(emitted, 1);
    }

    #[test]
    fn enrich_urls_only_writes_one_responsive_url_per_line() {
        let mut rec = sample_enrich();
        rec.final_url = Some("https://login.example.net/login?next=%2Fadmin".into());
        let mut output = Vec::new();
        let mut processed = 0;
        let mut emitted = 0;

        write_enrich_result(
            Ok(rec),
            &mut output,
            fuzz::OutputFormat::Json,
            false,
            false,
            true,
            false,
            &mut processed,
            &mut emitted,
            1,
            true,
        )
        .unwrap();

        assert_eq!(String::from_utf8(output).unwrap(), "https://target.com\n");
        assert_eq!(processed, 1);
        assert_eq!(emitted, 1);
    }

    #[test]
    fn enrich_urls_only_preserves_non_default_ports_and_ipv6() {
        let mut rec = sample_enrich();
        rec.successful_input_url = Some("http://target.com:8080/path".into());
        assert_eq!(format_enrich_url_origin(&rec), "http://target.com:8080");

        rec.successful_input_url = Some("https://[2001:db8::1]:8443/a".into());
        assert_eq!(format_enrich_url_origin(&rec), "https://[2001:db8::1]:8443");
    }

    #[test]
    fn enrich_urls_only_omits_unresponsive_hosts() {
        let mut rec = sample_enrich();
        rec.status_code = None;
        rec.final_url = None;
        rec.error = Some("dns: no records".into());
        let mut output = Vec::new();
        let mut processed = 0;
        let mut emitted = 0;

        write_enrich_result(
            Ok(rec),
            &mut output,
            fuzz::OutputFormat::Plain,
            false,
            false,
            true,
            false,
            &mut processed,
            &mut emitted,
            1,
            true,
        )
        .unwrap();

        assert!(output.is_empty());
        assert_eq!(processed, 1);
        assert_eq!(emitted, 0);
    }

    #[derive(Default)]
    struct FlushTrackingWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl std::io::Write for FlushTrackingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn realtime_writer_flushes_every_record() {
        let mut writer = FlushTrackingWriter::default();
        write_realtime_line(&mut writer, "{\"status_code\":200}").unwrap();
        assert_eq!(writer.bytes, b"{\"status_code\":200}\n");
        assert_eq!(writer.flushes, 1);
    }
}
