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
    about = "HTTP probe + path fuzzer with browser-grade TLS impersonation.",
    long_about = "HTTP probe + path fuzzer with browser-grade TLS impersonation.\n\n\
        TWO MODES — chosen automatically:\n  \
          ENRICH (default)  no -w  →  one probe per host: status, title, server, tech, IP, CDN\n  \
          FUZZ              -w set →  host × wordlist path scan, with wildcard suppression",
    after_help = "\x1b[1mQUICK START\x1b[0m\n  \
  httpxer -u example.com                          probe one host\n  \
  httpxer -l hosts.txt -o out.json                probe a list → NDJSON\n  \
  httpxer -u example.com -w paths.txt             fuzz paths on one host\n\n\
\x1b[1mFINGERPRINT / RECON (enrich)\x1b[0m\n  \
  httpxer -u example.com --rh                     show all response headers\n  \
  httpxer -l hosts.txt --no-cdn --no-tech         fast: skip CDN + tech-detect\n  \
  httpxer -l hosts.txt --httpx-compat -o out.json httpx-shaped JSON (drop-in)\n  \
  cat subs.txt | httpxer -l - -o live.json        pipe from subfinder/amass\n\n\
\x1b[1mDIRECTORY BRUTEFORCE\x1b[0m\n  \
  \x1b[2m# start here — sane defaults, wildcard auto-suppressed\x1b[0m\n  \
  httpxer -u https://t.com -w common.txt -o found.txt\n\n  \
  \x1b[2m# hide 401/403 auth walls, keep real hits\x1b[0m\n  \
  httpxer -u https://t.com -w common.txt -i 200,301,302,307,308 -o found.txt\n\n  \
  \x1b[2m# several wordlists at once (comma-separated, merged + deduped)\x1b[0m\n  \
  httpxer -u https://t.com -w admin.txt,api.txt,backup.txt -o found.txt\n\n  \
  \x1b[2m# recurse 3 levels into every directory found\x1b[0m\n  \
  httpxer -u https://t.com -w common.txt -r -R 3 --r200 -o found.txt\n\n  \
  \x1b[2m# full recon: recursion + crawl HTML/robots.txt/sitemap.xml\x1b[0m\n  \
  httpxer -u https://t.com -w common.txt -r -R 3 --crawl -o found.txt\n\n  \
  \x1b[2m# behind auth\x1b[0m\n  \
  httpxer -u https://t.com -w common.txt --bearer $TOKEN -o found.txt\n\n  \
  \x1b[2m# many hosts from a file, slow + polite\x1b[0m\n  \
  httpxer -l hosts.txt -w common.txt -t 50 --rl 10 -o found.txt\n\n  \
  \x1b[2m# out-of-scope program? turn the 401/403 bypass probes off\x1b[0m\n  \
  httpxer -u https://t.com -w common.txt --safe -o found.txt\n\n\
\x1b[1mAUTHENTICATED SCANS\x1b[0m  (work in BOTH modes)\n  \
  httpxer -u https://t.com --bearer $TOKEN -w w.txt\n  \
  httpxer -u https://t.com -H 'X-API-Key: k' --cookie 'sid=abc'\n\n\
\x1b[1mTOO MUCH NOISE?\x1b[0m\n  \
  --wildcard-policy strict   (default) auto-suppress catchall/soft-404 pages\n  \
  -i 200,301,302,307,308     only these codes (hides 401/403 auth walls)\n  \
  --exclude-root-size        drop pages the size of the homepage\n  \
  --exclude-sizes 1234,5678  drop exact byte sizes\n\n\
\x1b[1mSHORT FORMS\x1b[0m  (long names all still work)\n  \
  --wp  wildcard-policy    --md  max-dirs-per-host   --to  timeout-ms\n  \
  --rd  recursion-depth    --xa  add-excludes        --mr  max-redirects\n  \
  --es  exclude-sizes      --xm  exclude-mode        --rl  rate-limit\n  \
  --ers exclude-root-size  --cd  crawl-depth         --bp  body-preview\n  \
  --r200/--r403 recurse-on-200/403                   --rh  response-headers\n\n\
\x1b[1mOUTPUT\x1b[0m\n  \
  -o out.json    NDJSON, one record per line (default)\n  \
  -o out.txt     plain 'STATUS SIZE URL' lines (auto-detected from .txt)\n  \
  --rh           add every response header to terminal + JSON\n  \
  -q             quiet: no banner, no update check\n\n\
Docs: https://github.com/assassin-marcos/httpxer"
)]
struct Args {
    /// Input file (one hostname/URL per line, "-" for stdin). Either `-l`
    /// or `-u` is required (mutually compatible — `-u` is a one-host
    /// shortcut).
    #[arg(short = 'l', long, alias = "list",
          required_unless_present_any = ["update", "check_update", "uninstall", "target"])]
    input: Option<String>,

    /// Output NDJSON file
    #[arg(short = 'o', long, alias = "output")]
    output: Option<String>,

    /// Concurrent HTTP probes (matches httpx -t default)
    #[arg(short = 't', long, default_value_t = 250)]
    threads: usize,

    /// Per-probe HTTP timeout (ms)
    #[arg(visible_alias = "to", long, default_value_t = 5000)]
    timeout_ms: u64,

    /// Don't follow redirects (default: follow up to --max-redirects hops, matches httpx -fr)
    #[arg(visible_alias = "nfr", long)]
    no_follow_redirects: bool,

    /// (enrich) Max redirect hops to chase. SSO chains often need 4-6.
    #[arg(visible_alias = "mr", long, default_value_t = 10)]
    max_redirects: usize,

    /// Concurrent DNS lookups
    #[arg(visible_alias = "dc", long, default_value_t = 100)]
    dns_concurrency: usize,

    /// DNS timeout per lookup (seconds)
    #[arg(visible_alias = "dt", long, default_value_t = 3)]
    dns_timeout: u64,

    /// Embed in every output record under "domain"
    #[arg(long)]
    domain: Option<String>,

    /// Embed in every output record under "scan_id"
    #[arg(visible_alias = "sid", long)]
    scan_id: Option<String>,

    /// Embed in every output record under "source_tools" (e.g. "subfinder,amass")
    #[arg(visible_alias = "stools", long)]
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
    #[arg(visible_alias = "ni", long)]
    no_impersonate: bool,

    /// Include response body (capped at 2 MiB) in each output record under
    /// the `body` field. Useful for debugging fingerprint-echo endpoints
    /// (tls.peet.ws, ja3er.com) or archiving raw HTML. Off by default —
    /// keeps output files small.
    #[arg(visible_alias = "wb", long)]
    with_body: bool,

    /// Emit enrich-mode records in ProjectDiscovery httpx's JSON shape
    /// instead of the default httpxer shape. Differences in compat mode:
    /// `input` (URL with scheme) replaces `subdomain`; `a` / `aaaa` arrays
    /// replace the single `ip` string; `cname` becomes an array; `tech`
    /// becomes a string array (split from the comma-joined form);
    /// `webserver` is emitted alongside `server`; `host_ip` is added as
    /// the first A record (or first AAAA when no A is present).
    /// Inert in fuzz mode (the fuzz schema is already httpx-shaped).
    #[arg(long = "httpx-compat", visible_alias = "hc")]
    httpx_compat: bool,

    // ── Fuzz-mode flags (v0.3.0+) ──────────────────────────────────────
    // Presence of `-path / --paths` switches the binary from enrich mode
    // (1 probe per host) into fuzz mode (host × wordlist Cartesian probe).
    // All flags below are inert in enrich mode.
    /// Wordlist file (one path per line) — when set, switches to fuzz mode
    /// (host × path probe). Empty paths and `#` comments are skipped.
    /// v0.3.7 also accepts `-w` / `--wordlist` / `--wordlists` for
    /// dirsearch-muscle-memory compat (all aliases point at the same flag).
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

    /// (fuzz) Comma-separated status codes to emit
    #[arg(
        long = "match-codes",

        default_value = "200,301,302,307,308,401,403",
        help_heading = "Fuzz mode"
    )]
    match_codes: String,

    /// (fuzz) Body preview length in bytes (HTML-entity-encoded in output)
    #[arg(
        long = "body-preview", visible_alias = "bp",
        default_value_t = 8192,
        help_heading = "Fuzz mode"
    )]
    body_preview: usize,

    /// (fuzz) Wildcard suppression policy: strict|mark|off
    #[arg(
        long = "wildcard-policy", visible_alias = "wp",
        default_value = "strict",
        help_heading = "Fuzz mode"
    )]
    wildcard_policy: String,

    /// (fuzz) Shortcut for `--wildcard-policy off`
    #[arg(long = "no-wildcard", help_heading = "Fuzz mode")]
    no_wildcard: bool,

    /// (fuzz) Safe mode: disable the native, auto 401/403 bypass engine
    /// (path-override headers + path mutations on forbidden responses).
    /// Use on programs/targets where bypass attempts are out of scope.
    #[arg(long = "safe", help_heading = "Fuzz mode")]
    safe: bool,

    /// (fuzz) Per-host requests/sec ceiling. 0 = disabled (default).
    #[arg(long = "rate-limit", visible_alias = "rl", default_value_t = 0.0, help_heading = "Fuzz mode")]
    rate_limit: f64,

    /// (fuzz) Retry count on network error
    #[arg(long = "retries", default_value_t = 1, help_heading = "Fuzz mode")]
    retries: u32,

    /// (fuzz) Emit status_code=0 records (connection errors). Off by default.
    #[arg(long = "include-errors", visible_alias = "ie", help_heading = "Fuzz mode")]
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
    /// (backup) Turn OFF host-derived backup probing.
    #[arg(long = "no-backup-fuzz", help_heading = "Backup discovery")]
    no_backup_fuzz: bool,

    /// (backup) Print the candidates that would be probed and send no
    /// requests.
    #[arg(long = "backup-dry-run", help_heading = "Backup discovery")]
    backup_dry_run: bool,

    /// (backup) Extra base-name tokens, comma-separated. The one thing the
    /// tool cannot infer: an internal project name unrelated to the
    /// hostname (e.g. `--backup-tokens acmecorp,internal-portal`).
    #[arg(long = "backup-tokens", value_name = "LIST", help_heading = "Backup discovery")]
    backup_tokens: Option<String>,

    /// (fuzz) Status codes to EXCLUDE from output (default `429,503` —
    /// transient overload). Empty to disable. 403/404 are NOT in the
    /// default because they can be real findings (Apache reveal-on-403,
    /// stack-trace 404s).
    #[arg(
        long = "exclude",
        alias = "exclude-codes",
        alias = "exclude-status",
        default_value = "429,503",
        help_heading = "Fuzz mode"
    )]
    exclude_codes: String,

    /// (fuzz) Alias of `--match-codes` for dirsearch-muscle-memory users.
    #[arg(short = 'i', long = "include", help_heading = "Fuzz mode")]
    include_status: Option<String>,

    // ── Recursion (v0.3.7) ─────────────────────────────────────────────
    /// Enable recursive fuzz — discovered directories get re-fuzzed with
    /// the same wordlist up to `-R` levels deep. Per-directory multi-sample
    /// wildcard fingerprinting prevents soft-404 / catchall cascades.
    /// Default: off (single-round, v0.3.6 behavior).
    #[arg(short = 'r', long = "recursive", help_heading = "Recursion")]
    recursive: bool,

    /// (recursion) Max depth. Default 3 when `-r` is on.
    #[arg(
        short = 'R',
        long = "recursion-depth", visible_alias = "rd",
        default_value_t = 3,
        help_heading = "Recursion"
    )]
    recursion_depth: u8,

    /// (recursion) Also recurse on 200 + autoindex marker (`Index of /`).
    #[arg(long = "recurse-on-200", visible_alias = "r200", help_heading = "Recursion")]
    recurse_on_200: bool,

    /// (recursion) Also recurse on 403 (off by default — WAF noise prone).
    #[arg(long = "recurse-on-403", visible_alias = "r403", help_heading = "Recursion")]
    recurse_on_403: bool,

    /// (recursion) Hard cap on discovered directories per input host.
    #[arg(long = "max-dirs-per-host", visible_alias = "md", default_value_t = 200, help_heading = "Recursion")]
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
    #[arg(long = "exclude-subdirs", visible_alias = "xs", help_heading = "Recursion")]
    exclude_subdirs: Option<String>,

    /// (recursion) Append to the built-in --exclude-subdirs list
    /// (doesn't replace defaults; just adds).
    #[arg(long = "add-excludes", visible_alias = "xa", help_heading = "Recursion")]
    add_excludes: Option<String>,

    /// (recursion) How exclude entries match: `segment` (default — last
    /// path component equals an entry, case-insensitive) or `substring`
    /// (any entry appears anywhere in the path). Substring is dirsearch-
    /// muscle-memory compat and catches encoded traversal noise
    /// (`%2e%2e`, `%3b`, `..//`) hidden mid-path.
    #[arg(long = "exclude-mode", visible_alias = "xm", default_value = "segment", help_heading = "Recursion")]
    exclude_mode: String,

    /// (fuzz) Exact content-length(s) to drop from output. Comma-separated
    /// bytes — accepts trailing `B`. Mirrors dirsearch `--exclude-sizes`.
    /// Empty = no size filter.
    #[arg(long = "exclude-sizes", visible_alias = "es", default_value = "", help_heading = "Fuzz mode")]
    exclude_sizes: String,

    /// (fuzz) Probe `/` once at startup and add its content-length to
    /// `--exclude-sizes` automatically. Catches fake-200 catchall pages
    /// that return the homepage for every path (a pattern the wildcard
    /// detector usually catches, but this is the explicit dirsearch
    /// pattern from `ROOT_SIZE=$(curl ...)`).
    #[arg(long = "exclude-root-size", visible_alias = "ers", help_heading = "Fuzz mode")]
    exclude_root_size: bool,

    /// Output file format. `json` (default) writes one full FuzzRecord
    /// JSONL line per finding. `plain` writes dirsearch-style
    /// `STATUS  SIZE  URL` per finding — much smaller files, human-
    /// readable, no body_preview. Auto-detected from `-o` extension when
    /// this flag isn't passed (`.txt` → `plain`, anything else → `json`).
    #[arg(long = "format", help_heading = "Output")]
    format: Option<String>,

    /// Suppress the live findings display on stderr (v0.3.13). By
    /// default, every emitted finding prints to the terminal in
    /// dirsearch-style format (`STATUS SIZE URL`, color-coded by status
    /// class) above the progress bar. Pass this to silence and rely on
    /// the output file only — useful for log scrapers / tee invocations.
    #[arg(long = "no-live", help_heading = "Output")]
    no_live: bool,

    /// Capture the FULL response header set: printed under each result on the
    /// terminal AND emitted as a `response_headers` JSON object (lowercase
    /// keys; duplicate headers like Set-Cookie folded with ", "). Works in
    /// BOTH modes — enrich (`-u` / `-l`) and fuzz (`-w`). Off by default to
    /// keep output small. Aliases mirror httpx muscle memory: `--rh`, `--irh`.
    #[arg(
        long = "response-headers",
        visible_alias = "rh",
        visible_alias = "irh",
        help_heading = "Output"
    )]
    response_headers: bool,

    // ── Crawl (v0.3.7) ─────────────────────────────────────────────────
    /// Enable response crawling — parse HTML/robots.txt/sitemap.xml for
    /// endpoints and add them to the fuzz frontier. Same-host scope by
    /// default; static assets + third-party CDNs filtered out.
    #[arg(long = "crawl", help_heading = "Crawl")]
    crawl: bool,

    /// (crawl) Max crawl depth. Default = `--recursion-depth`.
    #[arg(long = "crawl-depth", visible_alias = "cd", help_heading = "Crawl")]
    crawl_depth: Option<u8>,

    /// (crawl) Cap on URLs extracted per response (default 200).
    #[arg(long = "max-links-per-page", visible_alias = "mlp", default_value_t = 200, help_heading = "Crawl")]
    max_links_per_page: usize,

    /// (crawl) Override the same-host default scope. Comma-separated host
    /// patterns. Supports `*.example.com` wildcard suffix.
    /// Built-in third-party deny list (Google/Cloudflare/CDN hosts) still
    /// applies regardless.
    #[arg(long = "scope", help_heading = "Crawl")]
    scope: Option<String>,

    // ── Misc fuzz behavior (v0.3.7) ────────────────────────────────────
    /// (fuzz) Follow redirects within fuzz probes (3xx normally a finding).
    /// Auto-on when `--crawl` is set.
    #[arg(long = "fuzz-follow-redirects", visible_alias = "ffr", help_heading = "Fuzz mode")]
    fuzz_follow_redirects: bool,

    // ── Auth (v0.3.7) ──────────────────────────────────────────────────
    /// Custom request header. Repeatable. Format `"Name: Value"`.
    #[arg(short = 'H', long = "header", help_heading = "Auth")]
    headers: Vec<String>,

    /// `Authorization: Bearer TOKEN` shortcut.
    #[arg(long = "bearer", help_heading = "Auth")]
    bearer: Option<String>,

    /// Cookie to attach. Repeatable. Format `"Name=Value"`.
    /// Sent as a fixed `Cookie:` header on every request — there is NO cookie
    /// jar, so `Set-Cookie` from responses is never captured or replayed.
    #[arg(long = "cookie", help_heading = "Auth")]
    cookies: Vec<String>,

    // ── Convenience ─────────────────────────────────────────────────────
    /// Single-target shortcut (alternative to `-l file`). Equivalent to
    /// passing a one-line input file.
    #[arg(short = 'u', long = "target")]
    target: Option<String>,

    /// HTTP / HTTPS / SOCKS5 proxy URL. Applied to EVERY client in the
    /// 16-slot pool, so both enrich and fuzz modes route through the same
    /// upstream. Accepts `http://host:port`, `https://host:port`,
    /// `socks5://host:port`, and `socks5h://host:port`. Invalid URLs fail
    /// loudly at startup. Sets `via_proxy:true` on every output record.
    #[arg(long = "proxy")]
    proxy: Option<String>,

    // ── Self-management ────────────────────────────────────────────────
    /// Install the latest release (replaces this binary in place).
    /// Short flag is `-U` (uppercase) — `-u` was reclaimed for `--target`
    /// in v0.3.7 for dirsearch-muscle-memory compat.
    #[arg(short = 'U', long, help_heading = "Self-management")]
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
    #[arg(visible_alias = "nuc", long, help_heading = "Self-management")]
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
    #[arg(long = "no-color", help_heading = "Output")]
    no_color: bool,
    /// httpx compat (no-op — httpxer doesn't print per-record stderr noise)
    #[arg(long, hide = true)]
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
    for a in argv {
        if a == "-q" || a == "--quiet" || a == "--no-update-check" {
            return false;
        }
    }
    true
}

/// Strip scheme + path/query/fragment so `https://foo.com/bar?x=1` becomes
/// `foo.com`. Without stripping `?` and `#`, inputs like
/// `https://foo.com?x=1` would resolve DNS as `foo.com?x=1` and silently
/// fail — and the resume-skip cache would miss its own dedupe key.
fn extract_host(input: &str) -> String {
    let s = input
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host_end = s.find(['/', '?', '#']).unwrap_or(s.len());
    s[..host_end].to_string()
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

    // Validate `--proxy` URL eagerly so a typo fails BEFORE the network
    // probes. `wreq::Proxy::all` parses the scheme + host:port; we throw
    // away the built Proxy and rebuild it inside `init_pool` (the value
    // is cheap to construct and not Clone-cheap to plumb here).
    if let Some(p) = args.proxy.as_deref() {
        wreq::Proxy::all(p).map_err(|e| anyhow::anyhow!("invalid --proxy URL '{}': {}", p, e))?;
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

    // `--fingerprints` is only consulted when the tech-detect engine is built,
    // which `--no-tech` skips entirely — so passing both means the custom
    // fingerprint file is silently ignored. Warn instead of no-op'ing quietly.
    // Placed BEFORE the mode split so it fires in fuzz mode too.
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
        let words = fuzz::read_words(paths_path)?;
        eprintln!("[+] wordlist: {} unique paths", words.len());

        // Host-derived backup discovery is ON by default in fuzz mode: the
        // per-host archive names a wordlist structurally cannot carry are
        // exactly the ones worth trying while we are already probing this
        // host. `--no-backup-fuzz` opts out.
        let backup_enabled = !args.no_backup_fuzz;

        // Build wildcard policy from flags. `--no-wildcard` overrides.
        let policy = fuzz::WildcardPolicy::from_cli(&args.wildcard_policy, args.no_wildcard)?;

        // Build the impersonation pool once — fuzz uses the same pool
        // enrich does, so the init logic is identical.
        probe::init_pool(args.timeout_ms, args.no_impersonate, args.proxy.as_deref())?;
        if !args.no_impersonate {
            eprintln!("[+] TLS impersonation: rotating real-browser JA3/JA4 + HTTP/2 fingerprints");
        } else {
            eprintln!("[+] TLS impersonation: DISABLED (--no-impersonate)");
        }

        // Backup phase runs before the wordlist sweep so a jackpot archive
        // surfaces immediately rather than after a long path scan.
        if backup_enabled {
            let opts = backup_fuzz::PhaseOpts {
                cfg: backup_fuzz::BackupCfg {
                    token_extra: args
                        .backup_tokens
                        .as_deref()
                        .map(|s| s.split(',').map(|t| t.trim().to_string()).collect())
                        .unwrap_or_default(),
                    current_year: chrono::Utc::now().format("%Y").to_string().parse().unwrap_or(2026),
                    ..Default::default()
                },
                dry_run: args.backup_dry_run,
                concurrency: args.threads,
            };
            eprintln!(
                "[+] backup discovery: host-derived candidates, auto-tuned per host{}",
                if args.backup_dry_run { " [dry-run]" } else { "" }
            );
            let found = backup_fuzz::run_phase(&hosts, &opts).await;
            if !found.is_empty() {
                backup_fuzz::print_confirmed_table(&found);
                let path = format!("{}.backup.jsonl", output_path);
                let mut buf = String::new();
                for f in &found {
                    buf.push_str(&serde_json::to_string(f)?);
                    buf.push('\n');
                }
                std::fs::write(&path, buf)?;
                eprintln!("[+] backup findings: {} → {}", found.len(), path);
            }
        }

        // -i / --include is a dirsearch-style alias for --match-codes.
        // When passed, it OVERRIDES match-codes.
        let codes_source = args
            .include_status
            .as_deref()
            .unwrap_or(args.match_codes.as_str());
        let match_codes: Vec<u16> = codes_source
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect();
        if match_codes.is_empty() {
            anyhow::bail!(
                "match codes parsed to zero (got '{}')",
                codes_source
            );
        }
        let exclude_codes: Vec<u16> = args
            .exclude_codes
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect();

        // Auth was already built + validated before the mode split (v0.5.0),
        // and installed for the enrich path via `probe::init_auth`. Fuzz reads
        // the same values out of `extra_headers` / `initial_cookie_header`.

        // Exclude-subdirs: built-in defaults unless --exclude-subdirs
        // override is passed; --add-excludes always appends.
        let exclude_subdirs = recurse::build_exclude_set(
            args.exclude_subdirs.as_deref(),
            args.add_excludes.as_deref(),
        );
        let exclude_mode = recurse::ExcludeMode::from_cli(&args.exclude_mode)?;

        // Exclude-sizes: parse comma-separated bytes (accept trailing 'B').
        // Empty string = no size filter.
        let mut exclude_sizes: Vec<i64> = args
            .exclude_sizes
            .split(',')
            .filter_map(|s| {
                let s = s.trim().trim_end_matches(['B', 'b']);
                if s.is_empty() {
                    None
                } else {
                    s.parse::<i64>().ok()
                }
            })
            .collect();

        // --exclude-root-size: probe `/` once and add its CL to exclude_sizes.
        // v0.4.5 — measure the root page through the SAME impersonation pool,
        // `-H` headers and Accept profile the fuzz probes use, so the learned
        // size matches what fuzz actually sees. (The old plain non-impersonated
        // client could measure a different response on TLS-/header-sensitive
        // edges — a real inconsistency.) Pool is already initialised above via
        // `probe::init_pool`. Redirects off (matches fuzz default — a 3xx root
        // is a finding, not a body to measure).
        if args.exclude_root_size {
            for h in &hosts {
                let url = if h.starts_with("http://") || h.starts_with("https://") {
                    h.trim_end_matches('/').to_string()
                } else {
                    format!("https://{}", h)
                };
                let Some(slot) = probe::pick_pool_slot_for(&url) else {
                    continue;
                };
                let mut req = slot
                    .client
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
                match req.send().await {
                    Ok(resp) => {
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
                            None => match resp.bytes().await {
                                Ok(b) => b.len() as i64,
                                Err(_) => -1,
                            },
                        };
                        if size > 0 && !exclude_sizes.contains(&size) {
                            eprintln!(
                                "[+] root-size {} → adding {} to --exclude-sizes",
                                url, size
                            );
                            exclude_sizes.push(size);
                        }
                    }
                    Err(e) => eprintln!(
                        "[!] root-size probe failed for {}: {} (skipping)",
                        url, e
                    ),
                }
            }
        }

        // v0.3.10 — apply exclude_subdirs to the wordlist BEFORE fuzz
        // even starts. This is the dirsearch behaviour the user expected
        // ("any queued path CONTAINING these strings is dropped"). When
        // exclude_mode=substring, every wordlist entry containing any
        // exclude pattern is dropped up-front; in segment mode only entries
        // whose last component matches are dropped.
        let initial_word_count = words.len();
        let words: Vec<String> = words
            .into_iter()
            .filter(|w| !recurse::path_excluded(w, &exclude_subdirs, exclude_mode))
            .collect();
        let filtered = initial_word_count - words.len();
        if filtered > 0 {
            eprintln!(
                "[+] exclude-subdirs ({} mode): {} wordlist entries dropped ({} → {})",
                exclude_mode.as_str(),
                filtered,
                initial_word_count,
                words.len()
            );
        }

        // Scope: empty = same-host-as-input default.
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

        // Recursion off when `-r` not passed; otherwise honour -R depth.
        let recursion_depth = if args.recursive { args.recursion_depth } else { 0 };
        // Crawl-depth defaults to recursion-depth (so a single -R bumps both).
        let crawl_depth = args.crawl_depth.unwrap_or(args.recursion_depth);
        // Crawl auto-follows redirects to capture terminal-page bodies —
        // but an explicit `--no-follow-redirects` is a kill switch and wins
        // over both that auto-enable and `--fuzz-follow-redirects`.
        let fuzz_follow_redirects =
            !args.no_follow_redirects && (args.fuzz_follow_redirects || args.crawl);
        if args.no_follow_redirects && (args.fuzz_follow_redirects || args.crawl) {
            eprintln!(
                "[!] --no-follow-redirects overrides redirect-following in fuzz mode \
                 (3xx stays a finding; crawl only sees pre-redirect bodies)"
            );
        }

        let cfg = fuzz::FuzzCfg {
            match_codes,
            exclude_codes,
            body_preview_bytes: args.body_preview,
            wildcard_samples: 3,
            include_errors: args.include_errors,
            retries: args.retries,
            via_proxy: args.proxy.is_some(),
            threads: args.threads,
            timeout_ms: args.timeout_ms,
            rate_limit_rps: args.rate_limit,
            recursion_depth,
            recurse_on_200: args.recurse_on_200,
            recurse_on_403: args.recurse_on_403,
            // v0.4.5 — auth-dir recursion is auto-on (smart default, no flag).
            recurse_on_auth: true,
            // v0.4.5 — native 401/403 bypass is auto-on unless `--safe`.
            bypass_enabled: !args.safe,
            max_dirs_per_host: args.max_dirs_per_host,
            crawl_enabled: args.crawl,
            crawl_depth,
            crawl_robots: true,
            crawl_sitemap: true,
            max_links_per_page: args.max_links_per_page,
            scope_hosts,
            exclude_sizes,
            fuzz_follow_redirects,
            // Honour `--max-redirects` in fuzz mode too (was hardcoded to 10;
            // 10 is also the flag's default, so unchanged unless passed).
            max_redirects: args.max_redirects,
            initial_cookie_header: auth_ctx.initial_cookie_header(),
            extra_headers,
            output_format: match args.format.as_deref() {
                Some(s) => fuzz::OutputFormat::from_cli(s)?,
                None => fuzz::OutputFormat::from_path(output_path),
            },
            live_findings: !args.no_live,
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
    probe::init_pool(args.timeout_ms, args.no_impersonate, args.proxy.as_deref())?;
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
    let via_proxy = args.proxy.is_some();

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
                    format!("https://{}", host)
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
                    rec.content_length = r.content_length;
                    rec.content_type = r.content_type;
                    rec.word_count = Some(r.word_count);
                    rec.lines = Some(r.line_count);
                    rec.server = r.server;
                    rec.location = r.location;
                    rec.title = r.title;
                    rec.final_url = r.final_url;
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
    }

    // 9. Drain — write NDJSON as each completes (crash-safe, no buffered tail).
    //    When `--httpx-compat` is set, every record is reshaped from the
    //    default EnrichRecord into HttpxCompatRecord just before serialise.
    let mut completed = 0usize;
    let httpx_compat = args.httpx_compat;
    while let Some(joined) = set.next().await {
        match joined {
            Ok(rec) => {
                let line = if httpx_compat {
                    serde_json::to_string(&HttpxCompatRecord::from_enrich(rec))?
                } else {
                    serde_json::to_string(&rec)?
                };
                writeln!(out_file, "{}", line)?;
                completed += 1;
                if completed % 50 == 0 || completed == total {
                    eprintln!("  [{}/{}]", completed, total);
                }
            }
            // Surface panics + cancellations so probe tasks lost to
            // tech-detect regex blowups / runtime aborts don't silently
            // disappear from the output.
            Err(e) => {
                eprintln!("[!] probe task did not complete: {}", e);
            }
        }
    }
    out_file.flush()?;
    eprintln!("[+] done: wrote {} records to {}", completed, output_path);
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

    /// extract_host must strip the path, the query, AND the fragment so
    /// `https://foo.com?x=1` resolves DNS as `foo.com`. Regression for the
    /// `'?'`/`'#'` cases that the original `.find('/')` missed.
    #[test]
    fn extract_host_strips_path_query_fragment() {
        assert_eq!(extract_host("https://foo.com/bar"), "foo.com");
        assert_eq!(extract_host("http://foo.com?x=1"), "foo.com");
        assert_eq!(extract_host("https://foo.com#section"), "foo.com");
        assert_eq!(extract_host("https://foo.com?x=1#section"), "foo.com");
        assert_eq!(extract_host("https://foo.com:8080/bar"), "foo.com:8080");
        assert_eq!(extract_host("foo.com"), "foo.com");
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
}
