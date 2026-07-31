// ─────────────────────────── src/backup_fuzz.rs ───────────────────────────
//
// Host-derived backup discovery (v0.6.0).
//
// WHY THIS EXISTS
// Site owners leave archives on the web root named after the site itself:
// `www.example.com.zip`, `example.com.sql`, `example.zip`. A static wordlist
// structurally cannot carry these, because the filename is a function of the
// target's own hostname. This module derives those names at runtime.
//
// AUTO-ACTIVATION
// The mode turns itself ON whenever the binary is in fuzz mode (a wordlist
// was supplied). `--backup off` opts out; `--backup dry-run` previews candidates
// without probing and then exits. Rationale: a fuzz run is already paying the per-host
// setup cost, and host-derived archives are the highest-yield candidates a
// wordlist cannot express.
//
// ISOLATION
// Nothing here mutates the wordlist probe path. The module owns its own
// candidate generation and verdict logic, and borrows the shared client pool
// (`probe::pick_pool_slot_for`) so no second HTTP client is introduced.
//
// URL JOINING
// `normalize_base` + `join_url` are the single shared implementation of the
// base-normalization contract. Both the wordlist mode and this mode must go
// through them so a join bug can only ever exist in one place.

use crate::probe;
use anyhow::Result;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;

// ───────────────────────────── extension matrix ─────────────────────────────
// Class 1 - archive containers.
pub const EXT_ARCHIVE: &[&str] = &[
    ".zip", ".rar", ".7z", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2",
    ".tar.xz", ".txz", ".gz", ".bz2", ".xz", ".Z", ".lz4", ".zst",
];
// Class 2 - editor / admin backup markers.
pub const EXT_BACKUP_MARKER: &[&str] = &[
    ".bak", ".backup", ".bkp", ".bck", ".old", ".orig", ".save", ".copy",
    ".tmp", ".temp", ".new", ".1", ".2", "~",
];
// Class 3 - database dumps.
pub const EXT_DATABASE: &[&str] = &[
    ".sql", ".sql.gz", ".sql.zip", ".sql.bz2", ".db", ".sqlite", ".sqlite3",
    ".dump", ".dmp", ".mdb", ".bacpac", ".bson",
];
// Class 4 - Java / mobile web packages.
pub const EXT_JAVA_PKG: &[&str] = &[".war", ".jar", ".ear", ".apk", ".ipa"];
// Class 5 - disk and VM images.
pub const EXT_DISK_IMAGE: &[&str] = &[".iso", ".img", ".vmdk", ".ova"];
// Class 6 - compound forms. Highest hit-rate in the wild: an admin tars a
// directory then zips the tarball, or renames `.zip` to `.zip.bak`.
pub const EXT_COMPOUND: &[&str] = &[
    ".bak.zip", ".backup.zip", ".old.zip", ".save.zip", ".sql.zip", ".db.zip",
    ".bak.tar.gz", ".backup.tar.gz", ".zip.bak", ".zip.old", ".tar.gz.bak",
    ".sql.bak", ".backup.sql",
];
// Class 7 - separator forms. `{}` is the token placeholder.
pub const SEPARATOR_FORMS: &[&str] = &[
    "{}_backup.zip", "{}-backup.zip", "{}.backup.zip", "backup_{}.zip",
    "backup-{}.zip", "{}_bak.zip", "{}_db.sql", "{}_dump.sql",
];
// Class 8 - date-stamped forms. `{}` = token, `{Y}` = year placeholder.
pub const DATE_FORMS: &[&str] = &[
    "{}-{Y}.zip", "{}_{Y}.zip", "{}.{Y}.zip", "{}-{Y}.sql.gz",
];

/// Directory prefixes conditionally verified after `backup/` or `bak/` exists.
pub const BACKUP_DIRS: &[&str] = &[
    "backup", "backups", "bak", "old", "tmp", "temp", "dump", "dumps",
    "db", "database", "archive", "archives", "files", "storage",
    "_backup", ".backup", "private", "uploads", "downloads",
];

/// Host-independent names that are always worth a try.
pub const STATIC_GENERIC: &[&str] = &[
    "backup.zip", "backup.sql", "backup.tar.gz", "db.sql", "dump.sql",
    "database.sql", "site.zip", "www.zip", "web.zip", "html.zip",
    "public_html.zip", "public_html.tar.gz", "wwwroot.zip", "htdocs.zip",
    "source.zip", "src.zip", "app.zip", "build.zip", "release.zip",
    "dist.zip", "full.zip", "all.zip", "data.zip", "old.zip", "new.zip",
];

/// P1 extension set - applied to the strongest tokens first.
const P1_EXTS: &[&str] = &[".zip", ".rar", ".7z", ".tar.gz", ".sql", ".bak", ".backup"];

/// Enough hostname forms to cover the full host, registrable domain, SLD and
/// one common separator variant before spending budget on the long tail.
const CORE_TOKEN_LIMIT: usize = 4;

// ───────────────────────────── base normalization ────────────────────────────

/// The two join bases derived from one input URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bases {
    /// `{scheme}://{host}[:{port}]` - never carries a trailing slash.
    pub root: String,
    /// Directory the URL sits in - never carries a trailing slash.
    pub dir: String,
}

/// Implements the base-normalization algorithm exactly.
///
/// Steps: parse, drop fragment + query, collapse repeated slashes, resolve
/// `.` / `..`, then classify the final segment as file or directory to pick
/// DIR_BASE. ROOT_BASE is always the bare authority.
pub fn normalize_base(raw: &str) -> Result<Bases, String> {
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{}", raw)
    };
    let parsed = url::Url::parse(&with_scheme).map_err(|e| format!("parse {}: {}", raw, e))?;

    let scheme = parsed.scheme();
    let host = parsed.host_str().ok_or_else(|| format!("no host in {}", raw))?;
    // `port()` is None for the scheme default, which is what we want - the
    // authority should read `example.com`, not `example.com:443`.
    let authority = match parsed.port() {
        Some(p) => format!("{}:{}", host, p),
        None => host.to_string(),
    };
    let root = format!("{}://{}", scheme, authority);

    // Fragment and query are already excluded by `path()`.
    let path = parsed.path();

    // Collapse repeated slashes, then resolve dot segments. The scheme's own
    // "//" is untouched because we are working on the path component alone.
    let mut segments: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }

    let ends_with_slash = path.ends_with('/');
    let dir = if segments.is_empty() {
        // Path was empty or "/" or "//" - the directory IS the root.
        root.clone()
    } else if ends_with_slash {
        // Explicit directory - keep every segment, drop the trailing slash.
        format!("{}/{}", root, segments.join("/"))
    } else {
        // No trailing slash: the last segment decides. A dot means it is a
        // file, so the directory is its parent. No dot means it is itself a
        // directory.
        let last = segments[segments.len() - 1];
        if last.contains('.') {
            let parent = &segments[..segments.len() - 1];
            if parent.is_empty() {
                root.clone()
            } else {
                format!("{}/{}", root, parent.join("/"))
            }
        } else {
            format!("{}/{}", root, segments.join("/"))
        }
    };

    Ok(Bases { root, dir })
}

/// Percent-encode characters that are unsafe in a path, leaving `/` intact so
/// multi-segment entries keep their structure.
fn encode_entry(entry: &str) -> String {
    let mut out = String::with_capacity(entry.len());
    for ch in entry.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' => out.push(ch),
            '/' | '-' | '_' | '.' | '~' | '!' | '$' | '&' | '\'' | '(' | ')'
            | '*' | '+' | ',' | ';' | '=' | ':' | '@' | '%' | '?' => out.push(ch),
            _ => {
                let mut buf = [0u8; 4];
                for b in ch.encode_utf8(&mut buf).as_bytes() {
                    out.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    out
}

/// The single join used by every candidate producer.
///
/// `base` must not end with `/` and `entry` must not start with `/`, so
/// exactly one separator is emitted. Returns `Err` when the result would
/// violate a runtime invariant, so a malformed candidate is dropped before
/// any request is sent rather than being reported as a finding.
pub fn join_url(base: &str, entry: &str) -> Result<String, String> {
    let b = base.trim_end_matches('/');
    let e = entry.trim_start_matches('/');
    if e.is_empty() {
        return Err("empty entry".to_string());
    }
    let url = format!("{}/{}", b, encode_entry(e));

    // Invariant: no "//" after the authority.
    let after_scheme = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => return Err(format!("no scheme in {}", url)),
    };
    if after_scheme.contains("//") {
        return Err(format!("double slash after authority: {}", url));
    }
    // Invariant: the scheme appears exactly once.
    if url.matches("://").count() != 1 {
        return Err(format!("scheme repeated: {}", url));
    }
    // Invariant: a separator actually exists between authority and entry.
    if !after_scheme.contains('/') {
        return Err(format!("missing separator: {}", url));
    }
    Ok(url)
}

// ───────────────────────────── token derivation ─────────────────────────────

/// Derive base-name tokens from a host, plus the current path segment.
///
/// Registrable domain comes from the Public Suffix List, so `abc.co.uk`
/// resolves correctly instead of being cut to `co.uk` by a naive dot count.
/// IP literals yield only the literal itself and its dot-variants - stripping
/// "TLDs" off an IP would produce nonsense.
pub fn derive_tokens(host: &str, path_segment: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let push = |t: String, out: &mut Vec<String>, seen: &mut HashSet<String>| {
        let t = t.trim_matches('.').to_ascii_lowercase();
        if !t.is_empty() && seen.insert(t.clone()) {
            out.push(t);
        }
    };

    // Trailing-dot FQDN form normalizes to the same host.
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return out;
    }

    let is_ip = host.parse::<std::net::IpAddr>().is_ok();

    // Rule 1 - full host verbatim.
    push(host.clone(), &mut out, &mut seen);

    if is_ip {
        // Rules 5/6/7 still make sense for an IPv4 literal (1.2.3.4 -> 1_2_3_4).
        push(host.replace('.', "_"), &mut out, &mut seen);
        push(host.replace('.', "-"), &mut out, &mut seen);
        push(host.replace('.', ""), &mut out, &mut seen);
        if let Some(seg) = path_segment {
            push(seg.to_string(), &mut out, &mut seen);
        }
        return out;
    }

    // Rule 2 - host minus a leading "www.".
    let no_www = host.strip_prefix("www.").unwrap_or(&host).to_string();
    push(no_www.clone(), &mut out, &mut seen);

    // Rule 3 - registrable domain (eTLD+1) via the Public Suffix List.
    let etld1 = psl::domain_str(&host).map(|d| d.to_string());
    if let Some(ref d) = etld1 {
        push(d.clone(), &mut out, &mut seen);
    }

    // Rule 4 - second-level label only, no public suffix.
    let sld = etld1
        .as_ref()
        .and_then(|d| d.split('.').next().map(|s| s.to_string()));
    if let Some(ref s) = sld {
        push(s.clone(), &mut out, &mut seen);
    }

    // Rules 5,6,7 - full host with separators swapped or removed.
    push(host.replace('.', "_"), &mut out, &mut seen);
    push(host.replace('.', "-"), &mut out, &mut seen);
    push(host.replace('.', ""), &mut out, &mut seen);

    // Rule 8 - eTLD+1 with separators swapped.
    if let Some(ref d) = etld1 {
        push(d.replace('.', "_"), &mut out, &mut seen);
        push(d.replace('.', "-"), &mut out, &mut seen);
    }

    // Rule 9 - host minus its public suffix.
    if let Some(ref d) = etld1 {
        if let Some(suffix) = d.split_once('.').map(|(_, s)| s) {
            let cut = host
                .strip_suffix(&format!(".{}", suffix))
                .map(|s| s.to_string());
            if let Some(c) = cut {
                push(c, &mut out, &mut seen);
            }
        }
    }

    // Rules 10,11 - leftmost label, and that label with hyphens swapped.
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() > 1 {
        let leftmost = labels[0].to_string();
        push(leftmost.clone(), &mut out, &mut seen);
        if leftmost.contains('-') {
            push(leftmost.replace('-', "_"), &mut out, &mut seen);
        }

        // Rule 12 - leftmost label concatenated with the SLD.
        if let Some(ref s) = sld {
            if &leftmost != s {
                push(format!("{}{}", leftmost, s), &mut out, &mut seen);
                push(format!("{}_{}", leftmost, s), &mut out, &mut seen);
                push(format!("{}-{}", leftmost, s), &mut out, &mut seen);
            }
        }
    }

    // Rule 13 - current path segment, when the URL has depth.
    if let Some(seg) = path_segment {
        push(seg.to_string(), &mut out, &mut seen);
    }

    out
}

// ─────────────────────────── candidate generation ───────────────────────────

/// Server stack, inferred from one response. Drives which extension classes
/// are worth spending requests on: a Java shop leaves `.war` files, a PHP
/// shop leaves `.sql` and `.zip`. Detection changes only lower-tail ordering;
/// mandatory candidates remain stack-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stack {
    Java,
    Php,
    DotNet,
    Node,
    Python,
    Unknown,
}

impl Stack {
    /// Extension classes ordered by what this stack most often leaves behind.
    ///
    /// Every stack returns every class. Automatic URL budgets may truncate the
    /// lower tail, but stack detection never removes a class from the matrix.
    fn ext_classes(&self) -> Vec<&'static [&'static str]> {
        // The lead classes for this stack, then everything else appended in a
        // stable default order.
        let lead: &[&'static [&'static str]] = match self {
            Stack::Java => &[EXT_JAVA_PKG, EXT_ARCHIVE],
            Stack::Php => &[EXT_DATABASE, EXT_ARCHIVE],
            Stack::DotNet => &[EXT_ARCHIVE, EXT_COMPOUND],
            Stack::Node => &[EXT_ARCHIVE, EXT_COMPOUND],
            Stack::Python => &[EXT_DATABASE, EXT_ARCHIVE],
            Stack::Unknown => &[EXT_ARCHIVE, EXT_DATABASE],
        };
        const ALL: &[&[&str]] = &[
            EXT_ARCHIVE, EXT_DATABASE, EXT_COMPOUND, EXT_BACKUP_MARKER,
            EXT_JAVA_PKG, EXT_DISK_IMAGE,
        ];
        let mut out: Vec<&'static [&'static str]> = lead.to_vec();
        for c in ALL {
            // Compare by pointer identity - these are all 'static slices.
            if !out.iter().any(|x| std::ptr::eq(x.as_ptr(), c.as_ptr())) {
                out.push(c);
            }
        }
        out
    }
}

/// Infer the stack from response headers and a body snippet.
pub fn stack_from_signals(server: Option<&str>, powered_by: Option<&str>, body: &[u8]) -> Stack {
    let hay = format!(
        "{} {} {}",
        server.unwrap_or(""),
        powered_by.unwrap_or(""),
        String::from_utf8_lossy(&body[..body.len().min(2048)])
    )
    .to_ascii_lowercase();

    // Order matters: a PHP banner on nginx should win over the nginx hint.
    if hay.contains("php") || hay.contains("wordpress") || hay.contains("wp-content") {
        return Stack::Php;
    }
    if hay.contains("tomcat") || hay.contains("jboss") || hay.contains("jetty")
        || hay.contains("jsessionid") || hay.contains("servlet") || hay.contains(".jsp")
    {
        return Stack::Java;
    }
    if hay.contains("asp.net") || hay.contains("aspnet") || hay.contains("iis")
        || hay.contains("__viewstate") || hay.contains(".aspx")
    {
        return Stack::DotNet;
    }
    if hay.contains("express") || hay.contains("next.js") || hay.contains("__next")
        || hay.contains("nuxt")
    {
        return Stack::Node;
    }
    if hay.contains("django") || hay.contains("gunicorn") || hay.contains("werkzeug")
        || hay.contains("wsgi") || hay.contains("csrfmiddlewaretoken")
    {
        return Stack::Python;
    }
    Stack::Unknown
}

/// Candidate-generation inputs. Everything here is derived automatically at
/// runtime except `token_extra`, which is the one value the tool cannot
/// infer: an internal project name unrelated to the hostname.
#[derive(Debug, Clone)]
pub struct BackupCfg {
    /// Shared candidate-URL ceiling per host. Auto-scaled by responsiveness and
    /// never above `MAX_PERMS_CEILING`.
    pub max_perms: usize,
    /// Date-stamp depth. Fixed at 3 (this year and the previous two) - a
    /// backup older than that is rarely still sitting on the web root.
    pub years: u32,
    /// User-supplied extra tokens.
    pub token_extra: Vec<String>,
    pub current_year: i32,
    /// Detected stack; drives extension ordering.
    pub stack: Stack,
}

/// Absolute per-host ceiling. Auto-scaling may lower the effective cap but
/// can never raise it past this, so the mode cannot run away on a big scope.
pub const MAX_PERMS_CEILING: usize = 300;

impl Default for BackupCfg {
    fn default() -> Self {
        Self {
            max_perms: MAX_PERMS_CEILING,
            years: 3,
            token_extra: Vec::new(),
            current_year: 2026,
            stack: Stack::Unknown,
        }
    }
}

/// Build the candidate filename list for a host, in priority order and capped
/// at `cfg.max_perms`. High-yield generic, separator and current-year names are
/// reserved before the bulk token/extension matrix, so a low live budget never
/// drops `backup.zip` or the strongest hostname-derived forms.
pub fn generate_candidates(host: &str, path_segment: Option<&str>, cfg: &BackupCfg) -> Vec<String> {
    let mut tokens = derive_tokens(host, path_segment);
    for extra in &cfg.token_extra {
        let e = extra.trim().to_ascii_lowercase();
        if !e.is_empty() && !tokens.contains(&e) {
            tokens.push(e);
        }
    }
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let push = |c: String, out: &mut Vec<String>, seen: &mut HashSet<String>| {
        if out.len() < cfg.max_perms && seen.insert(c.clone()) {
            out.push(c);
        }
    };

    let core_tokens: Vec<&String> = tokens.iter().take(CORE_TOKEN_LIMIT).collect();

    // P0 - mandatory coverage. These names must survive every automatic live
    // budget (the smallest is 50 candidate URLs).
    for t in &core_tokens {
        push(format!("{}.zip", t), &mut out, &mut seen);
    }
    for g in STATIC_GENERIC {
        push(g.to_string(), &mut out, &mut seen);
    }
    for t in &core_tokens {
        for f in SEPARATOR_FORMS.iter().take(2) {
            push(f.replace("{}", t), &mut out, &mut seen);
        }
        for f in DATE_FORMS.iter().take(2) {
            let c = f
                .replace("{}", t)
                .replace("{Y}", &cfg.current_year.to_string());
            push(c, &mut out, &mut seen);
        }
    }

    // P1 - every token with the highest-yield extensions.
    for t in &tokens {
        for e in P1_EXTS {
            push(format!("{}{}", t, e), &mut out, &mut seen);
        }
    }
    // P3 - compound extensions, then the remaining single-extension classes.
    for t in &tokens {
        for e in EXT_COMPOUND {
            push(format!("{}{}", t, e), &mut out, &mut seen);
        }
    }
    // Remaining classes, ordered by what the detected stack actually leaves
    // behind. `Unknown` keeps the full matrix so nothing is lost when the
    // stack probe is inconclusive.
    for t in &tokens {
        for class in cfg.stack.ext_classes() {
            for e in class {
                push(format!("{}{}", t, e), &mut out, &mut seen);
            }
        }
    }
    // P4 - remaining separator forms.
    for t in &tokens {
        for f in SEPARATOR_FORMS {
            push(f.replace("{}", t), &mut out, &mut seen);
        }
    }
    // P5 - date-stamped, newest year first.
    for back in 0..cfg.years {
        let year = cfg.current_year - back as i32;
        for t in &tokens {
            for f in DATE_FORMS {
                let c = f.replace("{}", t).replace("{Y}", &year.to_string());
                push(c, &mut out, &mut seen);
            }
        }
    }

    out
}

/// Join candidates to bases in priority-round-robin order under one global URL
/// budget. A target with both root and current-directory bases therefore still
/// probes at most `max_urls` candidate URLs, not `max_urls` per base.
fn build_probe_queue(
    candidates: &[String],
    targets: &[(String, String)],
    max_urls: usize,
) -> Vec<(String, String, String)> {
    let mut queue = Vec::with_capacity(max_urls);
    let mut seen = HashSet::new();
    if max_urls == 0 {
        return queue;
    }

    'candidates: for candidate in candidates {
        for (base_type, base) in targets {
            let Ok(url) = join_url(base, candidate) else {
                continue;
            };
            if seen.insert(url.clone()) {
                queue.push((url, base_type.clone(), candidate.clone()));
                if queue.len() == max_urls {
                    break 'candidates;
                }
            }
        }
    }
    queue
}

// ──────────────────────────────── detection ────────────────────────────────

/// Magic-byte signatures. `offset` is where the pattern must appear.
struct Magic {
    name: &'static str,
    offset: usize,
    pattern: &'static [u8],
}

const MAGICS: &[Magic] = &[
    Magic { name: "zip",    offset: 0,   pattern: &[0x50, 0x4B, 0x03, 0x04] },
    Magic { name: "zip",    offset: 0,   pattern: &[0x50, 0x4B, 0x05, 0x06] },
    Magic { name: "zip",    offset: 0,   pattern: &[0x50, 0x4B, 0x07, 0x08] },
    Magic { name: "gzip",   offset: 0,   pattern: &[0x1F, 0x8B] },
    Magic { name: "bzip2",  offset: 0,   pattern: &[0x42, 0x5A, 0x68] },
    Magic { name: "xz",     offset: 0,   pattern: &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] },
    Magic { name: "7z",     offset: 0,   pattern: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },
    Magic { name: "rar",    offset: 0,   pattern: &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07] },
    Magic { name: "tar",    offset: 257, pattern: b"ustar" },
    Magic { name: "sqlite", offset: 0,   pattern: b"SQLite format 3\x00" },
    Magic { name: "access", offset: 4,   pattern: b"Standard Jet DB" },
    Magic { name: "access", offset: 4,   pattern: b"Standard ACE DB" },
];

/// Return the format name when `body` carries a recognised archive/database
/// signature at the required offset.
pub fn magic_match(body: &[u8]) -> Option<&'static str> {
    for m in MAGICS {
        let end = m.offset + m.pattern.len();
        if body.len() >= end && &body[m.offset..end] == m.pattern {
            return Some(m.name);
        }
    }
    None
}

const SQL_MARKERS: &[&str] = &[
    "-- MySQL dump",
    "-- PostgreSQL database dump",
    "CREATE TABLE",
    "INSERT INTO",
    "DROP TABLE IF EXISTS",
    "PRAGMA foreign_keys",
];

/// True when the first bytes look like a plaintext SQL dump.
pub fn sql_text_match(body: &[u8]) -> bool {
    let head = &body[..body.len().min(1024)];
    let text = String::from_utf8_lossy(head);
    SQL_MARKERS.iter().any(|m| text.contains(m))
}

const WAF_MARKERS: &[&str] = &[
    "cf-ray",
    "Attention Required",
    "Request blocked",
    "Access Denied",
    "Reference #",
    "_Incapsula_Resource",
    "DataDome",
];

/// True when the body is an edge-security interstitial rather than content.
pub fn is_waf_interstitial(body: &[u8]) -> bool {
    let head = &body[..body.len().min(4096)];
    let text = String::from_utf8_lossy(head);
    WAF_MARKERS.iter().any(|m| text.contains(m))
}

/// Byte-level similarity in [0,1] against a baseline sample. Cheap stand-in
/// for edit distance: compares length ratio and a shared-prefix ratio, which
/// is enough to catch a soft-404 template reused across candidates.
pub fn similarity(a: &[u8], b: &[u8]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let max_len = a.len().max(b.len()) as f64;
    let len_ratio = a.len().min(b.len()) as f64 / max_len;
    let common = a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count() as f64;
    let prefix_ratio = common / max_len;
    (len_ratio * 0.5) + (prefix_ratio * 0.5)
}

/// Final verdict for one probed candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    #[serde(rename = "CONFIRMED")]
    Confirmed,
    #[serde(rename = "REVIEW")]
    Review,
    #[serde(rename = "DISCARDED")]
    Discarded,
}

/// One JSONL output record.
#[derive(Debug, Clone, Serialize)]
pub struct BackupFinding {
    pub url: String,
    pub base_type: String,
    pub host: String,
    pub candidate: String,
    pub method: String,
    pub status: u16,
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub magic_matched: Option<String>,
    pub sql_text_matched: bool,
    pub baseline_similarity: f64,
    pub confidence: f64,
    pub verdict: Verdict,
    pub first_bytes_sha256: String,
    pub timestamp: String,
}

/// Inputs the verdict gate needs. Keeping this separate from the HTTP layer
/// makes the decision logic unit-testable without a network.
pub struct Evidence<'a> {
    pub status: u16,
    pub content_length: Option<u64>,
    pub content_type: Option<&'a str>,
    pub body_head: &'a [u8],
    pub baseline_similarity: f64,
    pub candidate: &'a str,
}

#[derive(Debug, Clone)]
struct ResponseSample {
    status: u16,
    path: String,
    body: Vec<u8>,
}

fn canonical_sample_body(sample: &ResponseSample) -> Vec<u8> {
    if sample.path.is_empty() {
        return sample.body.clone();
    }
    let Ok(text) = std::str::from_utf8(&sample.body) else {
        return sample.body.clone();
    };
    text.replace(&sample.path, "{PATH}").into_bytes()
}

fn sample_similarity(a: &ResponseSample, b: &ResponseSample) -> f64 {
    similarity(&canonical_sample_body(a), &canonical_sample_body(b))
}

/// The zero-false-positive gate.
///
/// CONFIRMED requires all of: a 200/206 status, a body above the size floor,
/// a positive content signal (magic bytes or SQL text), and a body that does
/// not resemble the soft-404 baseline. Anything short of that is REVIEW at
/// best - a bare 200 with an HTML body on a `.zip` is DISCARDED outright,
/// which is the single biggest source of noise in naive backup scanning.
pub fn classify(ev: &Evidence) -> (Verdict, f64, Option<&'static str>, bool) {
    let magic = magic_match(ev.body_head);
    let sql = sql_text_match(ev.body_head);

    // Rule 1 - only 200/206 can ever be a finding.
    if ev.status != 200 && ev.status != 206 {
        // 401/403 are worth surfacing but are never CONFIRMED.
        if ev.status == 401 || ev.status == 403 {
            return (Verdict::Review, 0.30, magic, sql);
        }
        return (Verdict::Discarded, 0.0, magic, sql);
    }
    // Rule 8 - edge-security interstitial is not content.
    if is_waf_interstitial(ev.body_head) && magic.is_none() {
        return (Verdict::Discarded, 0.0, magic, sql);
    }
    // Rule 3 - indistinguishable from the soft-404 baseline.
    if ev.baseline_similarity >= 0.95 && magic.is_none() {
        return (Verdict::Discarded, 0.0, magic, sql);
    }
    // Rule 4 - size floor, waived when the signature already matched.
    if let Some(cl) = ev.content_length {
        if cl < 200 && magic.is_none() {
            return (Verdict::Discarded, 0.0, magic, sql);
        }
    }
    // Rule 5 - HTML content-type on an archive candidate is a soft-404 tell.
    let archive_like = [".zip", ".sql", ".db", ".tar.gz", ".rar", ".7z", ".sqlite", ".dump"]
        .iter()
        .any(|e| ev.candidate.ends_with(e));
    if archive_like {
        if let Some(ct) = ev.content_type {
            if ct.contains("text/html") && magic.is_none() && !sql {
                return (Verdict::Discarded, 0.0, magic, sql);
            }
        }
    }
    // Rule 10 - confidence gate.
    if magic.is_some() || sql {
        (Verdict::Confirmed, 0.97, magic, sql)
    } else {
        (Verdict::Review, 0.55, magic, sql)
    }
}

/// Hex sha256 of the first bytes, used for cross-candidate dedup.
pub fn first_bytes_sha256(body: &[u8]) -> String {
    use sha2::Digest;
    let head = &body[..body.len().min(1024)];
    let mut h = sha2::Sha256::new();
    h.update(head);
    hex::encode(h.finalize())
}

fn declared_object_length(
    content_length: Option<&str>,
    content_range: Option<&str>,
) -> Option<u64> {
    content_range
        .and_then(|value| value.rsplit_once('/').map(|(_, total)| total.trim()))
        .filter(|total| *total != "*")
        .and_then(|total| total.parse().ok())
        .or_else(|| content_length.and_then(|value| value.trim().parse().ok()))
}

/// Probe one candidate URL with the shared client pool.
///
/// Strategy: HEAD first (cheap, gives status + Content-Length). Only when
/// that looks positive do we spend a ranged GET for the first 1024 bytes.
/// The full archive is never downloaded.
async fn probe_candidate(
    url: &str,
    host_key: &str,
    base_type: &str,
    host: &str,
    candidate: &str,
    baselines: &[ResponseSample],
    magic_verify: bool,
    request: &RequestCtx,
) -> Option<BackupFinding> {
    let slot = probe::pick_pool_slot_for(host_key)?;

    // Step 1 - HEAD. Redirects are never followed: a 302 to a login page is
    // not a finding.
    gate_request(request, url).await;
    let head_resp = apply_request_ctx(
        slot.head(url)
            .redirect(wreq::redirect::Policy::none()),
        request,
    )
    .send()
    .await;

    let (mut status, mut content_length, mut content_type, mut method) = match head_resp {
        Ok(r) => {
            let s = r.status().as_u16();
            let cl = declared_object_length(
                r.headers().get("content-length").and_then(|v| v.to_str().ok()),
                r.headers().get("content-range").and_then(|v| v.to_str().ok()),
            )
            .or_else(|| r.content_length());
            let ct = r
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            (s, cl, ct, "HEAD".to_string())
        }
        Err(_) => (0, None, None, "HEAD".to_string()),
    };

    // A server that rejects HEAD tells us nothing - fall through to the
    // ranged GET rather than dropping a potentially real file.
    let head_unusable = status == 405 || status == 501 || status == 0;
    let worth_body = head_unusable || status == 200 || status == 206;
    if !worth_body {
        return None;
    }

    // Step 2 - ranged GET for the signature bytes only.
    let mut body_head: Vec<u8> = Vec::new();
    if magic_verify || head_unusable {
        gate_request(request, url).await;
        let get_resp = apply_request_ctx(
            slot.get(url)
                .redirect(wreq::redirect::Policy::none())
                .header("Range", "bytes=0-1023"),
            request,
        )
        .send()
        .await;
        if let Ok(r) = get_resp {
            status = r.status().as_u16();
            if content_length.is_none() {
                content_length = declared_object_length(
                    r.headers().get("content-length").and_then(|v| v.to_str().ok()),
                    r.headers().get("content-range").and_then(|v| v.to_str().ok()),
                )
                .or_else(|| r.content_length());
            }
            if content_type.is_none() {
                content_type = r
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
            }
            method = "GET(range)".to_string();
            if let Ok(b) = probe::read_body_capped(r, 1024).await {
                body_head = b;
            }
        }
    }

    let candidate_sample = ResponseSample {
        status,
        path: url::Url::parse(url)
            .map(|parsed| parsed.path().to_string())
            .unwrap_or_default(),
        body: body_head.clone(),
    };
    let baseline_similarity = baselines
        .iter()
        .map(|baseline| sample_similarity(&candidate_sample, baseline))
        .fold(0.0, f64::max);

    let ev = Evidence {
        status,
        content_length,
        content_type: content_type.as_deref(),
        body_head: &body_head,
        baseline_similarity,
        candidate,
    };
    let (verdict, confidence, magic, sql) = classify(&ev);
    if verdict == Verdict::Discarded {
        return None;
    }

    Some(BackupFinding {
        url: url.to_string(),
        base_type: base_type.to_string(),
        host: host.to_string(),
        candidate: candidate.to_string(),
        method,
        status,
        content_length,
        content_type,
        magic_matched: magic.map(|m| m.to_string()),
        sql_text_matched: sql,
        baseline_similarity,
        confidence,
        verdict,
        first_bytes_sha256: first_bytes_sha256(&body_head),
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Drop a `:port` suffix from an authority, leaving IPv6 literals intact.
pub fn strip_port(authority: &str) -> String {
    // IPv6 authorities are bracketed (`[::1]:8080`), so the port is whatever
    // follows the closing bracket - a bare `split(':')` would shred the address.
    if let Some(close) = authority.rfind(']') {
        return authority[..=close].to_string();
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
        _ => authority.to_string(),
    }
}

// ─────────────────────────────── phase runner ───────────────────────────────

/// Phase inputs. Only `token_extra` and `dry_run` come from the user - every
/// other decision (extensions, directory expansion, candidate cap, magic
/// verification, baseline calibration) is made at runtime from what the host
/// actually does.
pub struct PhaseOpts {
    pub cfg: BackupCfg,
    pub dry_run: bool,
    pub concurrency: usize,
    pub request: RequestCtx,
}

#[derive(Clone)]
pub struct RequestCtx {
    pub limiter: Arc<crate::fuzz::ratelimit::HostRateLimiter>,
    pub extra_headers: Vec<(String, String)>,
    pub cookie_header: Option<String>,
}

fn request_host_key(url: &str) -> String {
    let Ok(parsed) = url::Url::parse(url) else {
        return url.to_string();
    };
    let Some(host) = parsed.host_str() else {
        return url.to_string();
    };
    match parsed.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    }
}

async fn gate_request(ctx: &RequestCtx, url: &str) {
    ctx.limiter.acquire(&request_host_key(url)).await;
}

fn apply_request_ctx(mut req: wreq::RequestBuilder, ctx: &RequestCtx) -> wreq::RequestBuilder {
    for (name, value) in &ctx.extra_headers {
        req = req.header(name.as_str(), value.as_str());
    }
    if let Some(cookie) = &ctx.cookie_header {
        req = req.header("Cookie", cookie.as_str());
    }
    req
}

/// One request against the live base URL to learn the stack and how fast the
/// host answers. Both feed automatic decisions: stack picks the extension
/// ordering, latency scales the candidate cap so a slow or rate-limiting
/// host gets probed less aggressively than a fast one.
async fn profile_host(base: &str, host_key: &str, request: &RequestCtx) -> (Stack, usize) {
    let started = std::time::Instant::now();
    let slot = match probe::pick_pool_slot_for(host_key) {
        Some(s) => s,
        None => return (Stack::Unknown, 120),
    };
    gate_request(request, base).await;
    let resp = apply_request_ctx(
        slot.get(base)
            .redirect(wreq::redirect::Policy::none())
            .header("Range", "bytes=0-2047"),
        request,
    )
    .send()
    .await;

    let (stack, ok) = match resp {
        Ok(r) => {
            let server = r.headers().get("server").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            let powered = r
                .headers()
                .get("x-powered-by")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let body = probe::read_body_capped(r, 2048).await.unwrap_or_default();
            (stack_from_signals(server.as_deref(), powered.as_deref(), &body), true)
        }
        Err(_) => (Stack::Unknown, false),
    };

    // Latency-scaled cap. A host answering in well under a second can absorb
    // the full budget; a sluggish one gets a fraction of it. Never exceeds
    // the ceiling.
    let ms = started.elapsed().as_millis();
    let cap = if !ok {
        60
    } else if ms < 400 {
        MAX_PERMS_CEILING
    } else if ms < 1200 {
        180
    } else if ms < 3000 {
        100
    } else {
        50
    };
    (stack, cap)
}

async fn response_sample(
    url: &str,
    host_key: &str,
    request: &RequestCtx,
) -> Option<ResponseSample> {
    let slot = probe::pick_pool_slot_for(host_key)?;
    gate_request(request, url).await;
    let response = apply_request_ctx(
        slot.get(url)
            .redirect(wreq::redirect::Policy::none())
            .header("Range", "bytes=0-1023"),
        request,
    )
    .send()
    .await
    .ok()?;
    let status = response.status().as_u16();
    let body = probe::read_body_capped(response, 1024).await.ok()?;
    (!body.is_empty()).then_some(ResponseSample {
        status,
        path: url::Url::parse(url)
            .map(|parsed| parsed.path().to_string())
            .unwrap_or_default(),
        body,
    })
}

fn sample_is_distinct(sample: &ResponseSample, controls: &[ResponseSample]) -> bool {
    (sample.status == 200 || sample.status == 403)
        && !controls
            .iter()
            .any(|control| sample_similarity(sample, control) >= 0.95)
}

/// Verify backup-directory responses against impossible-path controls and
/// return the exact directories that differ. The remaining prefixes are only
/// checked after `backup/` or `bak/` is verified, preserving the bounded setup
/// cost on hosts with no backup-directory signal.
async fn verified_backup_dirs(
    root: &str,
    host_key: &str,
    request: &RequestCtx,
    file_controls: &[ResponseSample],
) -> Vec<String> {
    let mut controls = file_controls.to_vec();
    if let Ok(url) = join_url(root, "zzz-nonexistent-backup-dir-a1b2c3/") {
        if let Some(control) = response_sample(&url, host_key, request).await {
            controls.push(control);
        }
    }
    if controls.is_empty() {
        return Vec::new();
    }

    let mut found = Vec::new();
    for dir in ["backup", "bak"] {
        let Ok(url) = join_url(root, &format!("{}/", dir)) else {
            continue;
        };
        if let Some(sample) = response_sample(&url, host_key, request).await {
            if sample_is_distinct(&sample, &controls) {
                found.push(dir.to_string());
            }
        }
    }
    if found.is_empty() {
        return found;
    }

    for dir in BACKUP_DIRS {
        if *dir == "backup" || *dir == "bak" {
            continue;
        }
        let Ok(url) = join_url(root, &format!("{}/", dir)) else {
            continue;
        };
        if let Some(sample) = response_sample(&url, host_key, request).await {
            if sample_is_distinct(&sample, &controls) {
                found.push((*dir).to_string());
            }
        }
    }
    found
}

/// Run host-derived backup discovery across `hosts`.
///
/// Streams each finding through `on_finding` as soon as it clears the verdict
/// gate. Nothing here touches the wordlist probe path, so a change in this
/// function cannot regress normal fuzzing.
pub async fn run_phase<F>(hosts: &[String], opts: &PhaseOpts, mut on_finding: F) -> Result<usize>
where
    F: FnMut(&BackupFinding) -> Result<()>,
{
    use futures::stream::{FuturesUnordered, StreamExt};

    let mut finding_count = 0usize;
    let mut emitted_urls: HashSet<String> = HashSet::new();

    for raw_host in hosts {
        let bases = match normalize_base(raw_host) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("  [backup] skip {}: {}", raw_host, e);
                continue;
            }
        };
        let authority = bases.root.split("://").nth(1).unwrap_or("").to_string();
        // Strip the port before deriving tokens. A backup is named after the
        // site (`www.example.com.zip`), never after the socket
        // (`www.example.com:8443.zip`). The ported authority is still what we
        // key the client pool on, so only the token input is trimmed.
        let host_only = strip_port(&authority);
        // Deepest path segment feeds token rule 13.
        let seg = bases
            .dir
            .strip_prefix(&bases.root)
            .and_then(|p| p.trim_matches('/').split('/').next_back())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        // Learn the stack and a safe budget from the host itself. Skipped on
        // a dry run so previewing candidates never touches the network.
        let mut cfg = opts.cfg.clone();
        if !opts.dry_run {
            let (stack, cap) = probe::retry_wreq_pool_once(|| {
                profile_host(&bases.root, &host_only, &opts.request)
            })
            .await
            .unwrap_or((Stack::Unknown, 60));
            cfg.stack = stack;
            cfg.max_perms = cap.min(MAX_PERMS_CEILING);
            eprintln!(
                "  [backup] {} stack={:?} url_budget={}",
                host_only, stack, cfg.max_perms
            );
        }

        let candidates = generate_candidates(&host_only, seg.as_deref(), &cfg);

        // Soft-404 calibration keeps all successful controls. Similarity uses
        // the closest of the three after replacing each echoed request path,
        // so per-path catchalls cannot masquerade as archive content.
        let mut baselines: Vec<ResponseSample> = Vec::new();
        if !opts.dry_run {
            for probe_name in [
                "zzz-nonexistent-a1b2c3.zip",
                "zzz-nonexistent-d4e5f6.sql",
                "zzz-nonexistent-g7h8i9.tar.gz",
            ] {
                if let Ok(u) = join_url(&bases.root, probe_name) {
                    if let Some(value) = probe::retry_wreq_pool_once(|| {
                        response_sample(&u, &host_only, &opts.request)
                    })
                    .await
                    .unwrap_or(None)
                    {
                        baselines.push(value);
                    }
                }
            }
        }

        // Root and current directory share one URL budget. Verified backup
        // directories become exact bases rather than prefixes sprayed across
        // every possible directory name.
        let mut targets: Vec<(String, String)> = vec![("root".to_string(), bases.root.clone())];
        if bases.dir != bases.root {
            targets.push(("dir".to_string(), bases.dir.clone()));
        }
        if !opts.dry_run {
            let verified_dirs = probe::retry_wreq_pool_once(|| {
                verified_backup_dirs(&bases.root, &host_only, &opts.request, &baselines)
            })
            .await
            .unwrap_or_default();
            if !verified_dirs.is_empty() {
                eprintln!(
                    "  [backup] {} verified directories: {}",
                    host_only,
                    verified_dirs.join(",")
                );
            }
            for dir in verified_dirs {
                if let Ok(base) = join_url(&bases.root, &format!("{}/", dir)) {
                    targets.push((format!("backup-dir:{}", dir), base));
                }
            }
        }

        let queue = build_probe_queue(&candidates, &targets, cfg.max_perms);
        if opts.dry_run {
            eprintln!(
                "  [backup dry-run] {} maximum-url-budget={} bases={}",
                host_only,
                queue.len(),
                targets.len()
            );
            for (url, base_type, _) in &queue {
                eprintln!("  [backup dry-run] {} {}", base_type, url);
            }
            continue;
        }
        eprintln!(
            "  [backup] {} candidate_urls={} bases={}",
            host_only,
            queue.len(),
            targets.len()
        );

        // Bounded fan-out so the phase honours the caller's concurrency.
        let mut inflight = FuturesUnordered::new();
        let baselines = Arc::new(baselines);

        // Boxed so both spawn sites share one future type.
        type Task = std::pin::Pin<Box<dyn std::future::Future<Output = Option<BackupFinding>> + Send>>;
        let spawn = |idx: usize, queue: &[(String, String, String)]| -> Task {
            let (u, bt, c) = queue[idx].clone();
            let hk = host_only.clone();
            let ho = host_only.clone();
            let bl = baselines.clone();
            let request = opts.request.clone();
            Box::pin(async move {
                // Magic-byte verification is unconditional: it is the single
                // check that separates a real archive from an HTML soft-404
                // served with 200, so it is not something to make optional.
                probe::retry_wreq_pool_once(|| {
                    probe_candidate(
                        &u,
                        &hk,
                        &bt,
                        &ho,
                        &c,
                        bl.as_slice(),
                        true,
                        &request,
                    )
                })
                .await
                .unwrap_or(None)
            })
        };

        let mut next = 0usize;
        let cap = opts.concurrency.max(1);
        while next < queue.len() && inflight.len() < cap {
            inflight.push(spawn(next, &queue));
            next += 1;
        }
        while let Some(res) = inflight.next().await {
            if let Some(f) = res {
                // Distinct URLs are distinct findings even when their first
                // archive block is identical. Only collapse duplicate joins.
                if emitted_urls.insert(f.url.clone()) {
                    on_finding(&f)?;
                    finding_count += 1;
                }
            }
            if next < queue.len() {
                inflight.push(spawn(next, &queue));
                next += 1;
            }
        }
    }

    Ok(finding_count)
}

/// Human-readable stream for CONFIRMED findings only.
pub fn print_confirmed_finding(finding: &BackupFinding, header_printed: &mut bool) {
    if finding.verdict != Verdict::Confirmed {
        return;
    }
    if !*header_printed {
        eprintln!();
        eprintln!("  CONFIRMED host-derived backups");
        eprintln!("  {:<58} {:>6} {:>12}  {}", "URL", "STATUS", "SIZE", "TYPE");
        *header_printed = true;
    }
    eprintln!(
        "  {:<58} {:>6} {:>12}  {}",
        if finding.url.len() > 58 { &finding.url[..58] } else { &finding.url },
        finding.status,
        finding.content_length.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
        finding.magic_matched.as_deref().unwrap_or("sql-text"),
    );
}

// ───────────────────────────────── tests ─────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ---- base normalization: the twelve required vectors ----

    fn bases(u: &str) -> Bases {
        normalize_base(u).expect("normalize")
    }

    #[test]
    fn vec01_no_trailing_slash() {
        let b = bases("https://www.abc.com");
        assert_eq!(join_url(&b.root, ".env").unwrap(), "https://www.abc.com/.env");
    }

    #[test]
    fn vec02_trailing_slash() {
        let b = bases("https://www.abc.com/");
        assert_eq!(join_url(&b.root, ".env").unwrap(), "https://www.abc.com/.env");
    }

    #[test]
    fn vec03_double_trailing_slash() {
        let b = bases("https://www.abc.com//");
        assert_eq!(b.dir, "https://www.abc.com");
        assert_eq!(join_url(&b.dir, ".env").unwrap(), "https://www.abc.com/.env");
    }

    #[test]
    fn vec04_dir_no_slash_emits_both() {
        let b = bases("https://www.abc.com/portal");
        assert_eq!(
            join_url(&b.dir, ".git/HEAD").unwrap(),
            "https://www.abc.com/portal/.git/HEAD"
        );
        assert_eq!(
            join_url(&b.root, ".git/HEAD").unwrap(),
            "https://www.abc.com/.git/HEAD"
        );
    }

    #[test]
    fn vec05_dir_with_slash_same_as_04() {
        let a = bases("https://www.abc.com/portal");
        let b = bases("https://www.abc.com/portal/");
        assert_eq!(a, b);
    }

    #[test]
    fn vec06_file_drops_to_parent_dir() {
        let b = bases("https://www.abc.com/a/index.php");
        assert_eq!(
            join_url(&b.dir, "backup.zip").unwrap(),
            "https://www.abc.com/a/backup.zip"
        );
        assert_eq!(
            join_url(&b.root, "backup.zip").unwrap(),
            "https://www.abc.com/backup.zip"
        );
    }

    #[test]
    fn vec07_query_and_fragment_dropped() {
        let b = bases("https://www.abc.com/a/b?x=1#frag");
        assert_eq!(
            join_url(&b.dir, "crx/de/index.jsp").unwrap(),
            "https://www.abc.com/a/b/crx/de/index.jsp"
        );
    }

    #[test]
    fn vec08_repeated_slashes_collapse() {
        let b = bases("https://www.abc.com/a//b//");
        assert_eq!(
            join_url(&b.dir, "wp-config.php").unwrap(),
            "https://www.abc.com/a/b/wp-config.php"
        );
    }

    #[test]
    fn vec09_dot_dot_resolved() {
        let b = bases("https://www.abc.com/a/../b/");
        assert_eq!(join_url(&b.dir, ".env").unwrap(), "https://www.abc.com/b/.env");
    }

    #[test]
    fn vec10_non_default_port_preserved() {
        let b = bases("https://www.abc.com:8443/app");
        assert_eq!(
            join_url(&b.dir, "www.abc.com.zip").unwrap(),
            "https://www.abc.com:8443/app/www.abc.com.zip"
        );
        assert_eq!(
            join_url(&b.root, "www.abc.com.zip").unwrap(),
            "https://www.abc.com:8443/www.abc.com.zip"
        );
    }

    #[test]
    fn vec11_directory_entry_keeps_trailing_slash() {
        let b = bases("https://www.abc.com/dir");
        assert_eq!(
            join_url(&b.dir, "backup-db/").unwrap(),
            "https://www.abc.com/dir/backup-db/"
        );
    }

    #[test]
    fn vec12_ip_literal_root() {
        let b = bases("http://192.168.1.10/");
        assert_eq!(
            join_url(&b.root, "dump.sql").unwrap(),
            "http://192.168.1.10/dump.sql"
        );
    }

    // ---- runtime invariants ----

    #[test]
    fn invariant_rejects_double_slash() {
        assert!(join_url("https://a.com/x/", "/y").is_ok());
        // A base that still carries "//" internally must be rejected.
        assert!(join_url("https://a.com//x", "y").is_err());
    }

    #[test]
    fn invariant_separator_always_present() {
        let u = join_url("https://abc.com", "dump.sql").unwrap();
        assert!(u.starts_with("https://abc.com/"));
        assert!(!u.contains("comdump.sql"));
    }

    // ---- token derivation: the seven required hosts ----

    #[test]
    fn tokens_plain_domain() {
        let t = derive_tokens("abc.com", None);
        assert!(t.contains(&"abc.com".to_string()));
        assert!(t.contains(&"abc".to_string()));
        assert!(t.contains(&"abc_com".to_string()));
        assert!(t.contains(&"abc-com".to_string()));
        assert!(t.contains(&"abccom".to_string()));
    }

    #[test]
    fn tokens_www_stripped() {
        let t = derive_tokens("www.abc.com", None);
        assert!(t.contains(&"www.abc.com".to_string()));
        assert!(t.contains(&"abc.com".to_string()));
        assert!(t.contains(&"abc".to_string()));
        assert!(t.contains(&"www_abc_com".to_string()));
        assert!(t.contains(&"wwwabccom".to_string()));
        assert!(t.contains(&"www".to_string()));
    }

    #[test]
    fn tokens_compound_tld_uses_psl() {
        let t = derive_tokens("dev-api.abc.co.uk", None);
        // The registrable domain must be abc.co.uk, not co.uk.
        assert!(t.contains(&"abc.co.uk".to_string()), "tokens: {:?}", t);
        assert!(t.contains(&"abc".to_string()));
        assert!(t.contains(&"dev-api".to_string()));
        assert!(t.contains(&"dev_api".to_string()));
        assert!(!t.contains(&"co".to_string()));
    }

    #[test]
    fn tokens_deep_subdomain() {
        let t = derive_tokens("a.b.c.example.org", None);
        assert!(t.contains(&"example.org".to_string()));
        assert!(t.contains(&"example".to_string()));
        assert!(t.contains(&"a".to_string()));
        assert!(t.contains(&"a.b.c.example".to_string()));
    }

    #[test]
    fn tokens_ip_literal_not_split() {
        let t = derive_tokens("192.168.1.10", None);
        assert!(t.contains(&"192.168.1.10".to_string()));
        assert!(t.contains(&"192_168_1_10".to_string()));
        // An IP has no SLD - we must not invent one.
        assert!(!t.contains(&"192".to_string()));
    }

    #[test]
    fn tokens_punycode_host() {
        let t = derive_tokens("xn--80ak6aa92e.com", None);
        assert!(t.contains(&"xn--80ak6aa92e.com".to_string()));
        assert!(t.contains(&"xn--80ak6aa92e".to_string()));
    }

    #[test]
    fn tokens_trailing_dot_normalized() {
        let a = derive_tokens("abc.com.", None);
        let b = derive_tokens("abc.com", None);
        assert_eq!(a, b);
    }

    #[test]
    fn port_stripped_before_token_derivation() {
        // Regression: the phase used to feed `host:port` into the token
        // derivation, producing candidates like `www.abc.com:8443.zip`.
        assert_eq!(strip_port("www.abc.com:8443"), "www.abc.com");
        assert_eq!(strip_port("www.abc.com"), "www.abc.com");
        assert_eq!(strip_port("[2001:db8::1]:8443"), "[2001:db8::1]");
        assert_eq!(strip_port("[2001:db8::1]"), "[2001:db8::1]");
        let t = derive_tokens(&strip_port("www.abc.com:8443"), None);
        assert!(t.contains(&"www.abc.com".to_string()));
        assert!(!t.iter().any(|x| x.contains(':')));
    }

    #[test]
    fn tokens_path_segment_included() {
        let t = derive_tokens("abc.com", Some("portal"));
        assert!(t.contains(&"portal".to_string()));
    }

    // ---- candidate generation ----

    #[test]
    fn candidates_respect_max_perms() {
        let cfg = BackupCfg { max_perms: 25, ..Default::default() };
        let c = generate_candidates("www.abc.com", None, &cfg);
        assert_eq!(c.len(), 25);
    }

    #[test]
    fn automatic_cap_tiers_keep_mandatory_backup_coverage() {
        for cap in [50, 60, 100, 180, 300] {
            let cfg = BackupCfg { max_perms: cap, ..Default::default() };
            let candidates = generate_candidates("www.abc.com", None, &cfg);
            assert_eq!(candidates.len(), cap, "cap={}", cap);
            for required in [
                "www.abc.com.zip",
                "abc.com.zip",
                "abc.zip",
                "backup.zip",
                "backup.sql",
                "backup.tar.gz",
                "site.zip",
                "www.abc.com_backup.zip",
                "www.abc.com-2026.zip",
            ] {
                assert!(
                    candidates.iter().any(|candidate| candidate == required),
                    "cap={} missing {}",
                    cap,
                    required
                );
            }
        }
    }

    #[test]
    fn automatic_cap_tiers_are_global_across_all_bases() {
        let cfg = BackupCfg::default();
        let candidates = generate_candidates("www.abc.com", Some("portal"), &cfg);
        let targets = vec![
            ("root".to_string(), "https://www.abc.com".to_string()),
            ("dir".to_string(), "https://www.abc.com/portal".to_string()),
            (
                "backup-dir:backup".to_string(),
                "https://www.abc.com/backup".to_string(),
            ),
        ];
        for cap in [50, 60, 100, 180, 300] {
            let queue = build_probe_queue(&candidates, &targets, cap);
            assert_eq!(queue.len(), cap, "cap={}", cap);
            let unique: HashSet<&String> = queue.iter().map(|(url, _, _)| url).collect();
            assert_eq!(unique.len(), cap, "cap={}", cap);
            for base_type in ["root", "dir", "backup-dir:backup"] {
                assert!(
                    queue.iter().any(|(_, kind, _)| kind == base_type),
                    "cap={} missing base {}",
                    cap,
                    base_type
                );
            }
        }
    }

    #[test]
    fn path_echo_controls_do_not_verify_a_wildcard_directory() {
        let control = ResponseSample {
            status: 200,
            path: "/zzz-nonexistent-backup-dir-a1b2c3/".to_string(),
            body: b"not found path=/zzz-nonexistent-backup-dir-a1b2c3/; end".to_vec(),
        };
        let wildcard = ResponseSample {
            status: 200,
            path: "/backup/".to_string(),
            body: b"not found path=/backup/; end".to_vec(),
        };
        let real = ResponseSample {
            status: 200,
            path: "/backup/".to_string(),
            body: b"<html><title>Index of /backup/</title></html>".to_vec(),
        };

        assert!(sample_similarity(&control, &wildcard) >= 0.95);
        assert!(!sample_is_distinct(&wildcard, std::slice::from_ref(&control)));
        assert!(sample_is_distinct(&real, &[control]));
    }

    #[test]
    fn first_bytes_sha256_is_really_sha256() {
        assert_eq!(
            first_bytes_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(first_bytes_sha256(b"archive").len(), 64);
    }

    #[test]
    fn declared_length_uses_header_and_range_total() {
        assert_eq!(declared_object_length(Some("356"), None), Some(356));
        assert_eq!(
            declared_object_length(Some("1024"), Some("bytes 0-1023/90000")),
            Some(90_000)
        );
        assert_eq!(declared_object_length(None, Some("bytes */*")), None);
    }

    #[test]
    fn candidates_p1_comes_first() {
        let cfg = BackupCfg::default();
        let c = generate_candidates("www.abc.com", None, &cfg);
        assert_eq!(c[0], "www.abc.com.zip");
        assert!(c.contains(&"abc.com.zip".to_string()));
        assert!(c.contains(&"abc.zip".to_string()));
    }

    #[test]
    fn candidates_are_unique() {
        let cfg = BackupCfg::default();
        let c = generate_candidates("www.abc.com", None, &cfg);
        let uniq: HashSet<&String> = c.iter().collect();
        assert_eq!(uniq.len(), c.len());
    }

    // ---- detection ----

    #[test]
    fn stack_detection_from_headers_and_body() {
        assert_eq!(stack_from_signals(Some("Apache"), Some("PHP/8.1"), b""), Stack::Php);
        assert_eq!(stack_from_signals(Some("Apache-Coyote/1.1"), None, b""), Stack::Unknown);
        assert_eq!(stack_from_signals(Some("nginx"), None, b"Set-Cookie: JSESSIONID=x"), Stack::Java);
        assert_eq!(stack_from_signals(Some("Microsoft-IIS/10.0"), None, b""), Stack::DotNet);
        assert_eq!(stack_from_signals(None, Some("Express"), b""), Stack::Node);
        assert_eq!(stack_from_signals(Some("gunicorn/20"), None, b""), Stack::Python);
        assert_eq!(stack_from_signals(Some("nginx"), None, b"<html>hi</html>"), Stack::Unknown);
        // A PHP banner must win over a generic server hint.
        assert_eq!(
            stack_from_signals(Some("Microsoft-IIS/10.0"), Some("PHP/7.4"), b""),
            Stack::Php
        );
    }

    #[test]
    fn java_stack_prioritises_war_files() {
        let java = BackupCfg { stack: Stack::Java, ..Default::default() };
        let php = BackupCfg { stack: Stack::Php, ..Default::default() };
        let cj = generate_candidates("abc.com", None, &java);
        let cp = generate_candidates("abc.com", None, &php);
        let war_j = cj.iter().position(|c| c == "abc.com.war");
        let war_p = cp.iter().position(|c| c == "abc.com.war");
        // Both still cover .war - only the ordering differs.
        assert!(war_j.is_some() && war_p.is_some());
        assert!(war_j.unwrap() < war_p.unwrap(), "java should reach .war sooner");
    }

    #[test]
    fn unknown_stack_keeps_full_coverage() {
        let cfg = BackupCfg { stack: Stack::Unknown, max_perms: 5000, ..Default::default() };
        let c = generate_candidates("abc.com", None, &cfg);
        // Nothing is dropped when the stack probe is inconclusive.
        for ext in [".zip", ".sql", ".war", ".iso", ".bak"] {
            assert!(c.contains(&format!("abc.com{}", ext)), "missing {}", ext);
        }
    }

    #[test]
    fn cap_never_exceeds_ceiling() {
        let cfg = BackupCfg { max_perms: MAX_PERMS_CEILING, ..Default::default() };
        let c = generate_candidates("a.b.c.example.org", None, &cfg);
        assert!(c.len() <= MAX_PERMS_CEILING);
    }

    #[test]
    fn magic_detects_zip_and_gzip() {
        assert_eq!(magic_match(&[0x50, 0x4B, 0x03, 0x04, 0x00]), Some("zip"));
        assert_eq!(magic_match(&[0x1F, 0x8B, 0x08]), Some("gzip"));
        assert_eq!(magic_match(b"<html><body>nope"), None);
    }

    #[test]
    fn magic_detects_sqlite() {
        let mut b = b"SQLite format 3\x00".to_vec();
        b.extend_from_slice(&[0u8; 16]);
        assert_eq!(magic_match(&b), Some("sqlite"));
    }

    #[test]
    fn sql_text_detected() {
        assert!(sql_text_match(b"-- MySQL dump 10.13  Distrib 8.0.32"));
        assert!(sql_text_match(b"DROP TABLE IF EXISTS `users`;"));
        assert!(!sql_text_match(b"<html>404 not found</html>"));
    }

    #[test]
    fn html_on_zip_candidate_is_discarded() {
        let ev = Evidence {
            status: 200,
            content_length: Some(5000),
            content_type: Some("text/html; charset=utf-8"),
            body_head: b"<html><body>Not Found</body></html>",
            baseline_similarity: 0.10,
            candidate: "abc.com.zip",
        };
        let (v, _, _, _) = classify(&ev);
        assert_eq!(v, Verdict::Discarded);
    }

    #[test]
    fn real_zip_is_confirmed() {
        let mut body = vec![0x50, 0x4B, 0x03, 0x04];
        body.extend_from_slice(&[0u8; 100]);
        let ev = Evidence {
            status: 200,
            content_length: Some(90_000),
            content_type: Some("application/zip"),
            body_head: &body,
            baseline_similarity: 0.05,
            candidate: "abc.com.zip",
        };
        let (v, conf, magic, _) = classify(&ev);
        assert_eq!(v, Verdict::Confirmed);
        assert!(conf >= 0.95);
        assert_eq!(magic, Some("zip"));
    }

    #[test]
    fn soft_404_baseline_match_is_discarded() {
        let ev = Evidence {
            status: 200,
            content_length: Some(3000),
            content_type: Some("text/html"),
            body_head: b"<html>generic 404 template</html>",
            baseline_similarity: 0.99,
            candidate: "abc.com.zip",
        };
        let (v, _, _, _) = classify(&ev);
        assert_eq!(v, Verdict::Discarded);
    }

    #[test]
    fn forbidden_is_review_not_confirmed() {
        let ev = Evidence {
            status: 403,
            content_length: Some(500),
            content_type: Some("text/html"),
            body_head: b"forbidden",
            baseline_similarity: 0.0,
            candidate: "abc.com.zip",
        };
        let (v, _, _, _) = classify(&ev);
        assert_eq!(v, Verdict::Review);
    }

    #[test]
    fn redirect_is_not_a_finding() {
        let ev = Evidence {
            status: 302,
            content_length: Some(0),
            content_type: None,
            body_head: b"",
            baseline_similarity: 0.0,
            candidate: "abc.com.zip",
        };
        let (v, _, _, _) = classify(&ev);
        assert_eq!(v, Verdict::Discarded);
    }

    #[test]
    fn waf_interstitial_is_discarded() {
        let ev = Evidence {
            status: 200,
            content_length: Some(4000),
            content_type: Some("text/html"),
            body_head: b"<html>Attention Required! | Cloudflare cf-ray</html>",
            baseline_similarity: 0.0,
            candidate: "abc.com.zip",
        };
        let (v, _, _, _) = classify(&ev);
        assert_eq!(v, Verdict::Discarded);
    }

    #[test]
    fn tiny_body_below_size_floor_discarded() {
        let ev = Evidence {
            status: 200,
            content_length: Some(12),
            content_type: Some("application/octet-stream"),
            body_head: b"short",
            baseline_similarity: 0.0,
            candidate: "abc.com.zip",
        };
        let (v, _, _, _) = classify(&ev);
        assert_eq!(v, Verdict::Discarded);
    }
}
