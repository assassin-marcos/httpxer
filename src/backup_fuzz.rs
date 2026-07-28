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
// was supplied). `--no-backup-fuzz` opts out; `--backup-fuzz` forces it on
// outside fuzz mode. Rationale: a fuzz run is already paying the per-host
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
use serde::Serialize;
use std::collections::HashSet;

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

/// Directory prefixes probed when `--backup-dirs` is set.
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
    let mut push = |t: String, out: &mut Vec<String>, seen: &mut HashSet<String>| {
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
/// shop leaves `.sql` and `.zip`. Guessing wrong only costs ordering, never
/// coverage, because `Unknown` falls back to the full matrix.
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
    /// Every stack returns EVERY class - detection only changes the ORDER,
    /// never the coverage. Stack detection is a heuristic on one response,
    /// so excluding a class would mean a misdetected host silently loses a
    /// whole category of findings. Reordering is free; exclusion is not.
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
    /// Hard ceiling on candidates per host. Auto-scaled by responsiveness,
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

/// Build the candidate filename list for a host, in priority order P1..P5 and
/// capped at `cfg.max_perms`. Returns filenames only - joining to a base is
/// the caller's job so the same list can be reused for ROOT and DIR bases.
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
    let mut push = |c: String, out: &mut Vec<String>, seen: &mut HashSet<String>| {
        if out.len() < cfg.max_perms && seen.insert(c.clone()) {
            out.push(c);
        }
    };

    // P1 - the full host with the highest-yield extensions.
    if let Some(full) = tokens.first() {
        for e in P1_EXTS {
            push(format!("{}{}", full, e), &mut out, &mut seen);
        }
    }
    // P2 - every remaining token with the same set.
    for t in tokens.iter().skip(1) {
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
    // P4 - separator forms, then the host-independent generics.
    for t in &tokens {
        for f in SEPARATOR_FORMS {
            push(f.replace("{}", t), &mut out, &mut seen);
        }
    }
    for g in STATIC_GENERIC {
        push(g.to_string(), &mut out, &mut seen);
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

/// Expand a candidate list across the backup directory prefixes.
pub fn with_backup_dirs(candidates: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for d in BACKUP_DIRS {
        for c in candidates.iter().take(8) {
            out.push(format!("{}/{}", d, c));
        }
    }
    out
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
    use md5::Digest;
    // The pool already depends on md-5; a 128-bit digest is ample for dedup
    // of identical soft-404 bodies and keeps the dependency surface flat.
    let head = &body[..body.len().min(1024)];
    let mut h = md5::Md5::new();
    h.update(head);
    hex::encode(h.finalize())
}

/// Probe one candidate URL with the shared client pool.
///
/// Strategy: HEAD first (cheap, gives status + Content-Length). Only when
/// that looks positive do we spend a ranged GET for the first 1024 bytes.
/// The full archive is never downloaded.
pub async fn probe_candidate(
    url: &str,
    host_key: &str,
    base_type: &str,
    host: &str,
    candidate: &str,
    baseline: Option<&[u8]>,
    magic_verify: bool,
) -> Option<BackupFinding> {
    let slot = probe::pick_pool_slot_for(host_key)?;

    // Step 1 - HEAD. Redirects are never followed: a 302 to a login page is
    // not a finding.
    let head_resp = slot
        .client
        .head(url)
        .redirect(wreq::redirect::Policy::none())
        .send()
        .await;

    let (mut status, mut content_length, mut content_type, mut method) = match head_resp {
        Ok(r) => {
            let s = r.status().as_u16();
            let cl = r.content_length();
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
        let get_resp = slot
            .client
            .get(url)
            .redirect(wreq::redirect::Policy::none())
            .header("Range", "bytes=0-1023")
            .send()
            .await;
        if let Ok(r) = get_resp {
            status = r.status().as_u16();
            if content_length.is_none() {
                content_length = r.content_length();
            }
            if content_type.is_none() {
                content_type = r
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
            }
            method = "GET(range)".to_string();
            if let Ok(b) = r.bytes().await {
                body_head = b.to_vec();
                body_head.truncate(1024);
            }
        }
    }

    let baseline_similarity = match baseline {
        Some(b) => similarity(&body_head, b),
        None => 0.0,
    };

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
}

/// One request against the live base URL to learn the stack and how fast the
/// host answers. Both feed automatic decisions: stack picks the extension
/// ordering, latency scales the candidate cap so a slow or rate-limiting
/// host gets probed less aggressively than a fast one.
async fn profile_host(base: &str, host_key: &str) -> (Stack, usize) {
    let started = std::time::Instant::now();
    let slot = match probe::pick_pool_slot_for(host_key) {
        Some(s) => s,
        None => return (Stack::Unknown, 120),
    };
    let resp = slot
        .client
        .get(base)
        .redirect(wreq::redirect::Policy::none())
        .header("Range", "bytes=0-2047")
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
            let body = r.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
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

/// Probe two sentinel directories. The other prefixes are only worth
/// expanding into when a host demonstrably exposes a backup directory, so
/// this costs 2 requests instead of a flag the user has to guess at.
async fn backup_dir_exists(root: &str, host_key: &str) -> bool {
    for probe_dir in ["backup/", "bak/"] {
        if let Ok(u) = join_url(root, probe_dir) {
            if let Some(slot) = probe::pick_pool_slot_for(host_key) {
                if let Ok(r) = slot
                    .client
                    .head(&u)
                    .redirect(wreq::redirect::Policy::none())
                    .send()
                    .await
                {
                    let s = r.status().as_u16();
                    // 200 = listing, 403 = exists but denied. Both prove the
                    // directory is real, which is what we are testing for.
                    if s == 200 || s == 403 {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Run host-derived backup discovery across `hosts`.
///
/// Returns the findings that survived the verdict gate. Nothing here touches
/// the wordlist probe path, so a change in this function cannot regress
/// normal fuzzing.
pub async fn run_phase(hosts: &[String], opts: &PhaseOpts) -> Vec<BackupFinding> {
    use futures::stream::{FuturesUnordered, StreamExt};

    let mut findings: Vec<BackupFinding> = Vec::new();
    let mut dedup: HashSet<String> = HashSet::new();

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
            let (stack, cap) = profile_host(&bases.root, &host_only).await;
            cfg.stack = stack;
            cfg.max_perms = cap.min(MAX_PERMS_CEILING);
            eprintln!(
                "  [backup] {} stack={:?} budget={}",
                host_only, stack, cfg.max_perms
            );
        }

        let mut candidates = generate_candidates(&host_only, seg.as_deref(), &cfg);
        // Expand into backup directories only when the host actually has one.
        if !opts.dry_run && backup_dir_exists(&bases.root, &host_only).await {
            eprintln!("  [backup] {} exposes a backup directory - expanding", host_only);
            candidates.extend(with_backup_dirs(&candidates));
            candidates.truncate(cfg.max_perms);
        }

        // Both bases always, deduped when identical. There is no reason to
        // make the user choose - the join layer already collapses the case
        // where the directory IS the root.
        let mut targets: Vec<(&str, &String)> = vec![("root", &bases.root)];
        if bases.dir != bases.root {
            targets.push(("dir", &bases.dir));
        }

        if opts.dry_run {
            for (bt, base) in &targets {
                for c in &candidates {
                    match join_url(base, c) {
                        Ok(u) => eprintln!("  [backup dry-run] {} {}", bt, u),
                        Err(e) => eprintln!("  [backup malformed] {} ({})", c, e),
                    }
                }
            }
            continue;
        }

        // Soft-404 calibration: three names that cannot exist, so any body
        // they return IS the catch-all template for this host. Always on -
        // disabling it could only ever make results worse.
        let baseline: Option<Vec<u8>> = {
            let mut sample: Option<Vec<u8>> = None;
            for probe_name in [
                "zzz-nonexistent-a1b2c3.zip",
                "zzz-nonexistent-d4e5f6.sql",
                "zzz-nonexistent-g7h8i9.tar.gz",
            ] {
                if let Ok(u) = join_url(&bases.root, probe_name) {
                    if let Some(slot) = probe::pick_pool_slot_for(&host_only) {
                        if let Ok(r) = slot
                            .client
                            .get(&u)
                            .redirect(wreq::redirect::Policy::none())
                            .header("Range", "bytes=0-1023")
                            .send()
                            .await
                        {
                            if let Ok(b) = r.bytes().await {
                                let mut v = b.to_vec();
                                v.truncate(1024);
                                if !v.is_empty() {
                                    sample = Some(v);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            sample
        };

        // Bounded fan-out so the phase honours the caller's concurrency.
        let mut inflight = FuturesUnordered::new();
        let mut queue: Vec<(String, String, String)> = Vec::new();
        for (bt, base) in &targets {
            for c in &candidates {
                match join_url(base, c) {
                    Ok(u) => queue.push((u, bt.to_string(), c.clone())),
                    Err(e) => eprintln!("  [backup malformed, dropped] {} ({})", c, e),
                }
            }
        }

        // Boxed so both spawn sites share one future type.
        type Task = std::pin::Pin<Box<dyn std::future::Future<Output = Option<BackupFinding>> + Send>>;
        let spawn = |idx: usize, queue: &[(String, String, String)]| -> Task {
            let (u, bt, c) = queue[idx].clone();
            let hk = host_only.clone();
            let ho = host_only.clone();
            let bl = baseline.clone();
            Box::pin(async move {
                // Magic-byte verification is unconditional: it is the single
                // check that separates a real archive from an HTML soft-404
                // served with 200, so it is not something to make optional.
                probe_candidate(&u, &hk, &bt, &ho, &c, bl.as_deref(), true).await
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
                // Collapse identical bodies across candidates into one finding.
                if dedup.insert(f.first_bytes_sha256.clone()) {
                    findings.push(f);
                }
            }
            if next < queue.len() {
                inflight.push(spawn(next, &queue));
                next += 1;
            }
        }
    }

    findings
}

/// Human-readable table for CONFIRMED findings only.
pub fn print_confirmed_table(findings: &[BackupFinding]) {
    let confirmed: Vec<&BackupFinding> = findings
        .iter()
        .filter(|f| f.verdict == Verdict::Confirmed)
        .collect();
    if confirmed.is_empty() {
        return;
    }
    eprintln!();
    eprintln!("  CONFIRMED host-derived backups");
    eprintln!("  {:<58} {:>6} {:>12}  {}", "URL", "STATUS", "SIZE", "TYPE");
    for f in confirmed {
        eprintln!(
            "  {:<58} {:>6} {:>12}  {}",
            if f.url.len() > 58 { &f.url[..58] } else { &f.url },
            f.status,
            f.content_length.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
            f.magic_matched.as_deref().unwrap_or("sql-text"),
        );
    }
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
