//! Self-update + version-check banner — direct port of portwave's update flow.
//!
//! Three user-visible features:
//!   1. `httpxer -u` / `--update`        — install the latest release in place
//!   2. `httpxer -c` / `--check-update`  — print version status and exit
//!   3. Startup banner (stderr only)     — auto-detects outdated installs and
//!                                          shows "What's new" notes since the
//!                                          user's current version
//!
//! The banner uses a 24 h on-disk cache (`$XDG_CACHE_HOME/httpxer/last_check`
//! or `%LOCALAPPDATA%\httpxer\last_check`) so the common case is zero network
//! cost at startup. A best-effort 2.5 s refresh runs every >120 s so the
//! cache stays current without hammering GitHub on tight-loop invocations.
//!
//! The tags-API peek catches the brief window where a tag has been pushed
//! but the release-CI hasn't published binaries yet — without it, the
//! Releases-API-only path would tell users "you're up to date" for ~5
//! minutes after every tag.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub const REPO_OWNER: &str = "assassin-marcos";
pub const REPO_NAME: &str = "httpxer";

fn update_cache_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|a| PathBuf::from(a).join("httpxer").join("last_check"))
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".cache/httpxer/last_check"))
    }
}

/// Read the cached "latest release version" written by the most recent
/// `refresh_update_cache_best_effort` call. Returns None if the cache is
/// missing, unreadable, or older than 24 h. Used by the startup banner.
pub fn cached_latest_version() -> Option<String> {
    let p = update_cache_path()?;
    let meta = fs::metadata(&p).ok()?;
    let age = meta.modified().ok()?.elapsed().ok()?;
    if age > Duration::from_secs(24 * 3_600) {
        return None;
    }
    let s = fs::read_to_string(&p).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Eager non-blocking refresh of the update cache so the banner reflects
/// current GitHub state, not a stale value from hours ago. 120 s fast-path
/// skip avoids hammering GitHub when users run httpxer in tight loops.
/// 2500 ms budget on the slow path — long enough for the TLS handshake +
/// API response on real-world slow networks, short enough to feel instant.
pub async fn refresh_update_cache_best_effort() {
    let p = match update_cache_path() {
        Some(p) => p,
        None => return,
    };
    if let Ok(meta) = fs::metadata(&p) {
        if let Some(age) = meta.modified().ok().and_then(|t| t.elapsed().ok()) {
            if age < Duration::from_secs(120) {
                return;
            }
        }
    }
    let res = tokio::time::timeout(
        Duration::from_millis(2500),
        tokio::task::spawn_blocking(fetch_latest_version),
    )
    .await;
    if let Ok(Ok(Ok(Some(v)))) = res {
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&p, v);
    }
}

/// Sync — meant for `spawn_blocking`. Returns the version of the latest
/// published GitHub Release (without leading 'v'). A release exists only
/// after CI uploads at least one asset, so this lags tag creation by a
/// few minutes — `fetch_latest_tag` covers that gap.
pub fn fetch_latest_version() -> anyhow::Result<Option<String>> {
    let releases = self_update::backends::github::ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()?
        .fetch()?;
    Ok(releases.first().map(|r| r.version.clone()))
}

/// Release-notes ladder — (version, body) for every release strictly newer
/// than `current`, newest-first. Drives the "What's new" listing the
/// `--update` flow prints after a successful install.
pub fn fetch_release_notes_since(current: &str) -> anyhow::Result<Vec<(String, String)>> {
    let releases = self_update::backends::github::ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()?
        .fetch()?;
    let mut out: Vec<(String, String)> = Vec::new();
    for r in releases {
        if version_is_newer(&r.version, current) {
            out.push((r.version.clone(), r.body.clone().unwrap_or_default()));
        }
    }
    Ok(out)
}

/// Direct GitHub /tags read. Tags appear immediately on push (before CI
/// has built release binaries), so this catches the few-minute window
/// where `fetch_latest_version` still reports the previous release.
pub fn fetch_latest_tag() -> anyhow::Result<Option<String>> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/tags?per_page=20",
        REPO_OWNER, REPO_NAME
    );
    let resp = ureq::get(&url)
        .set("User-Agent", concat!("httpxer/", env!("CARGO_PKG_VERSION")))
        .set("Accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(4))
        .call()?;
    let tags: serde_json::Value = resp.into_json()?;
    let mut best: Option<(Vec<u32>, String)> = None;
    if let Some(arr) = tags.as_array() {
        for t in arr {
            if let Some(name) = t.get("name").and_then(|n| n.as_str()) {
                let stripped = name.trim_start_matches('v').to_string();
                let parts: Vec<u32> = stripped
                    .split('.')
                    .map(|p| p.split('-').next().unwrap_or(""))
                    .filter_map(|p| p.parse::<u32>().ok())
                    .collect();
                if parts.is_empty() {
                    continue;
                }
                if best.as_ref().map_or(true, |(b, _)| parts > *b) {
                    best = Some((parts, stripped));
                }
            }
        }
    }
    Ok(best.map(|(_, s)| s))
}

/// Component-wise semver-ish compare. Strips leading 'v' and any
/// `-suffix` (e.g. `0.3.0-rc1` → `0.3.0`). True when `latest > current`.
pub fn version_is_newer(latest: &str, current: &str) -> bool {
    fn parse(s: &str) -> Vec<u32> {
        s.trim_start_matches('v')
            .split('.')
            .map(|p| p.split('-').next().unwrap_or(""))
            .filter_map(|p| p.parse::<u32>().ok())
            .collect()
    }
    let l = parse(latest);
    let c = parse(current);
    for i in 0..l.len().max(c.len()) {
        let a = *l.get(i).unwrap_or(&0);
        let b = *c.get(i).unwrap_or(&0);
        if a != b {
            return a > b;
        }
    }
    false
}

/// Startup banner — yellow "[!] update available" line on stderr, plus a
/// "What's new" block listing release notes for every version between the
/// user's install and the latest. Truncated to keep enrichment output
/// readable on tight terminals.
pub fn print_update_banner(latest: &str, notes: &[(String, String)]) {
    eprintln!();
    eprintln!(
        "\x1b[33m[!] httpxer update available: {} → {}\x1b[0m",
        env!("CARGO_PKG_VERSION"),
        latest
    );
    if !notes.is_empty() {
        eprintln!();
        eprintln!("\x1b[1mWhat's new:\x1b[0m");
        for (ver, body) in notes.iter().take(3) {
            eprintln!("  \x1b[1mv{}\x1b[0m", ver);
            let mut printed = 0;
            for line in body.lines() {
                let line = line.trim();
                if line.is_empty()
                    || line.starts_with("## ")
                    || line.starts_with("**Full Changelog**")
                {
                    continue;
                }
                if printed >= 6 {
                    eprintln!("    …");
                    break;
                }
                let trimmed: String = line.chars().take(120).collect();
                eprintln!("    {}", trimmed);
                printed += 1;
            }
            if printed == 0 {
                eprintln!("    (no release notes attached)");
            }
        }
    }
    eprintln!();
    eprintln!(
        "\x1b[2m  install latest with: httpxer -u   (or --no-update-check to silence this)\x1b[0m"
    );
    eprintln!();
}

/// `httpxer -u` — replace the running binary with the latest release.
pub async fn run_update() -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    println!("httpxer: checking GitHub releases for {}/{}…", REPO_OWNER, REPO_NAME);
    let result = tokio::task::spawn_blocking(|| {
        self_update::backends::github::Update::configure()
            .repo_owner(REPO_OWNER)
            .repo_name(REPO_NAME)
            .bin_name("httpxer")
            .show_download_progress(true)
            .show_output(true)
            .current_version(env!("CARGO_PKG_VERSION"))
            .build()?
            .update()
    })
    .await??;

    match result {
        self_update::Status::UpToDate(v) => println!("Already up to date: {}", v),
        self_update::Status::Updated(v) => {
            println!("Updated to: {}", v);
            // Refresh the version-check cache so the next startup banner
            // doesn't re-prompt about the version we just installed.
            if let Some(p) = update_cache_path() {
                if let Some(parent) = p.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::write(&p, &v);
            }
            // Best-effort changelog dump so users see what they got.
            let notes_res = tokio::time::timeout(
                Duration::from_secs(4),
                tokio::task::spawn_blocking({
                    let cur = current.clone();
                    move || fetch_release_notes_since(&cur)
                }),
            )
            .await;
            if let Ok(Ok(Ok(notes))) = notes_res {
                if !notes.is_empty() {
                    println!();
                    println!(
                        "\x1b[1m─────── What's new in httpxer v{}  (was v{}) ───────\x1b[0m",
                        v, current
                    );
                    for (ver, body) in notes.iter().take(5) {
                        println!();
                        println!("  \x1b[1;36mv{}\x1b[0m", ver);
                        let mut printed = 0;
                        for line in body.lines() {
                            let line = line.trim();
                            if line.is_empty()
                                || line.starts_with("## ")
                                || line.starts_with("**Full Changelog**")
                            {
                                continue;
                            }
                            if printed >= 10 {
                                println!("    …");
                                break;
                            }
                            let trimmed: String = line.chars().take(120).collect();
                            println!("    {}", trimmed);
                            printed += 1;
                        }
                        if printed == 0 {
                            println!("    (no release notes attached)");
                        }
                    }
                    println!();
                    println!("\x1b[2m    Full history: https://github.com/{}/{}/releases\x1b[0m",
                        REPO_OWNER, REPO_NAME);
                    println!();
                }
            }
        }
    }
    Ok(())
}

/// `httpxer -c` — print version status (current / latest release / latest tag)
/// without installing anything. Tags-API peek catches the "tag pushed, release
/// CI still building" window so the message stays accurate.
pub async fn run_check_update() -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let (release, tag) = tokio::join!(
        tokio::task::spawn_blocking(fetch_latest_version),
        tokio::task::spawn_blocking(fetch_latest_tag),
    );
    let release = release.ok().and_then(|r| r.ok()).flatten();
    let tag = tag.ok().and_then(|r| r.ok()).flatten();

    let newest = match (&release, &tag) {
        (Some(r), Some(t)) => Some(if version_is_newer(t, r) { t.clone() } else { r.clone() }),
        (Some(v), None) | (None, Some(v)) => Some(v.clone()),
        (None, None) => None,
    };

    match newest {
        Some(v) if version_is_newer(&v, current) => {
            println!("Update available: {} → {}", current, v);
            // Distinguish "release published" vs "tag-only, CI still building"
            // so the user knows whether `-u` will succeed right now.
            if let (Some(t), Some(r)) = (&tag, &release) {
                if version_is_newer(t, r) {
                    println!(
                        "  Note: v{} is tagged but the release binaries are still being built — \
                         `httpxer -u` will return the previous version until CI lands.",
                        t
                    );
                }
            } else if release.is_none() && tag.is_some() {
                println!("  Note: no published release yet — only a tag exists. `-u` will not find a binary.");
            }
            println!("  Run: httpxer -u   (to install)");
        }
        Some(v) => println!("httpxer v{} is the latest version.", v),
        None => println!("Could not reach GitHub to check for updates."),
    }
    Ok(())
}

/// `httpxer -X` — remove the running binary + cache. Detects which install
/// path it came from (/usr/local/bin/httpxer or %USERPROFILE%\bin) and asks
/// for confirmation unless `--yes`.
pub fn run_uninstall(skip_prompt: bool) -> anyhow::Result<()> {
    let bin = std::env::current_exe()?;
    println!("Uninstall httpxer from: {}", bin.display());
    if let Some(p) = update_cache_path() {
        if let Some(parent) = p.parent() {
            println!("                cache: {}", parent.display());
        }
    }
    if !skip_prompt {
        eprint!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Cancelled.");
            return Ok(());
        }
    }
    // Cache first (no perms issue), then the binary itself. Use self_update's
    // helper for the binary so it handles the Windows-locked-file case.
    if let Some(p) = update_cache_path() {
        if let Some(parent) = p.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
    self_update::self_replace::self_delete()?;
    println!("Uninstalled.");
    Ok(())
}
