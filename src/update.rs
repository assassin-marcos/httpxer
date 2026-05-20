//! Self-update + version-check banner — direct port of portwave's update flow.
//!
//! Three user-visible features:
//!   1. `httpxer -u` / `--update`        — install the latest release in place
//!   2. `httpxer -c` / `--check-update`  — print version status and exit
//!   3. Startup banner (stderr only)     — auto-detects outdated installs and
//!      shows "What's new" notes since the user's current version
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
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

pub const REPO_OWNER: &str = "assassin-marcos";
pub const REPO_NAME: &str = "httpxer";

/// True when stderr is attached to a real terminal — gates the ASCII-art
/// banner so piped invocations (`httpxer ... | jq ...`) don't get noise.
pub fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// Figlet "Standard" font of "httpxer" — renders cleanly at 80-col width,
/// pure ASCII (no Unicode boxchars) so it survives the cmd.exe / minimal
/// terminals users sometimes scan from.
const BANNER_ART: &str = r"
 _     _   _
| |__ | |_| |_ _ ____  _____ _ __
| '_ \| __| __| '_ \ \/ / _ \ '__|
| | | | |_| |_| |_) >  <  __/ |
|_| |_|\__|\__| .__/_/\_\___|_|
              |_|                  ";

/// Startup banner — cyan figlet art + bold version line with inline
/// `(outdated → vX.Y.Z)` / `(latest)` tag pulled from the 24 h update
/// cache (zero network hit at print-time; cache is populated separately
/// by `refresh_update_cache_best_effort`).
pub fn print_banner() {
    eprintln!("\x1b[36m{}\x1b[0m", BANNER_ART);
    let current = env!("CARGO_PKG_VERSION");
    let tag = match cached_latest_version() {
        Some(latest) if version_is_newer(&latest, current) => {
            format!("  \x1b[31m(outdated → v{})\x1b[0m", latest)
        }
        Some(_) => "  \x1b[32m(latest)\x1b[0m".to_string(),
        None => String::new(),
    };
    eprintln!(
        "        \x1b[1mhttpxer {}\x1b[0m{}  \x1b[2m·\x1b[0m  \x1b[2mby assassin_marcos\x1b[0m  \x1b[2m·\x1b[0m  \x1b[2mgithub.com/assassin-marcos/httpxer\x1b[0m",
        current, tag
    );
    eprintln!();
}

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
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
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

/// True when we can write a temp file alongside the running binary. Cheap
/// up-front check so the user doesn't sit through a 5 MB download just to
/// hit a Permission-Denied at the final move.
fn install_dir_writable() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return true;
    };
    let Some(parent) = exe.parent() else {
        return true;
    };
    let probe = parent.join(format!(".httpxer-wcheck-{}", std::process::id()));
    match fs::File::create(&probe) {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Print actionable guidance when the install path isn't writable by the
/// running user. Same message is used for both the up-front check and the
/// post-download fallback path, so users always see the same explanation.
fn print_perm_help() {
    let path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "/usr/local/bin/httpxer".into());
    eprintln!();
    eprintln!(
        "\x1b[33m[!] cannot update in place — write permission denied at {}\x1b[0m",
        path
    );
    eprintln!();
    eprintln!("This binary is in a root-owned directory (typical when installed via the");
    eprintln!("default `install.sh` / `install.ps1`). The unprivileged user that ran");
    eprintln!("`httpxer -u` can't replace the file. Two clean fixes:");
    eprintln!();
    eprintln!("  \x1b[1m1. Re-run with sudo (one-time, every update):\x1b[0m");
    eprintln!("       \x1b[1msudo httpxer -u\x1b[0m");
    eprintln!();
    eprintln!(
        "  \x1b[1m2. Or relocate to a user-writable path (one-time, no sudo ever again):\x1b[0m"
    );
    eprintln!("       mkdir -p ~/.local/bin");
    eprintln!("       sudo mv {} ~/.local/bin/", path);
    eprintln!("       # macOS:  echo 'export PATH=\"$HOME/.local/bin:$PATH\"' >> ~/.zshrc && source ~/.zshrc");
    eprintln!("       # Linux:  echo 'export PATH=\"$HOME/.local/bin:$PATH\"' >> ~/.bashrc && source ~/.bashrc");
    eprintln!();
    eprintln!("Future `httpxer -u` invocations from the relocated path will not need sudo.");
}

/// `httpxer -u` — replace the running binary with the latest release.
pub async fn run_update() -> anyhow::Result<()> {
    // Up-front writability check — saves a 5 MB download when the user
    // would just hit a Permission-Denied at the final move step.
    if !install_dir_writable() {
        print_perm_help();
        std::process::exit(2);
    }

    let current = env!("CARGO_PKG_VERSION").to_string();
    println!(
        "httpxer: checking GitHub releases for {}/{}…",
        REPO_OWNER, REPO_NAME
    );
    let join = tokio::task::spawn_blocking(|| {
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
    .await?;

    let result = match join {
        Ok(s) => s,
        Err(e) => {
            // Post-download fallback — defends against the race where the
            // dir was writable at the up-front check but a directory ACL /
            // mount option changed in between.
            let msg = e.to_string();
            if msg.contains("Permission denied")
                || msg.contains("os error 13")
                || msg.to_ascii_lowercase().contains("access is denied")
            {
                print_perm_help();
                std::process::exit(2);
            }
            return Err(e.into());
        }
    };

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
                    println!(
                        "\x1b[2m    Full history: https://github.com/{}/{}/releases\x1b[0m",
                        REPO_OWNER, REPO_NAME
                    );
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
        (Some(r), Some(t)) => Some(if version_is_newer(t, r) {
            t.clone()
        } else {
            r.clone()
        }),
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

/// Find all places `httpxer` could plausibly be installed on this host.
/// Sweeps every standard binary-install location per OS (PATH, common
/// user-local dirs, system-wide dirs, Homebrew, MacPorts, .cargo/bin,
/// Windows %USERPROFILE%\bin, %LOCALAPPDATA%, %ProgramFiles%). Returns
/// only paths that exist, deduped by canonical inode/path. Matches
/// portwave's pattern verbatim so users with both tools installed get
/// consistent uninstall behaviour.
fn uninstall_collect_targets() -> (Vec<PathBuf>, Option<PathBuf>) {
    #[cfg(unix)]
    let home = std::env::var("HOME").ok();
    #[cfg(not(unix))]
    let home: Option<String> = None;
    let _ = &home; // suppress unused warning on Windows targets

    let mut bin_candidates: Vec<PathBuf> = Vec::new();

    // First — the running binary itself (whatever the user typed `httpxer` to
    // execute). Followed by its canonical form in case `httpxer` resolves
    // through a symlink (Homebrew + Linuxbrew do this).
    if let Ok(cur) = std::env::current_exe() {
        bin_candidates.push(cur.clone());
        if let Ok(canon) = cur.canonicalize() {
            if canon != cur {
                bin_candidates.push(canon);
            }
        }
    }

    #[cfg(unix)]
    {
        if let Some(h) = &home {
            let h = PathBuf::from(h);
            bin_candidates.push(h.join("bin/httpxer"));
            bin_candidates.push(h.join(".local/bin/httpxer"));
            bin_candidates.push(h.join(".cargo/bin/httpxer"));
        }
        bin_candidates.push(PathBuf::from("/usr/local/bin/httpxer"));
        bin_candidates.push(PathBuf::from("/opt/homebrew/bin/httpxer"));
        bin_candidates.push(PathBuf::from("/opt/local/bin/httpxer"));
    }
    #[cfg(windows)]
    {
        if let Ok(up) = std::env::var("USERPROFILE") {
            let up = PathBuf::from(up);
            bin_candidates.push(up.join("bin\\httpxer.exe"));
            bin_candidates.push(up.join(".local\\bin\\httpxer.exe"));
            bin_candidates.push(up.join(".cargo\\bin\\httpxer.exe"));
        }
        if let Ok(la) = std::env::var("LOCALAPPDATA") {
            bin_candidates.push(PathBuf::from(la).join("Programs\\httpxer\\httpxer.exe"));
        }
        if let Ok(pf) = std::env::var("ProgramFiles") {
            bin_candidates.push(PathBuf::from(pf).join("httpxer\\httpxer.exe"));
        }
    }

    // Keep only existing files; dedupe by canonical path so a binary that
    // appears via both /usr/local/bin and a symlink doesn't get listed twice.
    let mut bins: Vec<PathBuf> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for c in bin_candidates {
        let canon = c.canonicalize().unwrap_or_else(|_| c.clone());
        if c.is_file() && seen.insert(canon) {
            bins.push(c);
        }
    }

    let cache = update_cache_path()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .filter(|d| d.is_dir());

    (bins, cache)
}

/// `httpxer -X` — remove every httpxer binary on disk plus the version
/// cache. Shows a plan first, requires TTY-confirm unless `--yes` to avoid
/// nuking a real install via accidental pipe / redirect.
pub fn run_uninstall(skip_prompt: bool) -> anyhow::Result<()> {
    let (bins, cache) = uninstall_collect_targets();

    println!("httpxer uninstaller");
    println!();

    if bins.is_empty() && cache.is_none() {
        eprintln!("[!] No httpxer installation found on this system.");
        eprintln!(
            "    Nothing to remove. If httpxer isn't installed yet, run install.sh \
             (or install.ps1 on Windows) first."
        );
        return Ok(());
    }

    println!("About to REMOVE:");
    for b in &bins {
        println!("  binary  : {}", b.display());
    }
    if let Some(c) = &cache {
        println!("  cache   : {}", c.display());
    }
    println!();

    if !skip_prompt {
        // stdin TTY guard — prevents accidental uninstall via a pipe that
        // happens to feed an empty stdin (would otherwise see "no input" as
        // "decline", but we want a definitive y/n).
        if !std::io::stdin().is_terminal() {
            eprintln!("[!] stdin is not a TTY and --yes was not passed — aborting to be safe.");
            eprintln!("    Re-run interactively, or add --yes (alias -y) to proceed.");
            return Ok(());
        }
        eprint!("Proceed? [y/N] ");
        use std::io::Write as _;
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let answer = line.trim();
        if !answer.eq_ignore_ascii_case("y") && !answer.eq_ignore_ascii_case("yes") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let mut removed_bins = 0usize;
    for b in &bins {
        match fs::remove_file(b) {
            Ok(_) => {
                println!("removed {}", b.display());
                removed_bins += 1;
            }
            Err(e) => eprintln!(
                "could not remove {}: {} (check permissions)",
                b.display(),
                e
            ),
        }
    }
    if let Some(c) = &cache {
        match fs::remove_dir_all(c) {
            Ok(_) => println!("removed {}", c.display()),
            Err(e) => eprintln!("could not remove {}: {}", c.display(), e),
        }
    }

    println!();
    if removed_bins > 0 {
        println!("Uninstalled. ({} binary file(s) removed)", removed_bins);
    } else {
        eprintln!(
            "No binaries were removed — likely a permission issue. \
             Try re-running with `sudo` (Linux/macOS) or as Administrator (Windows)."
        );
    }
    Ok(())
}
