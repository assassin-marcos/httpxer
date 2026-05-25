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
use std::path::{Path, PathBuf};
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
/// `refresh_update_cache_best_effort` call. Returns None when the cache
/// is missing / unreadable / empty / older than **30 days**.
///
/// v0.4.1 — TTL extended from 24 h to 30 days. The 24 h limit was
/// silently hiding "outdated" warnings from users who run httpxer
/// sporadically (cache reads None → no `(outdated → vX.Y.Z)` tag →
/// user thinks they're current). Stale-cache outdated warnings are
/// still useful — better to flag "v0.3.4 → cached v0.4.0 (data from
/// 5 days ago)" than to flag nothing.
pub fn cached_latest_version() -> Option<String> {
    let p = update_cache_path()?;
    let meta = fs::metadata(&p).ok()?;
    let age = meta.modified().ok()?.elapsed().ok()?;
    if age > Duration::from_secs(30 * 24 * 3_600) {
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
                // Skip pre-release tags (e.g. `v1.2.3-rc1`, `v1.2.3-beta.2`).
                // A dot-separated suffix like `-rc.1` would otherwise expand
                // into an extra numeric component and rank ABOVE the
                // matching release, so `-c` reported pre-releases as the
                // newest installable version.
                if name.contains('-') {
                    continue;
                }
                let stripped = name.trim_start_matches('v').to_string();
                let parts: Vec<u32> = stripped
                    .split('.')
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

/// Find the highest-priority user-writable bin dir for auto-relocate.
/// Tries the standard candidates in order; the first that's either already
/// writable, or successfully created and writable, wins. Returns the
/// resolved `<dir>/httpxer` install path so callers can hand it directly to
/// `self_update::UpdateBuilder::bin_install_path`.
fn find_writable_install_path() -> Option<PathBuf> {
    // Empty env vars are not the same as unset — `HOME=''` ≠ `HOME` unset.
    // Filter both to skip degenerate paths that would resolve relative to
    // the current working dir (a Bash-style misconfig some CI runners ship).
    let nonempty = |v: std::ffi::OsString| {
        if v.is_empty() {
            None
        } else {
            Some(PathBuf::from(v))
        }
    };
    let home = std::env::var_os("HOME").and_then(nonempty);
    let xdg = std::env::var_os("XDG_BIN_HOME").and_then(nonempty);
    let candidates: Vec<PathBuf> = [
        xdg,
        home.as_ref().map(|h| h.join(".local").join("bin")),
        home.as_ref().map(|h| h.join("bin")),
    ]
    .into_iter()
    .flatten()
    // Reject any path that isn't absolute — a relative path would resolve
    // against $PWD, which is almost never what the user wants for an
    // install target.
    .filter(|p| p.is_absolute())
    .collect();

    for dir in candidates {
        let _ = fs::create_dir_all(&dir);
        let probe = dir.join(format!(".httpxer-wprobe-{}", std::process::id()));
        if fs::File::create(&probe).is_ok() {
            let _ = fs::remove_file(&probe);
            return Some(dir.join("httpxer"));
        }
    }
    None
}

/// Warn (to stderr) when the relocated dir isn't on the caller's $PATH —
/// the binary works but `httpxer` won't resolve until the user fixes PATH.
fn warn_if_not_on_path(dir: &Path) {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let split = std::env::split_paths(&path);
    if split.into_iter().any(|p| p == dir) {
        return;
    }
    let shell = std::env::var("SHELL").unwrap_or_default();
    let rc = if shell.ends_with("/zsh") {
        "~/.zshrc"
    } else if shell.ends_with("/fish") {
        "~/.config/fish/config.fish"
    } else {
        "~/.bashrc"
    };
    eprintln!();
    eprintln!(
        "\x1b[33m[!] {} is not on your $PATH — `httpxer` won't resolve until you add it.\x1b[0m",
        dir.display()
    );
    eprintln!(
        "    Add and reload:  \x1b[1mecho 'export PATH=\"{}:$PATH\"' >> {} && source {}\x1b[0m",
        dir.display(),
        rc,
        rc
    );
}

/// Best-effort cleanup of the root-owned old binary after a successful
/// relocate. Tries passwordless sudo first (silent if no sudoers entry);
/// if that fails, leaves the file alone and prints a one-liner with the
/// manual command. Never blocks the update flow on cleanup.
fn cleanup_old_binary(old: &Path) {
    if !old.exists() {
        return;
    }
    // Try non-interactive sudo first — silent if not allowed
    let sudo_ok = std::process::Command::new("sudo")
        .args(["-n", "rm", "-f"])
        .arg(old)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if sudo_ok && !old.exists() {
        eprintln!("    \x1b[2mremoved old binary: {}\x1b[0m", old.display());
        return;
    }
    eprintln!();
    eprintln!(
        "\x1b[2m[i] note: the old root-owned binary at {} is still on disk.\x1b[0m",
        old.display()
    );
    eprintln!(
        "    \x1b[2mremove it manually when convenient:  sudo rm {}\x1b[0m",
        old.display()
    );
}

/// Re-exec the current binary under `sudo`, preserving argv. Used as the
/// last-resort path when no user-writable fallback dir is available
/// (e.g. read-only `$HOME`, missing `$HOME`, or user explicitly chose to
/// stay in `/usr/local/bin`). Returns Ok only if the sudo invocation
/// itself completes — the child process replaces us via exit().
fn reexec_with_sudo() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    let argv: Vec<String> = std::env::args().skip(1).collect();
    eprintln!();
    eprintln!(
        "\x1b[33m[!] no user-writable fallback found. Re-executing as: sudo {} {}\x1b[0m",
        exe.display(),
        argv.join(" ")
    );
    eprintln!("    \x1b[2m(sudo will prompt for your password)\x1b[0m");
    let mut cmd = std::process::Command::new("sudo");
    cmd.arg(&exe);
    cmd.args(&argv);
    let status = cmd.status()?;
    std::process::exit(status.code().unwrap_or(1));
}

/// Auto-relocate flow — called when the running binary lives in a path
/// the current user can't write. Picks a user-writable destination
/// (`~/.local/bin/`, `~/bin/`, `$XDG_BIN_HOME`), copies the running
/// binary there, best-effort sudo-removes the root-owned original, then
/// `exec()`'s the new copy with `-u` so the standard `self_update`
/// in-place path runs against a directory the current user owns.
///
/// Why copy + exec instead of pointing `self_update::bin_install_path`
/// at the new path directly: `self_update 0.41` stages its temp file
/// next to `std::env::current_exe()` rather than next to the configured
/// install path. With a root-owned current_exe that staging write
/// fails with EACCES even when bin_install_path is on tmpfs. Replacing
/// the process via `exec` shifts current_exe() to the writable copy
/// and sidesteps the bug entirely.
///
/// Falls back to sudo re-exec when no writable destination is
/// available (read-only $HOME, missing $HOME, etc.).
async fn relocate_and_update() -> anyhow::Result<()> {
    let old_path = std::env::current_exe()?;
    let Some(new_install_path) = find_writable_install_path() else {
        return reexec_with_sudo();
    };
    let new_parent = new_install_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_default();

    eprintln!();
    eprintln!(
        "\x1b[33m[!] {} is in a non-writable directory — relocating to {} (one-time; no sudo for future updates).\x1b[0m",
        old_path.display(),
        new_install_path.display()
    );

    // 1. Copy the running binary to the new user-writable path
    fs::create_dir_all(&new_parent)?;
    fs::copy(&old_path, &new_install_path).map_err(|e| {
        anyhow::anyhow!(
            "copy {} → {} failed: {}",
            old_path.display(),
            new_install_path.display(),
            e
        )
    })?;
    // 2. chmod 0755 — preserve the executable bit explicitly (POSIX-only;
    //    Windows handles this differently and never hits this code path
    //    because the perm-denied case there manifests on the user's own
    //    %USERPROFILE%\bin which is always writable).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&new_install_path, perms)?;
    }

    eprintln!(
        "    \x1b[2mcopied binary to {}\x1b[0m",
        new_install_path.display()
    );

    // 3. Best-effort cleanup of the root-owned original (non-interactive
    //    sudo only — silent if not allowed).
    cleanup_old_binary(&old_path);

    // 4. Warn if the new dir isn't on $PATH (binary works but the
    //    `httpxer` command won't resolve until $PATH is fixed).
    warn_if_not_on_path(&new_parent);

    // 5. Refresh the update-check cache with the current version so the
    //    re-exec's startup banner is consistent.
    if let Some(p) = update_cache_path() {
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&p, env!("CARGO_PKG_VERSION"));
    }

    // 6. Re-exec the COPY with `-u`. The copy's `install_dir_writable()`
    //    will return true (its parent is owned by the current user), so
    //    the normal `self_update` flow runs against a writable path and
    //    the binary gets replaced atomically with the latest release.
    //
    //    `--no-update-check` suppresses the banner on the inner invocation
    //    since the outer one already showed it.
    eprintln!();
    eprintln!(
        "\x1b[2m    handing off to {} -u (will fetch latest release into {})...\x1b[0m",
        new_install_path.display(),
        new_parent.display()
    );
    eprintln!();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&new_install_path)
            .args(["-u", "--no-update-check"])
            .exec();
        // exec only returns on error
        Err(anyhow::anyhow!(
            "exec {} -u failed: {}",
            new_install_path.display(),
            err
        ))
    }
    #[cfg(not(unix))]
    {
        let status = std::process::Command::new(&new_install_path)
            .args(["-u", "--no-update-check"])
            .status()?;
        std::process::exit(status.code().unwrap_or(0));
    }
}

/// `httpxer -u` — replace the running binary with the latest release.
/// When the install path is root-owned and the running user can't write
/// to it, AUTO-RELOCATE the binary to a user-writable path
/// (`~/.local/bin/` / `~/bin/` / `$XDG_BIN_HOME`) instead of failing with
/// a "use sudo" message. Falls back to sudo re-exec only when no
/// user-writable destination exists.
pub async fn run_update() -> anyhow::Result<()> {
    // Up-front writability check. When false, switch to auto-relocate
    // (which calls self_update with bin_install_path set to a
    // user-writable destination) so the user never has to think about
    // sudo or PATH after their first install.
    if !install_dir_writable() {
        return relocate_and_update().await;
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
            // mount option changed in between. Auto-relocate kicks in here
            // too so the user still gets a working install without sudo.
            let msg = e.to_string();
            if msg.contains("Permission denied")
                || msg.contains("os error 13")
                || msg.to_ascii_lowercase().contains("access is denied")
            {
                return relocate_and_update().await;
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
