# httpxer

**Native HTTP enrichment + recursive path fuzzing with browser-grade TLS impersonation, content-aware wildcard detection, auth-dir recursion, crawling, and a content-confirmed 401/403 bypass engine.**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()

**Current release:** [v0.6.7](https://github.com/assassin-marcos/httpxer/releases/tag/v0.6.7)

```
 _     _   _
| |__ | |_| |_ _ ____  _____ _ __
| '_ \| __| __| '_ \ \/ / _ \ '__|
| | | | |_| |_| |_) >  <  __/ |
|_| |_|\__|\__| .__/_/\_\___|_|
              |_|     httpxer · by assassin_marcos
```

## What it is

One tool, two jobs:

- **Enrich mode** — reads a hostname list, probes each over HTTP(S), and emits one JSONL record per host with DNS, CDN, Wappalyzer-style technology detection, and HTTP metadata. `--httpx-compat` provides the common httpx JSON field shape; exact byte-for-byte parity is not promised.
- **Fuzz mode** — host × wordlist Cartesian probe with **recursive** dir bruteforce (incl. **auto-recursion into protected `401`/`403` dirs**), **crawl** (HTML/robots/sitemap link extraction), **content-aware wildcard detection** (static catchall + per-request-nonce catchall + path-echo), a **native, content-confirmed `401`/`403` bypass engine**, and dirsearch-style **live progress bar + findings stream**.

Both modes share a 16-slot **BoringSSL** browser-emulation pool. Enrich mode samples the pool per probe; fuzz mode pins one profile per host so wildcard pre-flight and wordlist probes see the same UA-dependent response. Distinct hosts are still distributed across the pool.

## Install

```bash
# Linux x86_64; macOS x86_64 or Apple Silicon
curl -sL https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.ps1 | iex

# Self-manage
httpxer -U   # install latest release
httpxer -c   # check for updates
httpxer -X   # uninstall
```

Released binaries: Linux `x86_64` (glibc 2.35+), macOS `x86_64` and `arm64`, and Windows `x86_64`. Linux ARM is not currently published; build it from source if your toolchain supports the dependency stack.

## Quickstart

### Enrich mode

```bash
# One target, a file, or stdin
httpxer -u https://example.com
httpxer -l hosts.txt -o enriched.jsonl
subfinder -d example.com -silent | httpxer -l - -o enriched.jsonl

# Common httpx-compatible JSON fields
httpxer -l hosts.txt --httpx-compat -o enriched.jsonl

# Headers, body, authentication, and proxying
httpxer -u example.com --rh
httpxer -u https://internal.example.com --bearer "$TOKEN" --cookie 'sid=abc'
httpxer -l hosts.txt --proxy http://127.0.0.1:8080 -o enriched.jsonl
httpxer -l hosts.txt --proxy proxies.txt -o rotated.jsonl

# Technology detection: embedded snapshot, disabled, or custom snapshot
httpxer -u example.com --tech default
httpxer -l hosts.txt --tech off -o fast.jsonl
httpxer -u example.com --tech ./fingerprints.json
```

Technology detection is enrich-only. Fuzz records keep `tech:[]`; path scans do not run the detector for every response.

### Fuzz mode

```bash
# Basic scan. Backup discovery, wildcard suppression and 401/403 bypass are on.
httpxer -u https://example.com/ -w wordlist.txt -o out.txt

# Multiple dictionaries are merged and de-duplicated
httpxer -u https://example.com/ -w admin.txt,api.txt,sensitive.txt -o out.txt

# Exact codes, status classes, and inline exclusions
httpxer -u https://example.com/ -w wordlist.txt --status '2xx,3xx,!429,!503'

# Recursion, crawl, or both at depth 3
httpxer -u https://example.com/ -w wordlist.txt --recurse 3 -o recurse.txt
httpxer -u https://example.com/ -w wordlist.txt --crawl 3 -o crawl.txt
httpxer -u https://example.com/ -w wordlist.txt --deep 3 -o deep.txt

# Polite multi-host scan
httpxer -l hosts.txt -w wordlist.txt -t 50 --rate-limit 10 -o findings.jsonl

# Authenticated scan; auth controls work in both modes
httpxer -u https://example.com/ -w wordlist.txt --bearer "$TOKEN" -H 'X-Tenant: 42'

# Disable bypass requests where they are out of scope
httpxer -u https://example.com/ -w wordlist.txt --safe -o findings.txt

# Inspect wildcard candidates instead of suppressing them
httpxer -u https://example.com/ -w wordlist.txt --wildcard mark -o review.jsonl

# Preview host-derived backup names without sending any request, then exit
httpxer -u https://example.com/ -w wordlist.txt --backup dry-run

# Disable host-derived backup probes for a pure wordlist scan
httpxer -u https://example.com/ -w wordlist.txt --backup off -o findings.txt
```

`.txt` selects plain `STATUS SIZE URL`; other output extensions select JSONL. With no `-o`, records stream to stdout. With `-o`, each record is written and flushed as soon as it is found; enrich tasks are bounded by `-t`, and backup findings stream to their sidecar instead of accumulating until phase completion. `-q` hides the banner, update check, live findings and progress while retaining phase summaries.

`--status`, `--tech`, `--backup`, and `--deep` are the preferred consolidated controls. Legacy spellings such as `-i`, `-r -R`, `--wildcard-policy`, `--no-backup-fuzz`, and `--backup-dry-run` remain accepted. Run `httpxer -h` for task-tagged examples or `httpxer --help` for the advanced option reference and practical recipes.

## Wildcard detection (the FP killer)

Most directory bruteforcers drown in false positives on CDN-fronted / SPA / soft-404 targets. httpxer's detector is multi-sample + multi-layer. Pre-flight probes a mix of **random-hex paths + realistic decoys** (`.conf`, `.config`, `.env`, `/.git/HEAD`) **concurrently**, so detection sees the same catchall your wordlist will hit:

- **Layer 1 — static catchall**: at least two same-status samples agree on `(content_type, content_length, snippet_md5)` within the configured length tolerance. Separate status and extension-family signatures are retained instead of overwriting one another.
- **Layer 2 — path-echo / dynamic-CL**: with at least three samples, `content_length = k × path_length + base` must fit within residual bounds. The slope `k` then predicts the wildcard length for each probe path.
- **Layer 1b — content-aware catchall**: when no path-echo model fits, the catchall body may still vary per request (for example, a request ID or timestamp). UUIDs, long hex/digit runs and timestamps are normalized before hashing. Bounded drift uses normalized-content and token-similarity guards; wide length drift additionally requires the normalized first 2 KiB to agree exactly. Matching is content-aware, never size-only.
- **Bodyless catchall**: the host answers **`2xx` with zero bytes** for *every* path. There is no body to fingerprint, so every layer above is blind to it by construction. `200` + no body across **3 distinct paths** is itself the signature — httpxer learns it per `(host, status, content_type)` and suppresses from then on. A *lone* legitimate empty `200` (a `/ping`-style endpoint) stays below the threshold and is still emitted.

This closes the case where a constant-size catchall with a per-request token used to emit *every* wordlist hit as a fake `200`. The host fingerprint also applies under **recursed directories** (so catchall noise doesn't reappear one level down).

| Policy | Behavior |
|---|---|
| `--wildcard strict` *(default)* | Drop probes matching the wildcard |
| `--wildcard mark` | Emit them tagged `is_wildcard:true` for later review |
| `--wildcard off` | Skip wildcard pre-flight and suppression |

## Recursion + crawl

Use `--recurse N`, `--crawl N`, or `--deep N` to turn the host × wordlist single pass into a multi-round orchestrator:

- **Recursion** — discovered directories (301/302/307/308 with `Location == URL + "/"` parity check; opt-in 200+autoindex via `--recurse-on-200`) get re-fuzzed with the wordlist up to the requested depth.
- **Auth-dir recursion** *(auto-on)* — a `401`/`403` on a **directory-shaped** path (e.g. `/api`, `/internal` — not `/x.php`) is descended into so accessible children behind a protected parent are found (the classic `/api` = 401 → `/api/actuator` = 200). Omitting `401`/`403` from `--status` hides the parent without disabling discovery. A scoped random-child fingerprint prevents identical nested auth walls from becoming new recursion roots. Bounded by `--max-dirs-per-host`; the legacy `--recurse-on-403` flag (recurse *any* 403) still exists.
- **Crawl** — response bodies are parsed for HTML `<a/link/script/img/form/iframe>`, robots.txt `Disallow/Allow/Sitemap`, and sitemap.xml `<loc>`. Discovery happens before output status/size filters. A `3xx` stays attached to its requested path while its `Location` is queued as a separate crawl URL, so crawling cannot change wildcard identity.

Both share a visited set and a per-host **directory** budget (`--max-dirs-per-host`, default 200). Each discovered directory costs a full wordlist pass, so that cap plus depth bounds a recursive scan.

Built-in `--exclude-subdirs` patterns guard **discovered directory expansion only**. Explicit wordlist entries are always probed, including names such as `healthz`, `readyz`, `ping`, and `actuator/health`. Override the built-ins with a comma-separated list, append with `--add-excludes`, or disable them with:

```bash
httpxer -u https://example.com -w wordlist.txt --deep 3 --exclude-subdirs ''
```

`--exclude-mode substring` is intentionally aggressive and can suppress a discovered directory when a short token appears anywhere in its path. The default `segment` mode is safer.

## Host-derived backup discovery (auto-on in fuzz mode)

Site owners leave archives on the web root named after the site itself — `www.example.com.zip`, `example.com.sql`, `example.zip`. **No wordlist can carry these**, because the filename is a function of the target's own hostname. httpxer derives them per-host at runtime.

Runs automatically whenever a wordlist is set. Use the single `--backup` control to select `auto`, `off`, or `dry-run`.

```sh
# Auto (default)
httpxer -u https://example.com -w paths.txt

# Preview the maximum-budget candidate set, send zero requests, then exit
httpxer -u https://example.com -w paths.txt --backup dry-run

# Pure wordlist scan
httpxer -u https://example.com -w paths.txt --backup off

# Add a name the hostname can't reveal (internal project name)
httpxer -u https://shop.example.io -w paths.txt --backup-tokens acmecorp,internal-portal
```

**13 token rules** per host — full host, `www.`-stripped, registrable domain (real Public Suffix List, so `abc.co.uk` doesn't collapse to `co.uk`), SLD alone, dot→underscore/hyphen/removed variants, leftmost label, sub+SLD concatenations, and the current path segment. Ports are stripped: a backup is named after the site, never the socket. The resulting tokens feed a broad matrix across archive, backup-marker, database, Java-package, disk-image, compound, separator, and date-stamped classes.

Every automatic budget reserves the highest-yield names first: full-host/registrable-domain/SLD `.zip` forms, all static generics (`backup.zip`, `backup.sql`, `backup.tar.gz`, `site.zip`, and related names), common separator forms, and current-year forms. Lower-priority permutations fill only the remaining budget.

Everything is decided at runtime:

- **Extension ordering follows the detected stack.** One request reads `Server`, `X-Powered-By` and a body snippet → Java / PHP / .NET / Node / Python / Unknown. Detection reorders the lower-priority matrix; the reserved names above are stack-independent.
- **Budget scales with responsiveness.** <400 ms → 300 candidate URLs, <1.2 s → 180, <3 s → 100, slower → 50, and failed profiling → 60. This is one total URL budget shared round-robin across root, current-directory, and verified backup-directory bases — not a separate allowance for every base.
- **Backup directories are catchall-verified.** `backup/` and `bak/` are compared with impossible-path controls after request-path echoes are normalized. Only exact directories whose bodies differ are added as bases; the remaining prefixes are checked only after a sentinel is verified.
- **Root and current directory both receive the highest-priority names**, deduped when identical and sharing the same URL budget.

`--backup dry-run` cannot know the target's latency or stack without making a request. It therefore prints the maximum 300-URL priority preview and clearly exits without initializing the HTTP pool; a live `auto` run may select a lower budget and reorder only the lower-priority tail.

**Zero-false-positive gate.** Naive backup scanning drowns in soft-404s — sites that answer `200 OK` with an HTML "not found" page for any filename. Every candidate must clear all of:

- Status `200`/`206` only. Other statuses are not emitted by backup discovery, and redirects are not followed.
- Soft-404 baseline calibrated from 3 impossible filenames per host; request-path echoes are normalized and ≥0.95 similarity to any control is discarded
- Content-Type sanity — `text/html` on a `.zip`/`.sql`/`.db` is discarded unless the bytes say otherwise
- **Magic bytes** — ZIP `50 4B 03 04`, GZIP `1F 8B`, BZIP2, XZ, 7Z, RAR, TAR `ustar`@257, `SQLite format 3`, MS Access — or a plaintext SQL-dump marker
- Edge-security interstitials (challenge/blocked pages) filtered out

Only `status OK + size OK + (magic OR SQL text) + baseline-dissimilar` reaches **CONFIRMED**. A remaining plausible `200`/`206` can be marked **REVIEW**; hard gate failures are discarded.

**Bandwidth-safe.** Each candidate URL gets `HEAD` first; only a `200`/`206` response (or a server that rejects `HEAD`) earns a ranged `GET` for the first 1024 bytes. The archive itself is never downloaded. The adaptive number is a candidate-URL budget; profiling, catchall controls, directory verification, retries, and the ranged confirmation request are additional bounded HTTP requests.

Findings go to `<output>.backup.jsonl` (15 fields including `base_type`, `magic_matched`, `baseline_similarity`, `confidence`, `verdict`), plus a terminal table for CONFIRMED only. When `-o` is omitted, the sidecar is `httpxer-backup.jsonl`; it is never derived from `/dev/stdout`.

## 401/403 bypass (native, auto, content-confirmed)

When a probe hits `401`/`403`, httpxer automatically retries it with a small, conservative battery of access-control bypass techniques — **on the forbidden resource only, never on every request**:

- **Header overrides** — `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`
- **Path mutations** — e.g. `…/..;/`

A bypass is reported **only when confirmed**: the retry returns a `2xx` with a non-empty body, its normalized content **differs** from the original block page, and it doesn't match the host catchall. Redirects and empty bodies are not accepted as proof of access. Confirmed hits are emitted with a `bypass:"<technique>"` tag and a visible `[bypass] /admin 403→200 via X-Original-URL` line. Traffic is bounded by a per-host budget; it only ever *adds* findings, never suppresses. Pass **`--safe`** to disable it entirely (for programs/targets where bypass attempts are out of scope).

## Technology fingerprints

The embedded snapshot contains **7,524 technology definitions**. In the source data, **5,205 apps** have at least one vector the shallow HTTP engine supports, comprising **6,590 pattern entries**. With the current Rust regex engine, startup compiles **6,582 patterns across 5,186 directly detectable apps** and reports the 8 unsupported regex patterns it skips. Implication rules can add related technology names after a direct match.

Supported vectors are response headers, cookies, meta tags, HTML, and script source URLs. JavaScript runtime variables and DOM-only rules require a browser and are not evaluated. Technology detection runs in enrich mode only; fuzz output intentionally leaves `tech` empty.

Use `--tech default`, `--tech off`, or `--tech /path/to/fingerprints.json`. The legacy `--no-tech` and `--fingerprints` spellings remain available.

## TLS impersonation

Browser-grade fingerprint emulation via [`wreq`](https://github.com/penumbra-x/rquest) and BoringSSL. There are 16 profiles in the pool:

| Family | Versions |
|---|---|
| Desktop Chrome | 131, 133, 135, 136, 137 |
| Desktop Firefox | 133, 136, 139 |
| Desktop Safari (macOS) | 18.2, 18.3.1, 18.5 |
| Desktop Edge | 131, 134 |
| Mobile Safari (iOS) | 17.4.1, 18.1.1 |
| Mobile Firefox (Android) | 135 |

Each `wreq` profile configures browser-specific TLS and HTTP/2 behavior plus matching request headers. Fuzz mode deliberately keeps one profile stable per host so pre-flight fingerprints remain comparable with later probes.

Verify against a TLS-echo service:
```bash
printf 'https://tls.peet.ws/api/all?n=%s\n' {1..64} > urls.txt
httpxer -l urls.txt -o out.jsonl --with-body --tech off -t 8
# Enrich mode samples profiles randomly; inspect the observed JA4 distribution.
```

## Output

### Plain (auto-detected from `.txt` extension)

```
200    1.2KB  https://example.com/admin
301    320B   https://example.com/login
403     --    https://example.com/.git/HEAD
500    5.4KB  https://example.com/buggy.aspx
```

Color-coded by status class when stderr is a TTY: green 2xx, yellow 3xx, cyan 401/403, magenta other 4xx, red 5xx.

### JSONL (default / `.jsonl` extension / `--format json`)

Full structured record per finding. Fuzz mode includes `depth`, `source`, `parent_url` for multi-round provenance, and `bypass` (the winning technique) on confirmed 401/403 bypasses. Enrich mode (`--httpx-compat`) uses common ProjectDiscovery httpx field names and array shapes, but consumers should not assume byte-for-byte output identity.

Live findings stream to stderr above a `[N/total] X% | rps | eta` progress bar. `--no-live` hides findings only; `-q` hides findings and progress while retaining phase summaries.

## Proxy rotation

`--proxy` accepts either one endpoint or a proxy file. A file may mix protocols; httpxer validates and de-duplicates it at startup, then selects the next endpoint for every HTTP request. The browser/TLS profile remains stable per target host so wildcard fingerprints stay comparable. URL credentials work with HTTP, HTTPS, SOCKS5, and SOCKS5H; the underlying client does not support SOCKS4 authentication, so authenticated SOCKS4 entries fail validation instead of starting a scan.

```text
# proxies.txt: one endpoint per line; blank lines and comments are ignored
http://127.0.0.1:8080
https://user:password@proxy.example:8443
socks5://127.0.0.1:1080
socks5h://user:password@proxy.example:1080
127.0.0.1:8888
```

```bash
# One authenticated proxy
httpxer -u https://example.com --proxy http://user:password@127.0.0.1:8080

# Mixed per-request rotation in enrich or fuzz mode
httpxer -l hosts.txt --proxy proxies.txt -o enriched.jsonl
httpxer -u https://example.com -w paths.txt --proxy proxies.txt -o findings.jsonl

# Force a path without a conventional file extension to be read as a file
httpxer -u https://example.com --proxy @proxy-pool
```

Supported schemes are HTTP, HTTPS, SOCKS4/SOCKS4A, and SOCKS5/SOCKS5H. Bare `host:port` entries default to HTTP. Credentials must use URL form (`scheme://user:password@host:port`) and are not printed in startup diagnostics. A failed endpoint is reported as a normal request error; retries rotate to the next endpoint.

## Auth

```bash
# Custom headers (repeatable) — e.g. an auth/tenant header for the whole scan
httpxer ... -H "Authorization: Bearer eyJ..." -H "X-Tenant-Id: 42"

# Bearer token
httpxer ... --bearer eyJhbGciOiJIUzI1NiJ9.xyz

# Static Cookie header seed (Set-Cookie responses are not persisted)
httpxer ... --cookie "sid=abc123" --cookie "csrf=token"
```

> You don't need to pass `X-Original-URL` / `X-Forwarded-For` for ACL bypass — that's handled natively per-`401`/`403` (see [401/403 bypass](#401403-bypass-native-auto-content-confirmed)). `-H` is for headers you want on **every** request.

## Flags (most-used)

| Flag | Default | Purpose |
|---|---|---|
| `-u <URL>` / `-l <FILE>` | — | Single target / hosts file (`-` for stdin) |
| `-w <FILE>` | — | Wordlist — presence triggers fuzz mode |
| `-o <FILE>` | — | Output (`.jsonl` → JSON, `.txt` → plain) |
| `-t <N>` | 250 | Concurrent probes |
| `--timeout-ms` | 5000 | Per-probe timeout (ms) |
| `--proxy <URL\|FILE>` | — | One proxy or mixed per-request proxy rotation file |
| `--status '2xx,3xx,!429'` | common finding codes | Include exact codes/classes and exclude with `!` |
| `--recurse [N]` | off / 3 | Recursive wordlist expansion |
| `--crawl [N]` | off / 3 | HTML, robots, sitemap and redirect discovery |
| `--deep [N]` | off / 3 | Recursion and crawl together |
| `--wildcard strict\|mark\|off` | `strict` | Drop, tag, or disable wildcard handling |
| `--backup auto\|off\|dry-run` | `auto` | Host-derived backups, disable, or request-free preview |
| `--safe` | off | Disable the native 401/403 bypass engine |
| `--tech default\|off\|FILE` | `default` | Embedded, disabled, or custom enrich fingerprints |
| `-H "K: V"` | — | Custom header (repeatable) |
| `--bearer <TOK>` | — | `Authorization: Bearer TOK` |
| `--cookie "K=V"` | — | Static Cookie header value (repeatable) |
| `--httpx-compat` | off | Enrich output in httpx JSON shape |
| `--with-body` | off | Include response body (≤2 MiB) |
| `-q` | off | Hide banner, update check, live findings and progress |
| `-U` / `-c` / `-X` | — | Update / check / uninstall |

Full reference: `httpxer --help`. Advanced exact-size filters are intentionally lossy: `--exclude-root-size` can hide a real page that happens to equal the root body size. `--fuzz-follow-redirects` classifies a terminal response under the requested path and should be used only when that behavior is explicitly required.

## Limitations

- **JS challenges** (Cloudflare Turnstile, Akamai sensor data) — needs a headless browser
- **Behavioral detection** (timing, mouse events, per-IP rate scoring) — static-signature defeat ≠ behavioral defeat
- **IP reputation** — proxy rotation distributes requests but cannot guarantee that an endpoint has good reputation
- **JS endpoint extraction** — crawl parses HTML/robots/sitemap; endpoints embedded inside JavaScript bodies aren't parsed (planned)

Browser emulation can reduce simple static-signature blocks, but it is not a bypass guarantee. Behavioral defenses still apply.

## Build from source

```bash
# Linux (Debian/Ubuntu): sudo apt install -y libclang-dev
# macOS:                 xcode-select --install
# Windows:               choco install -y llvm nasm
git clone https://github.com/assassin-marcos/httpxer && cd httpxer && cargo build --release
```

`libclang` is needed at build time for `boring-sys2` bindgen. The released Linux GNU binary dynamically uses the standard glibc runtime and targets glibc 2.35+; libclang, LLVM, and NASM are not runtime dependencies.

## License / Contact

MIT. By [**@assassin_marcos**](https://twitter.com/assassin_marcos). Issues + PRs: https://github.com/assassin-marcos/httpxer/issues.

**Only scan systems you own or have written permission to test.**
