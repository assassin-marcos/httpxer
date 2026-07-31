# httpxer

**Native httpx + dirsearch replacement: enrichment + recursive fuzz + crawl, with browser-grade TLS impersonation, content-aware wildcard detection, auth-dir recursion, and a native 401/403 bypass engine. One static binary.**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()

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

- **Enrich mode** — reads a hostname list, probes each over HTTP(S), emits one NDJSON record per host with DNS / CDN / Wappalyzer tech-detect / HTTP fingerprint. Drop-in for ProjectDiscovery `httpx -json` (use `--httpx-compat` for byte-identical field shape).
- **Fuzz mode** — host × wordlist Cartesian probe with **recursive** dir bruteforce (incl. **auto-recursion into protected `401`/`403` dirs**), **crawl** (HTML/robots/sitemap link extraction), **content-aware wildcard detection** (static catchall + per-request-nonce catchall + path-echo), a **native, content-confirmed `401`/`403` bypass engine**, and dirsearch-style **live progress bar + findings stream**.

Both modes share a 16-slot **BoringSSL** browser-emulation pool. Enrich mode samples the pool per probe; fuzz mode pins one profile per host so wildcard pre-flight and wordlist probes see the same UA-dependent response. Distinct hosts are still distributed across the pool.

## Install

```bash
# Linux / macOS — auto-detects x86_64 / arm64
curl -sL https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.ps1 | iex

# Self-manage
httpxer -U   # install latest release
httpxer -c   # check for updates
httpxer -X   # uninstall
```

## Quickstart

### Enrich mode

```bash
# Drop-in for httpx -json
httpxer -l hosts.txt -o enriched.jsonl

# httpx-compatible field shape (input/host/url/scheme/port/path/method/...)
httpxer -l hosts.txt -o enriched.jsonl --httpx-compat

# From stdin
subfinder -d example.com -silent | httpxer -l - -o enriched.jsonl

# Through a proxy (HTTP / HTTPS / SOCKS5)
httpxer -l hosts.txt -o enriched.jsonl --proxy http://127.0.0.1:8080

# Show every response header (terminal + a `response_headers` JSON object)
httpxer -u example.com --rh

# Authenticated probe — -H / --bearer / --cookie work in BOTH modes (v0.5.0)
httpxer -u https://internal.example.com --bearer "$TOKEN" --rh
```

### Fuzz mode (single target)

```bash
# Basic — wordlist fuzz, smart defaults
httpxer -u https://example.com/ -w wordlist.txt -o out.txt

# Full recon: recursion 3 levels + crawl 3 levels
httpxer -u https://example.com/ -w wordlist.txt -r -R 3 --crawl --crawl-depth 3 -o out.txt

# Plain "STATUS SIZE URL" output (auto-detected from .txt extension)
httpxer -u https://example.com/ -w wordlist.txt -o out.txt
# → 200    1.2KB  https://example.com/admin
# → 301    320B   https://example.com/login
# → 403     --    https://example.com/.git/HEAD

# Full JSONL output (.jsonl extension)
httpxer -u https://example.com/ -w wordlist.txt -o out.jsonl
```

### Multi-dictionary

`-w` accepts **comma-separated wordlists** — they're loaded, merged, and de-duplicated (a per-file load count is printed):

```bash
httpxer -u https://example.com/ -w admin.txt,api.txt,sensitive.txt -o out.txt
#   [wordlist] admin.txt : 1204 paths (+1204 new)
#   [wordlist] api.txt : 980 paths (+812 new)
#   ...
```

### dirsearch-equivalent invocation

```bash
httpxer -u https://example.com/ \
  -w common.txt,sensitive.txt \
  -t 150 \
  -r -R 3 \
  --crawl --crawl-depth 3 \
  -i 200,301,302,307,308 \
  --exclude 429,503 \
  --timeout-ms 10000 \
  --retries 2 \
  --fuzz-follow-redirects \
  -o everything.txt
```

> No `X-Original-URL` / `X-Forwarded-For` headers needed — the **native bypass engine** applies those (and more) *only* on `401`/`403` responses, with the real path and content-confirmation, instead of poisoning every request. Pass `--safe` to disable it.

## Wildcard detection (the FP killer)

Most directory bruteforcers drown in false positives on CDN-fronted / SPA / soft-404 targets. httpxer's detector is multi-sample + multi-layer. Pre-flight probes a mix of **random-hex paths + realistic decoys** (`.conf`, `.config`, `.env`, `/.git/HEAD`) **concurrently**, so detection sees the same catchall your wordlist will hit:

- **Layer 1 — static catchall**: at least two same-status samples agree on `(content_type, content_length, snippet_md5)` within the configured length tolerance. Separate status and extension-family signatures are retained instead of overwriting one another.
- **Layer 2 — path-echo / dynamic-CL**: with at least three samples, `content_length = k × path_length + base` must fit within residual bounds. The slope `k` then predicts the wildcard length for each probe path.
- **Layer 1b — content-aware catchall**: when no path-echo model fits, the catchall body may still vary per request (for example, a request ID or timestamp). UUIDs, long hex/digit runs and timestamps are normalized before hashing. Bounded drift uses normalized-content and token-similarity guards; wide length drift additionally requires the normalized first 2 KiB to agree exactly. Matching is content-aware, never size-only.
- **Bodyless catchall**: the host answers **`2xx` with zero bytes** for *every* path. There is no body to fingerprint, so every layer above is blind to it by construction. `200` + no body across **3 distinct paths** is itself the signature — httpxer learns it per `(host, status, content_type)` and suppresses from then on. A *lone* legitimate empty `200` (a `/ping`-style endpoint) stays below the threshold and is still emitted.

This closes the case where a constant-size catchall with a per-request token used to emit *every* wordlist hit as a fake `200`. The host fingerprint also applies under **recursed directories** (so catchall noise doesn't reappear one level down).

| Policy | Behavior |
|---|---|
| `--wildcard-policy strict` *(default)* | Drop probes matching the wildcard |
| `--wildcard-policy mark` | Emit them tagged `is_wildcard:true` (zero-suppression — you filter later) |
| `--wildcard-policy off` / `--no-wildcard` | Skip pre-flight entirely |

## Recursion + crawl

Pass `-r` (recursion) and/or `--crawl` to turn the host × wordlist single pass into a multi-round orchestrator:

- **Recursion** — discovered directories (301/302/307/308 with `Location == URL + "/"` parity check; opt-in 200+autoindex via `--recurse-on-200`) get re-fuzzed with the wordlist up to `-R N` levels deep.
- **Auth-dir recursion** *(auto-on)* — a `401`/`403` on a **directory-shaped** path (e.g. `/api`, `/internal` — not `/x.php`) is descended into so accessible children behind a protected parent are found (the classic `/api` = 401 → `/api/actuator` = 200). Excluding `401`/`403` from `-i` hides the parent without disabling discovery. A scoped random-child fingerprint prevents identical nested auth walls from becoming new recursion roots. Bounded by `--max-dirs-per-host`; the legacy `--recurse-on-403` flag (recurse *any* 403) still exists.
- **Crawl** — every response body is parsed for HTML `<a/link/script/img/form/iframe>`, robots.txt `Disallow/Allow/Sitemap`, sitemap.xml `<loc>`. Same-host scope + third-party CDN deny list + static-media filter applied. Extracted URLs probed in the next round.

Both share a visited-set + a per-host **directory** budget (`--max-dirs-per-host`, default 200) so recursion never blows up on adversarial targets. Each discovered directory costs a full wordlist pass, so that cap — together with `-R` depth — is what actually bounds a recursive scan.

## Host-derived backup discovery (auto-on in fuzz mode)

Site owners leave archives on the web root named after the site itself — `www.example.com.zip`, `example.com.sql`, `example.zip`. **No wordlist can carry these**, because the filename is a function of the target's own hostname. httpxer derives them per-host at runtime.

Runs automatically whenever a wordlist is set. Pass `--no-backup-fuzz` to turn it off.

```sh
# Auto — nothing to enable
httpxer -u https://example.com -w paths.txt

# Preview candidates, send zero requests
httpxer -u https://example.com -w paths.txt --backup-dry-run

# Add a name the hostname can't reveal (internal project name)
httpxer -u https://shop.example.io -w paths.txt --backup-tokens acmecorp,internal-portal
```

**13 token rules** per host — full host, `www.`-stripped, registrable domain (real Public Suffix List, so `abc.co.uk` doesn't collapse to `co.uk`), SLD alone, dot→underscore/hyphen/removed variants, leftmost label, sub+SLD concatenations, and the current path segment. Ports are stripped: a backup is named after the site, never the socket. Crossed with ~80 extensions across 8 classes (archive, backup marker, database, Java package, disk image, compound, separator, date-stamped).

Everything is decided at runtime:

- **Extension ordering follows the detected stack.** One request reads `Server`, `X-Powered-By` and a body snippet → Java / PHP / .NET / Node / Python / Unknown. Detection **reorders but never excludes** — a misread costs ordering, never a whole finding category.
- **Budget scales with responsiveness.** <400 ms → 300 candidates, <1.2 s → 180, <3 s → 100, slower → 50. Hard ceiling 300/host, so it can't run away on a large scope.
- **Backup directories are proven before expansion.** Two HEADs for `backup/` and `bak/`; the other 17 prefixes are only tried if one exists (200 or 403 both count).
- **Root and current directory both probed**, deduped when identical.

**Zero-false-positive gate.** Naive backup scanning drowns in soft-404s — sites that answer `200 OK` with an HTML "not found" page for any filename. Every candidate must clear all of:

- Status `200`/`206` only. Other statuses are not emitted by backup discovery, and redirects are not followed.
- Soft-404 baseline calibrated from 3 impossible filenames per host; ≥0.95 body similarity is discarded
- Content-Type sanity — `text/html` on a `.zip`/`.sql`/`.db` is discarded unless the bytes say otherwise
- **Magic bytes** — ZIP `50 4B 03 04`, GZIP `1F 8B`, BZIP2, XZ, 7Z, RAR, TAR `ustar`@257, `SQLite format 3`, MS Access — or a plaintext SQL-dump marker
- Edge-security interstitials (challenge/blocked pages) filtered out

Only `status OK + size OK + (magic OR SQL text) + baseline-dissimilar` reaches **CONFIRMED**. A remaining plausible `200`/`206` can be marked **REVIEW**; hard gate failures are discarded.

**Bandwidth-safe.** `HEAD` first; only a promising result earns a ranged `GET` for the first 1024 bytes. The archive itself is never downloaded — a 4 GB `backup.tar.gz` costs ~1 KB to confirm.

Findings go to `<output>.backup.jsonl` (15 fields incl. `base_type`, `magic_matched`, `baseline_similarity`, `confidence`, `verdict`), plus a terminal table for CONFIRMED only.

## 401/403 bypass (native, auto, content-confirmed)

When a probe hits `401`/`403`, httpxer automatically retries it with a small, conservative battery of access-control bypass techniques — **on the forbidden resource only, never on every request**:

- **Header overrides** — `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`
- **Path mutations** — e.g. `…/..;/`

A bypass is reported **only when confirmed**: the retry returns a `2xx` with a non-empty body, its normalized content **differs** from the original block page, and it doesn't match the host catchall. Redirects and empty bodies are not accepted as proof of access. Confirmed hits are emitted with a `bypass:"<technique>"` tag and a visible `[bypass] /admin 403→200 via X-Original-URL` line. Traffic is bounded by a per-host budget; it only ever *adds* findings, never suppresses. Pass **`--safe`** to disable it entirely (for programs/targets where bypass attempts are out of scope).

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
httpxer -l urls.txt -o out.jsonl --with-body --no-tech -t 8
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

Full structured record per finding. Fuzz mode includes `depth`, `source`, `parent_url` for multi-round provenance, and `bypass` (the winning technique) on confirmed 401/403 bypasses. Enrich mode (`--httpx-compat`) matches ProjectDiscovery httpx's JSON shape field-for-field. New fields are `skip_serializing_if`-gated, so existing downstream parsers stay byte-compatible on the common case.

Live findings stream to stderr above a `[N/total] X% | rps | eta` progress bar. Disable with `--no-live`.

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
| `--proxy <URL>` | — | HTTP / HTTPS / SOCKS5 proxy |
| `-r / -R <N>` | off / 3 | Enable recursion, max depth (incl. auto auth-dir recursion) |
| `--crawl / --crawl-depth <N>` | off / 3 | Enable crawl, max depth |
| `-w a.txt,b.txt` | — | Multiple wordlists (merged + de-duplicated) |
| `--wildcard-policy strict\|mark\|off` | `strict` | Drop / tag / skip wildcard matches |
| `--safe` | off | Disable the native 401/403 bypass engine |
| `-i <codes>` | `200,301,302,307,308,401,403` | Status codes to emit (alias: `--match-codes`) |
| `--exclude <codes>` | `429,503` | Status codes to drop |
| `--exclude-root-size` | off | Auto-probe `/` and add CL to exclude list |
| `--exclude-mode segment\|substring` | `segment` | Exclude-list match style |
| `--recurse-on-200` / `--recurse-on-403` | off | Treat these statuses as directories too |
| `-H "K: V"` | — | Custom header (repeatable) |
| `--bearer <TOK>` | — | `Authorization: Bearer TOK` |
| `--cookie "K=V"` | — | Static Cookie header value (repeatable) |
| `--fuzz-follow-redirects` | off (auto-on with `--crawl`) | Follow redirects in fuzz mode |
| `--no-backup-fuzz` | backup discovery on | Disable host-derived backup discovery |
| `--backup-dry-run` | off | Print backup candidates, send no requests |
| `--backup-tokens <LIST>` | — | Extra base-name tokens the hostname can't reveal |
| `--httpx-compat` | off | Enrich output in httpx JSON shape |
| `--with-body` | off | Include response body (≤2 MiB) |
| `--no-live` | live on | Suppress live findings stream on stderr |
| `-q` | off | Suppress banner / progress / update-check |
| `-U` / `-c` / `-X` | — | Update / check / uninstall |

Full reference: `httpxer --help`.

## Limitations

- **JS challenges** (Cloudflare Turnstile, Akamai sensor data) — needs a headless browser
- **Behavioral detection** (timing, mouse events, per-IP rate scoring) — static-signature defeat ≠ behavioral defeat
- **IP reputation** — rotate egress IPs at a higher layer (proxies / residential pool)
- **JS endpoint extraction** — crawl parses HTML/robots/sitemap; endpoints embedded inside JavaScript bodies aren't parsed (planned)

Browser emulation can reduce simple static-signature blocks, but it is not a bypass guarantee. Behavioral defenses still apply.

## Build from source

```bash
# Linux (Debian/Ubuntu): sudo apt install -y libclang-dev
# macOS:                 xcode-select --install
# Windows:               choco install -y llvm nasm
git clone https://github.com/assassin-marcos/httpxer && cd httpxer && cargo build --release
```

`libclang` is needed once at build time (for `boring-sys2` bindgen). The resulting binary is statically linked — runtime has no dependencies.

## License / Contact

MIT. By [**@assassin_marcos**](https://twitter.com/assassin_marcos). Issues + PRs: https://github.com/assassin-marcos/httpxer/issues.

**Only scan systems you own or have written permission to test.**
