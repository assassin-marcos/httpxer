# httpxer

**Native httpx + dirsearch replacement: enrichment + recursive fuzz + crawl, with browser-grade TLS impersonation and multi-signal wildcard detection. One 17 MB static binary.**

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
- **Fuzz mode** — host × wordlist Cartesian probe with **recursive** dir bruteforce, **crawl** (HTML/robots/sitemap link extraction), **multi-sample wildcard detection** (2-layer: static catchall + path-echo), and dirsearch-style **live progress bar + findings stream**.

Both modes share a 16-slot **BoringSSL** pool that rotates real-browser JA3/JA4/HTTP-2 fingerprints per probe — defeats static WAF rule-blocks (Cloudflare, Akamai, Imperva, AWS, Datadome).

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

### dirsearch-equivalent invocation

```bash
httpxer -u https://example.com/ \
  -w common.txt,sensitive.txt \
  -t 150 \
  -r -R 3 \
  --crawl --crawl-depth 3 \
  -i 200,301,307,401 \
  --exclude 429,403,404 \
  --timeout-ms 10000 \
  --retries 2 \
  --fuzz-follow-redirects \
  --exclude-root-size \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Original-URL: /" \
  -o everything.txt
```

## Wildcard detection (the FP killer)

Most directory bruteforcers drown in false positives on CDN-fronted / SPA targets. httpxer's detector is multi-sample + multi-layer:

- **Layer 1 — static catchall**: 3 random hex paths probed at start. All 3 must agree on `(status, content_length, content_type, snippet_md5)` to record a wildcard fingerprint. Probes matching the fingerprint are suppressed.
- **Layer 2 — path-echo / dynamic-CL**: when bodies differ but `content_length = k × path_length + base` fits linearly (server reflects path in body), the slope `k` is computed and used to predict the wildcard CL for any new probe path.

Result: ~0 false positives on static-catchall servers, ~6 FPs out of 15,000 probes on path-echo servers (the hardest case). dirsearch is the only other tool that gets close, at 30-50× the wall time.

| Policy | Behavior |
|---|---|
| `--wildcard-policy strict` *(default)* | Drop probes matching the wildcard |
| `--wildcard-policy mark` | Emit them tagged `is_wildcard:true` |
| `--wildcard-policy off` / `--no-wildcard` | Skip pre-flight entirely |

## Recursion + crawl

Pass `-r` (recursion) and/or `--crawl` to turn the host × wordlist single pass into a multi-round orchestrator:

- **Recursion** — discovered directories (301/302/307/308 with `Location == URL + "/"` parity check; opt-in 200+autoindex via `--recurse-on-200`) get re-fuzzed with the wordlist up to `-R N` levels deep.
- **Crawl** — every response body is parsed for HTML `<a/link/script/img/form/iframe>`, robots.txt `Disallow/Allow/Sitemap`, sitemap.xml `<loc>`. Same-host scope + third-party CDN deny list + static-media filter applied. Extracted URLs probed in the next round.

Both share a visited-set + per-host probe/dir budgets (`--max-probes-per-host`, `--max-dirs-per-host`) so recursion never blows up on adversarial targets.

## TLS impersonation

Browser-grade fingerprint rotation via [`wreq`](https://github.com/penumbra-x/rquest) (BoringSSL — Chrome's TLS stack). 16 profiles in the pool:

| Family | Versions |
|---|---|
| Desktop Chrome | 131, 133, 135, 136, 137 |
| Desktop Firefox | 133, 136, 139 |
| Desktop Safari (macOS) | 18.2, 18.3.1, 18.5 |
| Desktop Edge | 131, 134 |
| Mobile Safari (iOS) | 17.4.1, 18.1.1 |
| Mobile Firefox (Android) | 135 |

Each profile sends the exact cipher-suite ordering, TLS extensions, signature algorithms, ALPN, HTTP/2 SETTINGS frame, and matching headers (`sec-ch-ua`, `sec-fetch-*`, `Accept-Encoding: gzip, deflate, br, zstd`) of that browser version.

Verify against a TLS-echo service:
```bash
printf 'https://tls.peet.ws/api/all?n=%s\n' 1 2 3 4 5 > urls.txt
httpxer -l urls.txt -o out.jsonl --with-body --no-tech -t 5
# Inspect 5+ unique JA4s in out.jsonl — all real-browser families
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

Full structured record per finding. Fuzz mode includes `depth`, `source`, `parent_url` for multi-round provenance. Enrich mode (`--httpx-compat`) matches ProjectDiscovery httpx's JSON shape field-for-field.

Live findings stream to stderr above a `[N/total] X% | rps | eta` progress bar. Disable with `--no-live`.

## Auth

```bash
# Custom headers (repeatable)
httpxer ... -H "X-Forwarded-For: 127.0.0.1" -H "X-Original-URL: /"

# Bearer token
httpxer ... --bearer eyJhbGciOiJIUzI1NiJ9.xyz

# Cookie jar (initial seed; Set-Cookie auto-persists)
httpxer ... --cookie "sid=abc123" --cookie "csrf=token"
```

## Flags (most-used)

| Flag | Default | Purpose |
|---|---|---|
| `-u <URL>` / `-l <FILE>` | — | Single target / hosts file (`-` for stdin) |
| `-w <FILE>` | — | Wordlist — presence triggers fuzz mode |
| `-o <FILE>` | — | Output (`.jsonl` → JSON, `.txt` → plain) |
| `-t <N>` | 250 | Concurrent probes |
| `--timeout-ms` | 5000 | Per-probe timeout (ms) |
| `--proxy <URL>` | — | HTTP / HTTPS / SOCKS5 proxy |
| `-r / -R <N>` | off / 3 | Enable recursion, max depth |
| `--crawl / --crawl-depth <N>` | off / 3 | Enable crawl, max depth |
| `-i <codes>` | smart | Status codes to emit (alias: `--match-codes`) |
| `--exclude <codes>` | `429,503` | Status codes to drop |
| `--exclude-root-size` | off | Auto-probe `/` and add CL to exclude list |
| `--exclude-mode segment\|substring` | `segment` | Exclude-list match style |
| `--recurse-on-200` / `--recurse-on-403` | off | Treat these statuses as directories too |
| `-H "K: V"` | — | Custom header (repeatable) |
| `--bearer <TOK>` | — | `Authorization: Bearer TOK` |
| `--cookie "K=V"` | — | Cookie (repeatable; jar persists) |
| `--fuzz-follow-redirects` | off (auto-on with `--crawl`) | Follow redirects in fuzz mode |
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

Static-signature defenses (JA4 rule-blocks, header-pattern rules, UA blocklists) are defeated. Behavioral defenses still apply.

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
