# httpxer

**Native httpx-enrichment replacement with browser-grade TLS impersonation.**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()

One static binary that reads a hostname list, probes each via HTTP(S), and emits NDJSON in the exact shape ProjectDiscovery `httpx -json` produces — plus a CDN tag and Wappalyzer tech-detect — using **BoringSSL** (Chrome's own TLS stack) with a **rotating pool of 16 real-browser JA3/JA4 + HTTP/2 fingerprints** so Cloudflare / Akamai / Imperva / Datadome can't rule-block on a static scanner signature.

```
$ httpxer -l subs.txt -fr -sc -cl -wc -server -location -title -td -ip -cname -json -no-color -t 250 \
          --scan-id scan_xxx --domain example.com --source-tools "subfinder,amass" \
          -o enriched.jsonl
[+] tech-detect: loaded 7524 apps
[+] CDN table: 1245 ranges
[+] TLS impersonation: rotating real-browser JA3/JA4 + HTTP/2 fingerprints
[+] probing 615 hosts (250 concurrent)…
  [615/615]
[+] done: wrote 615 records to enriched.jsonl
```

---

## What it does

| | httpx | httpxer |
|---|---|---|
| Status code, title, content-length, redirect chain, server header | ✓ | ✓ |
| Wappalyzer tech-detect (7524 apps, same fingerprint set as httpx) | ✓ | ✓ |
| NDJSON output, follow-redirects, concurrent probing | ✓ | ✓ |
| IP, CNAME, CDN tag in same record | ✓ (IP/CNAME), CDN partial | ✓ (live-fetched ranges per run) |
| Rotating real-browser TLS fingerprints (JA3/JA4) | ✗ (single static fingerprint) | **✓ (16 profiles, random per probe)** |
| HTTP/2 SETTINGS frame matches real browser | ✗ | **✓** |
| Auto-resume on `-o` file (re-run skips done hosts) | ✗ | **✓** |
| Per-record `error` field (no silent drops) | ✗ | **✓** |
| Single static binary, no Go runtime | ✗ | **✓** |

---

## Install (prebuilt binary)

### Linux x86_64

```bash
curl -sL https://github.com/assassin-marcos/httpxer/releases/latest/download/httpxer-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv httpxer /usr/local/bin/
httpxer --help
```

### macOS Apple Silicon (M1/M2/M3/M4)

```bash
curl -sL https://github.com/assassin-marcos/httpxer/releases/latest/download/httpxer-aarch64-apple-darwin.tar.gz | tar xz
sudo mv httpxer /usr/local/bin/
```

### macOS Intel

```bash
curl -sL https://github.com/assassin-marcos/httpxer/releases/latest/download/httpxer-x86_64-apple-darwin.tar.gz | tar xz
sudo mv httpxer /usr/local/bin/
```

### Windows (PowerShell)

```powershell
Invoke-WebRequest -Uri https://github.com/assassin-marcos/httpxer/releases/latest/download/httpxer-x86_64-pc-windows-msvc.zip -OutFile httpxer.zip
Expand-Archive .\httpxer.zip -DestinationPath .
# Move httpxer.exe somewhere on PATH, e.g.:
Move-Item .\httpxer.exe "$env:USERPROFILE\bin\httpxer.exe"
```

---

## Build from source

httpxer depends on `wreq` → `boring-sys2` → BoringSSL. Each OS needs `libclang` once at build time (the resulting binary is statically linked, so end users don't need it):

```bash
# Linux  (Debian/Ubuntu/Mint/...)
sudo apt install -y libclang-dev

# macOS  (Apple Clang ships with Xcode CLT — already there if `clang --version` works)
xcode-select --install   # only if you don't have it

# Windows
choco install -y llvm nasm
```

Then:

```bash
git clone https://github.com/assassin-marcos/httpxer
cd httpxer
cargo build --release
# binary at ./target/release/httpxer
```

---

## Drop-in replacement for httpx

Your existing httpx command:

```bash
httpx -l final_resolved.txt -fr -sc -cl -wc -server -location -title -td -ip -t 250 -cname -json -no-color -o out.json
```

Becomes (same flags, plus three metadata flags):

```bash
httpxer -l final_resolved.txt -fr -sc -cl -wc -server -location -title -td -ip -t 250 -cname -json -no-color -o out.jsonl \
        --scan-id scan_xxx --domain example.com --source-tools "subfinder,amass"
```

The httpx flags (`-fr -sc -cl -wc -server -location -title -td -ip -cname -json -no-color`) are accepted as **no-ops** — all those features are always on in httpxer's JSON output. An argv pre-processor converts Go-style single-dash long flags (`-fr`, `-no-color`) into clap's double-dash form before parsing.

---

## Output schema (NDJSON, one record per line)

```json
{
  "subdomain": "www.cloudflare.com",
  "domain": "example.com",
  "scan_id": "scan_1776760475_d00d07",
  "source_tools": "subfinder,amass",
  "ip": "104.16.124.96",
  "cname": "",
  "cdn": "cloudflare",
  "status_code": 200,
  "content_length": 1371851,
  "word_count": 173236,
  "server": "cloudflare",
  "title": "Cloudflare: Build for the agent era",
  "final_url": null,
  "redirect_chain": [],
  "tech": "Astro:5.18.1, Cloudflare, Cloudflare Bot Management, HSTS, HTTP/3, OneTrust"
}
```

Fields:

| Field | Type | Notes |
|---|---|---|
| `subdomain` | string | Input hostname (or extracted from input URL) |
| `domain`, `scan_id`, `source_tools` | string | Embedded from CLI flags into every record |
| `ip` | string | First A/AAAA from parallel hickory-DNS lookup; `""` on NXDOMAIN |
| `cname` | string | First CNAME under `subdomain`, or `""` if directly A-recorded |
| `cdn` | string | `cloudflare` / `cloudfront` / `fastly` / `google`, or `""` if none |
| `status_code` | integer | HTTP status |
| `content_length` | integer | Wire `Content-Length`; falls back to body length if header is absent (H2 strips it on auto-decompression) |
| `word_count` | integer | Whitespace-separated tokens in the body — matches httpx `-wc` |
| `server` | string | Response `Server` header |
| `location` | string | Response `Location` header (last hop) |
| `title` | string | Parsed `<title>`, whitespace-collapsed, ≤160 chars |
| `final_url` | string | Set only if redirects were followed |
| `redirect_chain` | array | Intermediate URLs (omitted when ≤1 hop) |
| `tech` | string | `"Name:Version, Name, Name:Version"` (httpx-compat) |
| `body` | string | Response body (≤2 MiB) — only when `--with-body` |
| `error` | string | DNS / HTTP failure reason, absent on success |

---

## TLS impersonation — the headline feature

Modern WAFs (Cloudflare, Akamai, Imperva, Datadome, PerimeterX) fingerprint the **TLS ClientHello** (JA4+ — the post-Chrome-110 successor to JA3) and **HTTP/2 SETTINGS frame** to detect tools regardless of User-Agent. A scanner using `reqwest` / `curl` / `python requests` has a *single static fingerprint* that's trivial to rule-block.

httpxer rotates **16 real-browser profiles** per probe via the [`wreq`](https://github.com/penumbra-x/rquest) crate (BoringSSL-based — Chrome's own TLS stack):

| Family | Versions |
|---|---|
| Desktop Chrome | 131, 133, 135, 136, 137 |
| Desktop Firefox | 133, 136, 139 |
| Desktop Safari (macOS) | 18.2, 18.3.1, 18.5 |
| Desktop Edge | 131, 134 |
| Mobile Safari (iOS) | 17.4.1, 18.1.1 |
| Mobile Firefox (Android) | 135 |

Each profile sets the exact cipher suite ordering, TLS extensions, signature algorithms, supported groups, ALPN, HTTP/2 SETTINGS frame, and matching browser-realistic headers (`sec-ch-ua`, `sec-fetch-*`, `Accept-Encoding` including `zstd`, etc.) of the impersonated browser. Per-profile Accept-Language varies too (`en-US`, `en-GB`, mixed locales).

### Verify it works

```bash
# Probe 10 different URLs against the public TLS-fingerprint echoer
printf 'https://tls.peet.ws/api/all?n=%s\n' 1 2 3 4 5 6 7 8 9 10 > /tmp/check.txt
httpxer -l /tmp/check.txt -o /tmp/out.jsonl --no-tech --with-body -t 4

# Pull the JA4 hash each probe was tagged with
python3 -c "
import json
for l in open('/tmp/out.jsonl'):
    r = json.loads(l)
    d = json.loads(r['body'])
    print(d['tls']['ja4'])"
```

With impersonation on you'll see **5+ unique real-browser JA4 hashes** across the 10 probes (Chrome `t13d2014h2_a09f3c656075_*`, Safari `t13d1516h2_*`, etc.). Without (`--no-impersonate`), all 10 produce a single static non-browser JA4 — the kind a WAF rule-blocks in one line.

---

## All flags

```
USAGE: httpxer [OPTIONS] -l <FILE> -o <FILE>

INPUT / OUTPUT
  -l, --list <FILE>            Input file (one hostname/URL per line, "-" for stdin)
  -o, --output <FILE>          Output NDJSON file
      --no-resume              Overwrite output instead of appending unscanned hosts
      --with-body              Include response body (≤2 MiB) in each record

CONCURRENCY / TIMING
  -t, --threads <N>            Concurrent HTTP probes (default 250)
      --timeout-ms <N>         Per-probe HTTP timeout in ms (default 5000)
      --no-follow-redirects    Disable redirect following (default: follow 3 hops)
      --dns-concurrency <N>    Concurrent DNS lookups (default 100)
      --dns-timeout <SEC>      DNS timeout per lookup (default 3)

OUTPUT METADATA
      --scan-id <ID>           Embed in every record under "scan_id"
      --domain <ROOT>          Embed in every record under "domain"
      --source-tools <TOOLS>   Embed in every record under "source_tools" (e.g. "subfinder,amass")

TLS / WAF BYPASS
      --no-impersonate         Disable browser TLS impersonation (faster cold-start, fine for non-WAF targets)

ENRICHMENT
      --no-cdn                 Skip live CDN range fetch (cdn always "")
      --no-tech                Skip Wappalyzer tech-detect
      --fingerprints <PATH>    Load tech-detect fingerprints from this path (default: embedded snapshot)

HTTPX COMPATIBILITY (no-ops — features always on)
  -fr   -sc   -cl   -wc   -server   -location   -title   -td   -ip
  -cname   -json   -no-color   -silent
```

---

## What's NOT bypassed (honest scope)

- **Cloudflare / Akamai JavaScript challenges** — the "checking your browser" / Turnstile CAPTCHA. Needs a headless browser to execute JS.
- **Behavioural / timing analysis** — multi-request patterns, mouse-event correlation. Static-signature defeat ≠ behavioural defeat.
- **IP reputation / rate limits** — need to rotate egress IPs at a higher layer (proxies / residential pool).
- **Datadome / PerimeterX device-fingerprinting** — relies on JS-injected canvas/audio/WebGL fingerprints we can't synthesize.

Static-signature defenses (JA4 rule-blocks, header-pattern rules, UA blocklists) are defeated. Behavioural defenses still apply.

---

## License / Contact

MIT. Developed by [**@assassin_marcos**](https://twitter.com/assassin_marcos). Issues + PRs at https://github.com/assassin-marcos/httpxer/issues.

**Disclaimer:** Security-research tool. **Only scan systems you own or have written permission to test.**
