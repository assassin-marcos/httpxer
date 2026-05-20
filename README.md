# httpxer

**Native httpx-enrichment replacement with browser-grade TLS impersonation — one static binary, drop-in `httpx` flags.**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![X / Twitter](https://img.shields.io/badge/DM-%40assassin__marcos-1da1f2.svg)](https://twitter.com/assassin_marcos)

```
 _     _   _
| |__ | |_| |_ _ ____  _____ _ __
| '_ \| __| __| '_ \ \/ / _ \ '__|
| | | | |_| |_| |_) >  <  __/ |
|_| |_|\__|\__| .__/_/\_\___|_|
              |_|     httpxer · by assassin_marcos
```

Reads a hostname list, probes each via HTTP(S), emits NDJSON in the exact shape ProjectDiscovery `httpx -json` produces — plus a CDN tag and 7524-app Wappalyzer tech-detect — using **BoringSSL** with **16 rotating real-browser JA3/JA4 + HTTP/2 fingerprints** per probe so Cloudflare / Akamai / Imperva / Datadome can't rule-block on a static scanner signature.

---

## Install

```bash
# Linux / macOS — auto-detects x86_64 / arm64
curl -sL https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.ps1 | iex

# Manage with the binary itself
httpxer -u    # install latest
httpxer -c    # check for updates
httpxer -X    # uninstall
```

Installs to `/usr/local/bin/httpxer` (Linux/macOS, sudo only if needed) or `%USERPROFILE%\bin\httpxer.exe` (Windows, auto-added to user PATH). Override with `INSTALL_DIR=…`.

---

## Quickstart

```bash
# Drop-in for: httpx -l urls.txt -fr -sc -cl -wc -server -location -title -td -ip -cname -json -no-color -t 250 -o out.json
httpxer -l urls.txt -fr -sc -cl -wc -server -location -title -td -ip -cname -json -no-color -t 250 -o out.jsonl

# With metadata embedded into every record (matches your existing recon-pipeline schema)
httpxer -l subs.txt -o enriched.jsonl \
        --scan-id scan_1776760475 --domain example.com --source-tools "subfinder,amass"

# From stdin
subfinder -d example.com -silent | httpxer -l - -o enriched.jsonl

# Disable WAF bypass on internal/un-fronted targets (a few % faster cold-start)
httpxer -l internal-hosts.txt -o out.jsonl --no-impersonate

# Skip tech-detect for max throughput
httpxer -l huge-list.txt -o out.jsonl --no-tech -t 500
```

All defaults are tuned for real recon — concurrency 250, follow-redirects 3 hops, 5 s probe timeout, 2 MiB streaming body cap, auto-resume on `-o` file.

---

## Output (NDJSON, one record per line)

Stderr (TTY):
```
 _     _   _
| |__ | |_| |_ _ ____  _____ _ __
| '_ \| __| __| '_ \ \/ / _ \ '__|
| | | | |_| |_| |_) >  <  __/ |
|_| |_|\__|\__| .__/_/\_\___|_|
              |_|
        httpxer 0.2.3  (latest)  ·  by assassin_marcos  ·  github.com/assassin-marcos/httpxer

[+] tech-detect: loaded 7524 apps
[+] CDN table: 1245 ranges
[+] TLS impersonation: rotating real-browser JA3/JA4 + HTTP/2 fingerprints
[+] probing 615 hosts (250 concurrent)…
  [615/615]
[+] done: wrote 615 records to enriched.jsonl
```

One record (file):
```json
{"subdomain":"www.cloudflare.com","scan_id":"scan_xxx","source_tools":"subfinder,amass","ip":"104.16.124.96","cname":"","cdn":"cloudflare","status_code":200,"content_length":1371851,"word_count":173236,"server":"cloudflare","title":"Cloudflare: Build for the agent era","tech":"Astro:5.18.1, Cloudflare, Cloudflare Bot Management, HSTS, HTTP/3, OneTrust"}
```

| Field | Notes |
|---|---|
| `subdomain` | Input hostname (or extracted from input URL) |
| `domain`, `scan_id`, `source_tools` | Embedded from CLI flags into every record |
| `ip` / `cname` / `cdn` | Live DNS (hickory, A+AAAA+CNAME) + live CDN-range tagging (Cloudflare / CloudFront / Fastly / Google) |
| `status_code`, `content_length`, `word_count`, `server`, `location`, `title` | Matches httpx `-sc -cl -wc -server -location -title` |
| `final_url`, `redirect_chain` | Set only when redirects were followed |
| `tech` | `"Name:Version, Name, Name:Version"` — 7524 Wappalyzer fingerprints, same set httpx uses |
| `body` | Response body (≤2 MiB) — only when `--with-body` |
| `error` | DNS / HTTP failure reason, absent on success |

---

## TLS impersonation

Modern WAFs fingerprint the TLS ClientHello (JA4+ — Cloudflare, AWS, VirusTotal use it now) and HTTP/2 SETTINGS frame. A scanner using plain `reqwest` / `curl` / `python requests` has one static signature; trivial to rule-block. httpxer rotates 16 real-browser profiles via [`wreq`](https://github.com/penumbra-x/rquest) (BoringSSL — Chrome's own TLS stack):

| Family | Versions |
|---|---|
| Desktop Chrome | 131, 133, 135, 136, 137 |
| Desktop Firefox | 133, 136, 139 |
| Desktop Safari (macOS) | 18.2, 18.3.1, 18.5 |
| Desktop Edge | 131, 134 |
| Mobile Safari (iOS) | 17.4.1, 18.1.1 |
| Mobile Firefox (Android) | 135 |

Each profile sets the exact cipher-suite ordering, TLS extensions, signature algorithms, ALPN, HTTP/2 SETTINGS frame, and matching browser-realistic headers (`sec-ch-ua`, `sec-fetch-*`, `Accept-Encoding` incl. `zstd`) of the impersonated browser version. Accept-Language varies per slot too.

**Verify it works:**
```bash
printf 'https://tls.peet.ws/api/all?n=%s\n' 1 2 3 4 5 6 7 8 9 10 > /tmp/c.txt
httpxer -l /tmp/c.txt -o /tmp/o.jsonl --no-tech --with-body -t 4
python3 -c "import json; [print(json.loads(l)['body'] and json.loads(json.loads(l)['body'])['tls']['ja4']) for l in open('/tmp/o.jsonl')]"
```
With impersonation: 5+ unique JA4s, all real-browser families. With `--no-impersonate`: 1 static non-browser JA4.

---

## Flags

Full list via `httpxer -h`. Most-used:

| Flag | Default | Purpose |
|---|---|---|
| `-l, --list <FILE>` | — | Input file (one hostname/URL per line, `-` = stdin) |
| `-o, --output <FILE>` | — | Output NDJSON file (append + resume by default) |
| `-t, --threads <N>` | 250 | Concurrent HTTP probes |
| `--scan-id`, `--domain`, `--source-tools` | — | Metadata embedded in every record |
| `--no-impersonate` | off | Skip TLS-fingerprint rotation (faster on un-fronted targets) |
| `--no-tech` / `--no-cdn` | both on | Skip Wappalyzer / CDN-range fetch |
| `--with-body` | off | Include response body (≤2 MiB) in JSON |
| `--no-follow-redirects` | follow | Disable 3-hop redirect chain |
| `--timeout-ms` | 5000 | Per-probe HTTP timeout |
| `--no-resume` | resume | Overwrite output file, don't skip already-probed |
| `--fingerprints <PATH>` | embedded | Load fresh Wappalyzer fingerprints |
| `-u` / `-c` / `-X` | — | Self-update / check / uninstall |
| `--no-art` / `--no-update-check` / `-q` | — | Suppress banner / update-check / both |
| **httpx-compat (no-ops, accepted)** | — | `-fr -sc -cl -wc -server -location -title -td -ip -cname -json -no-color -silent` |

---

## Limitations

- **JS challenges** (Cloudflare Turnstile / Akamai sensor data) — needs a headless browser, not raw HTTP
- **Behavioural detection** (timing, mouse events, per-IP rate scoring) — static-signature defeat ≠ behavioural defeat
- **IP reputation** — rotate egress IPs at a higher layer (proxies / residential pool)
- **Device-fingerprinting WAFs** (Datadome / PerimeterX canvas+WebGL) — needs JS execution

Static-signature defenses (JA4 rule-blocks, header-pattern rules, UA blocklists) are defeated. Behavioural defenses still apply.

---

## Build from source

```bash
# Linux (Debian/Ubuntu): sudo apt install -y libclang-dev
# macOS:  xcode-select --install
# Windows: choco install -y llvm nasm
git clone https://github.com/assassin-marcos/httpxer && cd httpxer && cargo build --release
```

`libclang` is needed once at build time (for `boring-sys2` bindgen). The resulting binary is statically linked — end users never need it at runtime.

---

## License / Contact

MIT. Developed by [**@assassin_marcos**](https://twitter.com/assassin_marcos). Issues + PRs at https://github.com/assassin-marcos/httpxer/issues.

**Disclaimer:** Security-research tool. **Only scan systems you own or have written permission to test.**
