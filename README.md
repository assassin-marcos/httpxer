# httpxer

**Native httpx-replacement: enrichment + path-fuzz with browser-grade TLS impersonation, Wappalyzer tech-detect, wildcard suppression. One static binary.**

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

## Modes

httpxer auto-detects which mode to run based on whether `-path / --paths` is set:

| Mode | Trigger | What it does | Output |
|---|---|---|---|
| **Enrich** *(default)* | no `-path` flag | One probe per host. Resolves DNS, tags CDN ranges, runs Wappalyzer tech-detect on the response, follows redirects. | `subdomain, ip, cname, cdn, status_code, content_length, server, title, tech, …` (httpx-compatible) |
| **Fuzz** | `-path <wordlist>` | Host × wordlist Cartesian probe. Pre-flight wildcard fingerprint per host; auto-suppress identical-body false positives; per-request `Policy::none()` so 3xx is a finding, not chased. | `url, input, path, host, status_code, content_length, content_type, title, server, webserver, body_preview, is_wildcard, snippet_md5, tls_impersonation, …` (matches retroh4ck-prober v0.1.0) |

Both modes share the same 16-slot real-browser TLS impersonation pool — wreq + BoringSSL — and the same `-l` input + `-o` output path.

---

## Quickstart

### Enrich mode (default)

```bash
# Drop-in for: httpx -l urls.txt -fr -sc -cl -wc -server -location -title -td -ip -cname -json -no-color -t 250 -o out.json
httpxer -l urls.txt -fr -sc -cl -wc -server -location -title -td -ip -cname -json -no-color -t 250 -o out.jsonl

# With metadata embedded into every record (matches your existing recon-pipeline schema)
httpxer -l subs.txt -o enriched.jsonl \
        --scan-id scan_1776760475 --domain target.com --source-tools "subfinder,amass"

# From stdin
subfinder -d target.com -silent | httpxer -l - -o enriched.jsonl

# Disable WAF bypass on internal/un-fronted targets (a few % faster cold-start)
httpxer -l internal-hosts.txt -o out.jsonl --no-impersonate

# Skip tech-detect for max throughput
httpxer -l huge-list.txt -o out.jsonl --no-tech -t 500
```

All enrich-mode defaults are tuned for real recon — concurrency 250, follow-redirects 3 hops, 5 s probe timeout, 2 MiB streaming body cap, auto-resume on `-o` file.

### Fuzz mode

Pass `-path <wordlist>` to switch from one-probe-per-host enrichment to host × path Cartesian fuzzing.

```bash
# Basic fuzz — host × path Cartesian, wildcard auto-suppress, default match-codes
httpxer -l hosts.txt -path paths.txt -o fuzz.jsonl

# Tune concurrency, retry, status filter
httpxer -l hosts.txt -p paths.txt -o fuzz.jsonl \
        --threads 400 --retries 2 --match-codes 200,301,302,403,500

# Disable wildcard suppression (emit everything, including catch-all 404s)
httpxer -l hosts.txt -p paths.txt -o fuzz.jsonl --no-wildcard

# Mark wildcards instead of dropping them (keep records, tag is_wildcard:true)
httpxer -l hosts.txt -p paths.txt -o fuzz.jsonl --wildcard-policy mark

# Rate-limit to 5 req/s per host so you don't trip per-IP throttling
httpxer -l hosts.txt -p paths.txt -o fuzz.jsonl --rate-limit 5

# Smaller body preview for compact output (default 8192)
httpxer -l hosts.txt -p paths.txt -o fuzz.jsonl --body-preview 1024
```

In fuzz mode httpxer first issues one random-hex-path pre-flight per host to fingerprint the catch-all response (`content_length, content_type, snippet_md5`). Any subsequent fuzz hit with the same triple is flagged `is_wildcard:true` and (under default `strict` policy) suppressed — exactly matching ffuf's wildcard discipline and stopping CDN 404 pages from drowning real findings.

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

### Enrich-mode record (file)
```json
{"subdomain":"www.target.com","scan_id":"scan_xxx","source_tools":"subfinder,amass","ip":"104.16.124.96","cname":"","cdn":"cloudflare","status_code":200,"content_length":1371851,"word_count":173236,"server":"cloudflare","title":"Some Page","tech":"Astro:5.18.1, Cloudflare, HSTS, HTTP/3"}
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

### Fuzz-mode record (file)

Triggered by `-path <wordlist>`. Schema matches retroh4ck-prober v0.1.0 — existing downstream parsers work unchanged.

```json
{"url":"https://target.com/admin","input":"https://target.com","path":"/admin","host":"target.com","status_code":403,"content_length":4552,"content_type":"text/html; charset=UTF-8","title":"403 Forbidden","location":"","server":"nginx","webserver":"nginx","body_preview":"&lt;html&gt;…","tech":[],"method":"GET","is_wildcard":false,"wildcard_policy":"strict","via_proxy":false,"attempts":1,"elapsed_ms":87,"snippet_md5":"bba6966945786dc1b4724012c460a62e","tls_impersonation":"chrome-137","user_agent":"Mozilla/5.0 …","cf_challenge":false,"timestamp":"2026-05-20T03:03:38.655Z","prober":"httpxer/0.3.0"}
```

| Field | Notes |
|---|---|
| `url`, `input`, `path`, `host` | Full URL probed + the input host (scheme+netloc) + path component + bare hostname |
| `status_code`, `content_length`, `content_type`, `title` | HTTP-level metadata |
| `location` | Set on 3xx (fuzz mode does NOT chase redirects — 3xx is a finding) |
| `server`, `webserver` | Both emitted with the same value — some httpx consumers read one, some the other |
| `body_preview` | First `--body-preview` bytes of body, HTML-entity-encoded (`"` → `&#34;`) so downstream `html.unescape()` round-trips |
| `snippet_md5` | MD5 of `body[:200]` — wildcard fingerprint correlator |
| `is_wildcard`, `wildcard_policy` | `true` when `(content_length, content_type, snippet_md5)` matches the per-host wildcard pre-flight; suppressed under default `strict` |
| `attempts`, `elapsed_ms` | `1 + retries actually used`; total request time |
| `tls_impersonation`, `user_agent` | The TLS profile + UA actually used (one of 16 real-browser slots) |
| `cf_challenge` | Set when the response matches Cloudflare's `cf-chl-bypass` / `Just a moment...` patterns |
| `via_proxy`, `timestamp`, `prober`, `method`, `tech` | Routing flag; ISO-8601 UTC; `"httpxer/0.3.0"`; always `"GET"`; always `[]` (fuzz mode skips tech-detect) |
| `error` | Set only when `--include-errors` is on AND the request failed (status_code=0) |

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
# Probe a JA3/JA4 echo service multiple times; each request hits a different
# pool slot and reports its real-browser TLS fingerprint.
printf 'https://tls.peet.ws/api/all?n=%s\n' 1 2 3 4 5 6 7 8 9 10 > urls.txt
httpxer -l urls.txt -o out.jsonl --no-tech --with-body -t 4
python3 -c "import json; [print(json.loads(json.loads(l)['body'])['tls']['ja4']) for l in open('out.jsonl') if json.loads(l).get('body')]"
```
With impersonation: 5+ unique JA4s, all real-browser families. With `--no-impersonate`: 1 static non-browser JA4.

---

## Flags

Full list via `httpxer -h`. Most-used:

### Shared flags (enrich + fuzz)

| Flag | Default | Purpose |
|---|---|---|
| `-l, --list <FILE>` | — | Input file (one hostname/URL per line, `-` = stdin) |
| `-o, --output <FILE>` | — | Output NDJSON file |
| `-t, --threads <N>` | 250 | Concurrent HTTP probes |
| `--timeout-ms` | 5000 | Per-probe HTTP timeout |
| `--no-impersonate` | off | Skip TLS-fingerprint rotation (faster on un-fronted targets) |
| `--no-resume` | resume | Overwrite output file (enrich); always truncate (fuzz) |
| `-u` / `-c` / `-X` | — | Self-update / check / uninstall |
| `--no-art` / `--no-update-check` / `-q` | — | Suppress banner / update-check / both |

### Enrich-mode flags

| Flag | Default | Purpose |
|---|---|---|
| `--scan-id`, `--domain`, `--source-tools` | — | Metadata embedded in every record |
| `--no-tech` / `--no-cdn` | both on | Skip Wappalyzer / CDN-range fetch |
| `--with-body` | off | Include response body (≤2 MiB) in JSON |
| `--no-follow-redirects` | follow | Disable 3-hop redirect chain |
| `--fingerprints <PATH>` | embedded | Load fresh Wappalyzer fingerprints |
| **httpx-compat (no-ops, accepted)** | — | `-fr -sc -cl -wc -server -location -title -td -ip -cname -json -no-color -silent` |

### Fuzz-mode flags

Setting `-path <wordlist>` switches to fuzz mode. All flags below are inert when no wordlist is provided.

| Flag | Default | Purpose |
|---|---|---|
| `-p, --paths <FILE>` | — | Wordlist file — presence triggers fuzz mode |
| `--match-codes`, `--mc` | `200,301,302,307,308,401,403` | Comma-separated status filter — others dropped |
| `--body-preview <N>` | `8192` | First N bytes of body, HTML-entity-encoded in output |
| `--wildcard-policy <P>` | `strict` | `strict` (suppress wildcards) / `mark` (tag, keep) / `off` (skip pre-flight) |
| `--no-wildcard` | off | Shortcut for `--wildcard-policy off` |
| `--rate-limit <RPS>` | `0` (off) | Per-host requests/sec ceiling |
| `--retries <N>` | `1` | Retry count on network error |
| `--include-errors` | off | Emit `status_code:0` records for failed probes |
| `--proxy <URL>` | — | HTTP/SOCKS5 proxy (reserved — see CHANGELOG for status) |

---

## Limitations

- **JS challenges** (Cloudflare Turnstile / Akamai sensor data) — needs a headless browser, not raw HTTP
- **Behavioural detection** (timing, mouse events, per-IP rate scoring) — static-signature defeat ≠ behavioural defeat
- **IP reputation** — rotate egress IPs at a higher layer (proxies / residential pool)
- **Device-fingerprinting WAFs** (Datadome / PerimeterX canvas+WebGL) — needs JS execution

Static-signature defenses (JA4 rule-blocks, header-pattern rules, UA blocklists) are defeated. Behavioural defenses still apply.

## Performance

v0.3.0 fuzz mode matches retroh4ck-prober v0.1.0 baseline on per-probe throughput, wildcard accuracy, and JSONL schema. See CHANGELOG for the merge notes and `--no-wildcard` baseline numbers.

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
