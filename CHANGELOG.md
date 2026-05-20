# Changelog

All notable changes to **httpxer** are recorded here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [0.3.4] — 2026-05-20

### Fixed
- **HTTP response decompression now enabled.** Added `gzip`, `brotli`, `deflate`, `zstd` features to the `wreq` dependency. Real-browser TLS impersonation profiles advertise `Accept-Encoding: gzip, deflate, br, zstd` in request headers (matching real Chrome/Firefox), so servers respond with compressed bodies. Without the matching client-side decoders the body was returned as raw bytes — which looked like binary garbage to downstream parsers and tripped pattern-loose regex validators by accident (the `JU3=` / `H$2=` byte sequences inside gzip output match e.g. `.env`-file detection regex `^[A-Za-z_][A-Za-z0-9_]*=`). Smoke probe against a gzip-serving target now returns clean readable HTML (0 non-printable chars in first 200 bytes, was 100% binary garbage before).

### Changed
- Version: 0.3.3 → **0.3.4**
- Binary size: +~200 KB for the four decompression decoders (net 16 MB → 16.2 MB on Linux x86_64)

## [0.3.3] — 2026-05-20

### Added
- **`--httpx-compat`** — emit enrich-mode records in ProjectDiscovery httpx's JSON shape. `input` replaces `subdomain`; `a` / `aaaa` arrays replace the single `ip` string; `cname` and `tech` become arrays; `webserver` is added alongside `server`; `host_ip` is the first A record (falling back to first AAAA). Default httpxer shape is unchanged when the flag is off.

### Changed
- Version: 0.3.2 → **0.3.3**

### Unchanged (compatibility)
- Default enrich JSONL shape is unchanged when `--httpx-compat` is not set.
- All v0.3.2 flags continue to work unchanged.

## [0.3.2] — 2026-05-20

### Added
- **`--proxy <URL>` is now fully wired** — every client in the 16-slot impersonation pool is built with `.proxy(wreq::Proxy::all(url)?)` so both enrich and fuzz modes route all egress through the configured upstream. Accepts `http://`, `https://`, `socks5://`, and `socks5h://`. Invalid URLs fail loudly at startup before the banner renders.
- **`via_proxy` field on every enrich record** — boolean flag set whenever `--proxy` is in effect. Mirrors the existing fuzz-mode `via_proxy` so both schemas advertise proxy routing consistently.

### Changed
- Version: 0.3.0 → **0.3.2**
- `wreq` feature set now includes `"socks"` — required for SOCKS5 proxy URLs to parse. Adds the `tokio-socks` transitive dep (~50 KB).

### Fixed
- Redirect-cap default raised from 3 to 10 hops + new `--max-redirects` flag — already shipped earlier on `main`; rolled into this release for completeness.

### Unchanged (compatibility)
- Default enrich JSONL shape is byte-compatible with v0.3.0 when `--proxy` is not set (the only new field is `via_proxy:false`, which downstream parsers should ignore by virtue of not reading unknown keys).
- All v0.3.0 fuzz-mode flags continue to work unchanged.

## [0.3.0] — 2026-05-20

### Added
- **Fuzz mode** — host × wordlist Cartesian probe. Triggered by `-path / --paths <wordlist>`. Issues N probes per host, emits one JSONL record per finding. Schema matches retroh4ck-prober v0.1.0 so existing downstream parsers keep working.
- **Wildcard auto-suppression** — per-host random-hex-path pre-flight records `(content_length, content_type, snippet_md5)`. Subsequent fuzz hits with the same triple are tagged `is_wildcard:true` and (under default `strict` policy) suppressed. Stops CDN catch-all 404 pages from drowning real findings.
- `--match-codes` / `--mc` — comma-separated status-code filter (default `200,301,302,307,308,401,403`)
- `--body-preview <N>` — first N bytes of body, HTML-entity-encoded in JSONL (default `8192`)
- `--wildcard-policy strict|mark|off` and `--no-wildcard` shortcut
- `--rate-limit <RPS>` — per-host requests/sec ceiling, via `governor` (default `0` = off)
- `--retries <N>` — retry count on network error (default `1`)
- `--include-errors` — emit `status_code:0` records for failed probes
- `--proxy <URL>` — HTTP / SOCKS5 proxy flag (sets `via_proxy:true` in output; full pool-builder wiring lands in v0.3.x)

### Changed
- Version: 0.2.4 → **0.3.0**
- Tagline: now reflects dual-mode operation (`enrichment + path-fuzz`)
- Pool slots now carry a `tag` (e.g. `"chrome-137"`, `"firefox-139"`) for the fuzz-mode `tls_impersonation` JSONL field
- New deps: `md-5`, `hex`, `governor`, `chrono` — all gated to the fuzz path

### Unchanged (compatibility)
- Enrich mode is byte-identical to v0.2.4 — same flags, same defaults, same output schema, same 16-slot TLS pool, same DNS / CDN / Wappalyzer path
- All v0.2.x CLI flags continue to work
- Single static binary — no new runtime dependencies

### Performance / verification
- 5-host CDN-fronted cohort × 433-path backup wordlist (2165 probes total)
  - With default `strict` wildcard suppression: ~420 records emitted in ~10 s (~210 rps)
  - With `--no-wildcard`: ~1730 records — confirming ~75% catch-all noise reduction
- Schema parity vs retroh4ck-prober v0.1.0: 100% field-name match (25 / 25), zero missing, zero extra
- Binary size: 16 MB (unchanged from v0.2.4 — new deps are small)

## [0.2.4] — 2026-05-19

Pre-v0.3 baseline. See git log for the v0.2.x development history.
