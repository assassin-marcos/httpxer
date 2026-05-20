# Changelog

All notable changes to **httpxer** are recorded here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

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
