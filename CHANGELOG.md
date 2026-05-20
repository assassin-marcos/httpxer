# Changelog

All notable changes to **httpxer** are recorded here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [0.3.6] — 2026-05-20

### Fixed
- **`--httpx-compat` is now actually httpx-compatible.** Side-by-side against `httpx -fr -sc -cl -wc -server -location -title -td -ip -cname -json` on the same target, the JSON shape now matches field-for-field. The pre-v0.3.6 compat output was missing 11 fields and put a URL where httpx puts a bare hostname — DB ingest paths that keyed off `host` were dropping httpxer records.
  - `input` is now the **bare hostname** (was a URL — this was the DB-ingest blocker).
  - `host` is now emitted as the bare hostname (was missing entirely).
  - `url` is the full URL with scheme (this is what `input` used to hold).
  - `scheme` / `port` / `path` / `method` are broken out as discrete fields.
  - `timestamp` (RFC3339 nanosecond UTC), `time` (Go-formatted duration like `"662.326051ms"`), `failed` (boolean), `cdn_name`, `cdn_type` (`cdn` / `cloud` per ProjectDiscovery cdncheck categories), `content_type`, `lines` all added.
  - `word_count` is now serialised as `words` in compat mode (httpx field name); the default shape keeps `word_count`.
- **CDN coverage expanded ~5×.** AWS IP ranges are now fully ingested, not just CLOUDFRONT prefixes. A johndeerecloud target sitting on EC2 EU-Central (`3.78.154.254`) that previously showed `cdn:""` now tags as `cdn_name:"aws", cdn_type:"cloud"` — matching httpx behavior. Linear-scan order keeps CLOUDFRONT-specific prefixes ahead of generic AWS so a CloudFront IP still tags as `cloudfront`.
- **`time` field on every probe.** Total wall-clock from the first `send()` to the terminal response, including all redirect hops. Go-style duration format (`ms` for sub-second, `s` for ≥1 s; `µs` and `ns` for very fast).
- **`content_type` exposed.** Pulled from the response's `Content-Type` header. Surfaced in both the default and compat shapes.
- **`lines` exposed.** Body line count via `str::lines()`. Both shapes.

### Added
- `probe::format_elapsed_go(Duration) -> String` — Go-style duration formatter (matches `time.Duration.String()`).
- 3 new regression tests: `format_elapsed_go_picks_correct_unit`, `cdn_type_categories_match_httpx`, `compat_shape_marks_failed_records`.

### Changed
- Version: 0.3.5 → **0.3.6**
- `HttpProbeResult` gained `elapsed: Duration`, `content_type: Option<String>`, `line_count: usize`.
- `EnrichRecord` (default shape) gained `content_type` / `lines` / `time` (all `skip_serializing_if = "Option::is_none"`).
- `HttpxCompatRecord` reshaped (see Fixed above). 14 fields added or renamed.
- `cdn.rs`: `fetch_cloudfront` replaced by `fetch_aws_all` which splits the AWS ip-ranges feed into CLOUDFRONT and generic-AWS entry sets in one pass. CDN table size jumps from ~3 k to ~16 k ranges (the AWS feed dominates).

### Unchanged (compatibility)
- **Default httpxer JSONL shape**: pre-existing keys are unchanged; the only difference is the addition of `content_type` / `lines` / `time` (all optional, absent when missing). Old consumers ignore unknown keys.
- All v0.3.5 CLI flags continue to work unchanged.
- Fuzz mode output schema unchanged.

### Verification (smoke test against `0001.abrower.ppstdevl.ghns-web-platform-r2-prod-standalone4.eu.e00.c01.johndeerecloud.com`)
- httpxer compat: `input` = bare hostname, `host` = bare hostname, `url` = full URL ✅
- `cdn_name:"aws", cdn_type:"cloud"` ✅ (was empty before)
- `scheme:"https"`, `port:"443"`, `path:"/"`, `method:"GET"` ✅
- `time:"663.003392ms"` ✅ Go-duration format
- `content_type:"text/html"`, `words:83`, `lines:13`, `failed:false` ✅
- 23 / 23 tests pass

## [0.3.5] — 2026-05-20

### Fixed
- **`final_url` no longer reports an unreachable URL on mid-chain redirect failure.** When a follow-redirect chain failed at hop N+1, `final_url` was set to the URL we tried but couldn't reach, while the rest of the record (`status_code`, `headers`, `title`, `body`) described the *previous* hop. Now tracked via a separate `last_url` variable that shadows `current` only after a successful response — failed hops leave it pointing at the last URL we actually got data from. `via_https` derived from the same source.
- **Wappalyzer array-form patterns now compile every alternative.** Header / cookie / meta fingerprints supplied as a JSON array (`{"X-Powered-By": ["pattern1", "pattern2"]}`) were silently dropping everything past `[0]`. Now iterates the full array. The embedded fingerprint set has ~hundreds of array-form entries — this restores detection coverage that had been quietly degraded.
- **`--rate-limit` honors fractional rps.** Previously any positive value rounded to integer rps, so `--rate-limit 0.1` (one request every 10 s) silently became 1 rps — 10× the user's intended throughput. Now uses `governor::Quota::with_period` for sub-1 values; smoke test confirms 4 probes at `--rate-limit 0.5` paces at exactly 0.5 rps (~6 s elapsed, was ~3 s).
- **`extract_host` strips `?` and `#`.** URLs like `https://foo.com?x=1` used to resolve DNS as the literal `foo.com?x=1`, silently dropping the host from the scan. Resume-skip dedup keys also stayed broken across runs. Now matches the `bare_host` helper in fuzz mode.
- **Fuzz JSONL write failures surface to stderr (once).** A disk-full or broken-pipe during a long fuzz run used to silently drop records — the user saw "[fuzz done: N probes…]" thinking everything persisted. A one-shot `WRITE_ERR_LOGGED` guard now logs the first failure and stays quiet thereafter.
- **Wildcard fingerprint map no longer collides across path-prefixes.** Two inputs that shared a hostname but differed in path-prefix (`https://target.com/api` and `https://target.com/admin`) hashed to the same bare-host key; the second pre-flight overwrote the first and the wrong fingerprint was used for half the probes. Now keyed by full `host_to_input` string.
- **Pre-release tags no longer rank above releases in `httpxer -c`.** A tag like `v1.2.3-rc.1` was getting parsed as `[1,2,3,1]` and compared greater than `[1,2,3]`, so `--check-update` would falsely advertise a pre-release as the latest installable version. Pre-release tags (anything containing `-`) are now skipped by the tag-API peek.
- **`non_standard_port` scheme-flip works on URLs with `:` in the path.** The previous `rsplit_once(':')` heuristic mistook a `:` inside the path for the port (e.g. `https://host:8080/a:80/b` parsed port as `80`, said "standard", skipped the flip). Now uses `url::Url::parse().port_or_known_default()`.
- **Wildcard signatures now match the fuzz probes that follow them.** Pre-flight picked a random TLS profile and the actual fuzz probes picked different ones per request, so on UA-varying servers the `(content_length, snippet_md5)` triples diverged and wildcard suppression silently failed. New `probe::pick_pool_slot_for(host_key)` hashes the host to one fixed pool slot — pre-flight and probes against the same host now use the same browser profile. Across distinct hosts the picker still spreads load.
- **Panicked / cancelled probe tasks now log to stderr.** Previously the `if let Ok(rec) = joined` branch in the enrich drainer silently swallowed `JoinError`, so a regex blowup in tech-detect would just make hosts disappear from the output. Now matches both arms.

### Added
- 8 new regression tests covering each fix: `extract_host_strips_path_query_fragment`, `array_form_header_patterns_compile_every_entry`, `host_rate_limiter_supports_fractional_rps`, `map_keys_dont_collide_across_path_prefixes`, `resolve_redirect_url_{absolute,root_relative,relative}`, `extract_title_basic`.

### Changed
- Version: 0.3.4 → **0.3.5**
- Removed dead `pick_pool_slot` public API (superseded by `pick_pool_slot_for`); removed unused `ua_echo` workaround in `fuzz::dispatch_one`.

### Unchanged (compatibility)
- Default enrich and fuzz JSONL shapes are byte-compatible with v0.3.4. The only field-level change is that `final_url` and `tech` now reflect what was actually observed (a strictly improved signal, not a schema change).
- All v0.3.4 CLI flags continue to work unchanged — `--rate-limit` accepts the same float values, sub-1 ones just now mean what they say.

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
