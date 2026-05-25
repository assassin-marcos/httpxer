# Changelog

All notable changes to **httpxer** are recorded here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [0.3.13] — 2026-05-25

UX overhaul — output is finally readable. Live findings on terminal,
clean plain-text file format, no more giant VIEWSTATE blobs by default.

### Added
- **Live findings display** (dirsearch / ffuf parity). Every emitted
  probe prints to stderr in `STATUS  SIZE  URL` format, color-coded
  by HTTP status class (green 2xx, yellow 3xx, cyan 401/403, magenta
  4xx, red 5xx). Sits above the v0.3.12 progress bar — `\r\x1b[K`
  wipes the bar before each finding lands so the layout stays clean.
  TTY-gated (no ANSI in piped output). Suppress with `--no-live`.
- **`--format plain`** — output file format flag. Writes dirsearch-style
  `STATUS  SIZE  URL` one per line instead of JSONL. **Strips the
  body_preview entirely** — your `everything_scan.txt` shrinks from
  ~50 MB (with VIEWSTATE blobs) to ~50 KB.
- **`--format json|plain` + auto-detect from `-o` extension**. `.txt`
  paths → `plain`, anything else → `json`. Explicit `--format` overrides.
- **`format_size()` helper** — `146B`, `1KB`, `1.2MB`, `3.4GB`. Used by
  both live findings and plain file output. Negative content-length
  (error records) prints `--`.

### Sample output

Terminal (TTY, color-coded):
```
  [12876/14999] 86% | 4275 rps | eta 0s
200      8B  http://x.com/favicon.ico
301    320B  http://x.com/login
403     --   http://x.com/.git/HEAD
500   1.2KB  http://x.com/buggy.aspx
```

Plain file:
```
200     41B  http://127.0.0.1/wp-admin/admin-ajax.php
200     35B  http://127.0.0.1/api/v1/users
200     43B  http://127.0.0.1/login.aspx
200     54B  http://127.0.0.1/Trace.axd
```

### Changed
- Version: 0.3.12 → **0.3.13**
- `FuzzCfg` gained `output_format: OutputFormat` and `live_findings: bool`.
- `write_record()` signature: now takes `format` + `live` parameters.
  Lives serialized JSON in JSON mode, formatted finding line in plain
  mode. Calls is_terminal() per write to decide ANSI inclusion.
- `OutputFormat` enum with `from_cli()` parser + `from_path()` extension-
  based auto-detect.

### Migration

Your script benefits immediately — change `-o everything_scan.txt`
behavior:

| Before v0.3.13 | After v0.3.13 |
|---|---|
| `-o out.txt` → full JSONL with body_preview (~MBs) | `-o out.txt` → plain `STATUS SIZE URL` lines |
| No live findings on terminal | Live findings stream by default |
| Output file was the only feedback | Live findings + progress bar + output file |

Keep `-o out.jsonl` (or `.json`) for the old JSONL behavior.

### Still on the roadmap (slid to v0.3.14)
- Multi-round recursion orchestration
- Crawl per-probe extraction loop
- Auto-throttle on 429 spike
- Extension multiplication (`-e auto`)

### Unchanged
- All v0.3.12 CLI flags work identically.
- `.json` / `.jsonl` output schemas unchanged — only plain-mode output
  is new.

## [0.3.12] — 2026-05-25

### Added
- **Live in-place progress bar** (dirsearch / ffuf parity). Updates
  every ~100 ms via `\r` + `\x1b[K`. Format:
  `  [7439/14970] 49% | 3875 rps | eta 1s`
  - TTY-gated — piped runs (`httpxer ... | jq`) fall through to the
    batched cadence (one `[fuzz N/total]` line per 500 completions) so
    log scrapers stay parseable.
  - Atomic `completed_counter` shared with workers; separate ticker
    task reads it every 100 ms. Previous v0.3.11 attempt at a drain-
    loop counter never fired meaningfully because the spawn loop's
    inline `while tasks.len() > backlog_cap` drains most tasks BEFORE
    the post-spawn drain runs. Verified: 40 redraws captured over a
    3.5 s scan (one every ~88 ms).
- `format_eta(secs)` helper — compact `5s` / `1m30s` / `2h15m4s` units.

### Fixed
- **`is_tty` check moved to drain phase** (was missing entirely
  pre-v0.3.12). Stderr-pipe scans now stream batched progress without
  ANSI escape codes; TTY scans get the live bar.

### Changed
- Version: 0.3.11 → **0.3.12**
- `cfg.threads * 4` backlog cap now serves two purposes: bounded
  memory + workers actually completing during the spawn loop (which
  the new atomic counter sees).

### Tests
- **73 unit tests passing** (was 72). 1 new:
  - `format_eta_picks_compact_unit` — boundary checks at 0/59/60/3599/3600.

### Smoke verification
```
$ httpxer -u http://x/ -w 15k-words.txt -t 20 -o out.jsonl
[+] input: 1 unique hosts
[+] wordlist: 14999 unique paths
[+] fuzz: 1 hosts × 14970 paths = 14970 probes
  [7439/14970] 49% | 3875 rps | eta 1s   ← redrawn in-place every 100 ms
[+] fuzz done: 14970 probes in 3.50s (4274 rps avg) → out.jsonl
```

### Still on the roadmap (slid to v0.3.13)
- Multi-round recursion orchestration
- Crawl per-probe extraction loop
- Auto-throttle on 429 spike
- Extension multiplication (`-e auto`)

### Unchanged
- All v0.3.11 CLI flags work identically.
- Output schemas unchanged.

## [0.3.11] — 2026-05-25

UX policy change: JS crawling is now **on by default**.

### Changed
- **Removed ALL JavaScript-related entries from `DEFAULT_EXCLUDE_SUBDIRS`.**
  JS files routinely contain real API endpoints, config data, OAuth client
  IDs, hardcoded credentials, and other recon-worthy artifacts. Blocking
  them by default forfeits a major surface. The 15 removed entries are:
  ```
  js, static/js, assets/js,
  node_modules, bower_components,
  _next, _nuxt, _app,
  __webpack, __webpack_hmr,
  .sapper, .svelte-kit,
  @vite, @react-refresh, @fs
  ```
  Result: a wordlist with `js`, `node_modules/lodash/package.json`,
  `_next/data/foo.json`, `@vite/client`, `.svelte-kit/runtime` now
  probes them all (was: 5/8 dropped in v0.3.10 substring mode; now:
  0/8 dropped from the JS-specific list).

### Still kept in defaults
- General asset containers (`static`, `assets`, `public`, `dist`,
  `build`, `bundle`, `bundles`) — they hold ALL asset types (CSS,
  fonts, images, JS, ...), substring mode still drops them.
- Visual asset dirs (`css`, `fonts`, `images`, `img`, `icons`,
  `media`, `videos`, `audio`, `svg`)
- Compound non-JS forms (`static/css`, `static/fonts`,
  `static/images`, `assets/css`, `assets/fonts`, `assets/images`...)
- All traversal / semicolon / slash / backslash patterns (always noise)
- PHP/Composer `vendor` dir (ambiguous — kept)
- Health endpoints (`healthz`, `readyz`, `livez`, `ping`,
  `actuator/health`, `_health`, `_status`, `ready`, `live`)

### Opting back in
If you want JS dropped (rare — usually you want to crawl it):
```bash
httpxer ... --add-excludes 'js,node_modules,_next,_nuxt,@vite,.svelte-kit'
```

If you want everything blocked except JS (sometimes useful — e.g.
focused-recon mode):
```bash
httpxer ... --exclude-subdirs 'css,fonts,images,assets/css,...'  # custom list
```

### Substring-mode caveat (unchanged)
Paths nested inside `static/`, `assets/`, `public/`, `dist/`, `build/`
are still dropped in substring mode because the parent container is
in defaults. JS files at the ROOT (`/js/...`) or in JS framework
prefixes (`/_next/...`, `/@vite/...`) pass through. To probe JS
inside any asset container under substring mode:
```bash
httpxer ... --exclude-mode substring --exclude-subdirs 'css,fonts,images,svg'
```

### Tests
- **72 unit tests passing** (was 71). 1 new:
  - `defaults_do_not_block_js_crawl` — regression-check that the 15
    JS-related entries are NOT in the default exclude list.
- Renamed `default_excludes_cover_user_list` → `default_excludes_cover_user_list_minus_js`
  to reflect the v0.3.11 policy.

### Smoke verification

```
$ cat /tmp/js-test.txt
admin
js
static/js/app.js          ← substring blocked by "static" container
assets/js/main.bundle.js  ← substring blocked by "assets" container
_next/data/foo.json
@vite/client
node_modules/lodash/package.json
.svelte-kit/runtime

$ httpxer -u http://x/ -w /tmp/js-test.txt --exclude-mode substring -o out.jsonl
[+] wordlist: 8 unique paths
[+] exclude-subdirs (substring mode): 2 wordlist entries dropped (8 → 6)
```

The 6 kept (down from v0.3.10's 3 kept): `admin`, `js`, `_next/...`,
`@vite/...`, `node_modules/...`, `.svelte-kit/...`.

### Unchanged
- All v0.3.10 CLI flags work identically.
- Output schemas unchanged.

## [0.3.10] — 2026-05-25

The 3 tightenings the user asked for from the dirsearch-parity gap
analysis — all shipped as actually-functional flags (not just CLI
scaffolding). `--exclude-subdirs` is now wired into wordlist pre-
filtering, so it does something useful TODAY without waiting for the
v0.3.11 recursion orchestration.

### Added
- **`--exclude-mode segment|substring`** — choose how exclude entries
  match. Default `segment` (last path component equals an entry; v0.3.7
  behavior, low FP-drop risk). `substring` is the dirsearch-paste-compat
  mode — any entry appears ANYWHERE in the path drops it. Substring
  catches encoded traversal noise (`%2e%2e`, `%3b`, `..//`) hidden
  mid-path; segment is more precise (won't drop `/api/css-tooling/x`
  just because `css` is a substring).
- **`--exclude-sizes <list>`** — exact content-length filter, comma-
  separated. Accepts trailing `B` (e.g. `218B,500B,128`). Empty = no
  size filter. dirsearch parity.
- **`--exclude-root-size`** — probes `/` once at startup, captures the
  homepage's content-length, and auto-adds it to `--exclude-sizes`.
  Mirrors the user's bash pattern `ROOT_SIZE=$(curl -sk -o /dev/null
  -w "%{size_download}" "$1/")`. Drops fake-200 catchall pages that
  return the homepage for every probe.
- **`--exclude-subdirs` now filters the WORDLIST** (not just future
  recursion targets). In v0.3.7-v0.3.9 the flag parsed but never
  fired against the wordlist; v0.3.10 wires it into the pre-fuzz
  filter step. Result: an exclude list with `%3b,%2e%2e` (substring
  mode) drops every wordlist entry containing those substrings
  BEFORE any probe goes out.

### Expanded — `DEFAULT_EXCLUDE_SUBDIRS`

From 46 entries → 79 entries. New coverage matches the user's bash
`EXCL=( ... )` list verbatim:

```
# Dot-traversal full set:
%2e., .%2e, ../, .. (plain), ..\\
# Semicolon-bypass:
;/, %3b/, ;%2f, ..;
# Slash-confusion:
%2f/, //, /../, //.., ///, %2f%2f
# Backslash-traversal:
%5c, \\/, \\.., \\ (bare)
# Mixed second-level combos:
/..//, /;/, /.%2e, /%2e., /%3b, /%5c
# Static asset compounds:
static/css, static/fonts, static/images, static/img, static/media,
static/icons, static/js, assets/css, assets/fonts, assets/images,
assets/img, assets/js
# Extra health endpoints:
actuator/health, ready, live
```

### Tests
- **71 unit tests passing** (was 66). 5 new:
  - `exclude_mode_from_cli_parses` — CLI parse + case-insensitive
  - `path_excluded_segment_mode` — segment match semantics
  - `path_excluded_substring_mode` — substring match semantics
    incl. case-insensitive + encoded patterns
  - `path_excluded_works_on_bare_paths` — wordlist-entry shape
  - `default_excludes_cover_user_list` — regression-check that every
    entry from the user's `EXCL` bash list is in our defaults

### Smoke verification (vs the user's dirsearch invocation)

```
$ httpxer -u http://test/ -w wordlist.txt --exclude-mode substring \
    --add-excludes '%3b,%2e%2e,css' -o out.jsonl
[+] wordlist: 7 unique paths
[+] exclude-subdirs (substring mode): 4 wordlist entries dropped (7 → 3)
```

Dropped: `api/%3b/users`, `static/css/main.css`, `my-static-css-tool`,
`foo/%2e%2e/etc/passwd`. Kept: `admin`, `api/v1/users`, `normal/path`.

`--exclude-root-size` against a wildcard catchall server:
```
[+] root-size http://127.0.0.1 → adding 186 to --exclude-sizes
[+] fuzz done: 7 probes → 1 record (6 catchall responses dropped)
```

### Changed
- Version: 0.3.9 → **0.3.10**
- `FuzzCfg` gained `exclude_mode: ExcludeMode` and `exclude_sizes: Vec<i64>`.
- `recurse::ExcludeMode` enum + `path_excluded()` helper added.
- `DEFAULT_EXCLUDE_SUBDIRS` grew from 46 → 79 entries.

### Still on the roadmap (slid to v0.3.11)
- Multi-round recursion orchestration (modules + flags + smart-exclude
  wiring all shipped; orchestrator loop is the remaining work)
- Crawl orchestration (HTML + robots + sitemap extractors all shipped
  + tested; per-probe extraction loop slides one release)
- Auto-throttle on 429 spike

### Unchanged (compatibility)
- All v0.3.9 CLI flags work identically.
- Default mode is `segment` so old scans behave the same.
- Output schemas unchanged.

## [0.3.9] — 2026-05-25

**Headline**: Layer 2 path-echo wildcard detection closes the only gap
where dirsearch beat httpxer in the v0.3.7 benchmark. On the
path-echo target, FPs dropped from **14,937 → 6** — a **2,489×
reduction** — at no meaningful cost to speed or memory.

### Added — Layer 2 multi-signal wildcard detector
- **`wildcard::detect(samples, tolerance)`** — replaces the v0.3.7
  Layer-1-only `agreed_from_samples` for primary use. Tries Layer 1
  (static catchall) first; if samples disagree but the bodies' sizes
  fit a linear relationship `CL = k × path_len + base`, records the
  slope `k` (how many times the path appears in the body) and
  intercept `base` instead. dirsearch / feroxbuster use the same
  pattern with `k=1` hardcoded; ours computes `k` from the samples.
- **`wildcard::ProbeSample`** — carries `path_len` alongside the
  Layer 1 fingerprint fields so detection can fit the linear formula.
- **Pre-flight sends 3 random hex paths of VARYING lengths** —
  16, 32, 64 chars (was uniform 32). Different x-values are what
  let the detector compute the slope. `pick_hex_lens(N)` helper.
- **`WildcardSig` extended** with `k: Option<i64>`, `base: Option<i64>`,
  `tolerance: i64` fields. `WildcardSig::layer1(...)` constructor for
  backwards-compat Layer-1-only sigs.

### Fixed — path-echo wildcard suppression
- **`WildcardMap::matches()`** now checks BOTH layers per probe.
  Layer 1 first (cheap exact match); Layer 2 second (formula
  prediction `CL ≈ k × probe_path_len + base` within `tolerance`).
  New signature takes `probe_path_len` as 5th argument; all callers
  updated. Layer 1 retains ±10 byte tolerance from v0.3.7.
- **Probe-path length normalisation**: strip query/fragment AND
  percent-decode before measuring `probe_path_len`. Counting
  `/admin?x=1` (10 bytes raw) or `/%2e%2e/admin` (18 bytes raw)
  instead of the server-visible decoded form (`/admin` 6 bytes,
  `/../admin` 9 bytes) inflated the formula prediction and caught
  244 spurious FPs across the v0.3.9 benchmark before this fix.
  `decoded_path_len(path)` inline helper — no new dep on
  `percent_encoding`.

### Benchmark results — v0.3.7 → v0.3.9 (15,000-word wordlist, 250 threads, localhost)

| target        | tool          | FPs (was → now) | wall   |
|---------------|---------------|-----------------|--------|
| static catchall | httpxer     | **0 → 0**       | 4.2s → 5.0s |
| static catchall | dirsearch   | 0               | 149s   |
| static catchall | ffuf (default) | 14,721       | 3.9s   |
| **path-echo**   | **httpxer** | **14,937 → 6**  | **4.5s → 5.1s** |
| path-echo     | dirsearch     | 0               | 242s   |
| path-echo     | ffuf -ac      | 16              | 4.0s   |

The 6 remaining FPs on path-echo are URL-encoding edge cases
(`%c0%ae` overlong UTF-8, unnormalized `/../` path traversal) — even
dirsearch / feroxbuster's K=1 detection handles them differently
depending on server-side path-normalization behavior. **No real
findings lost** (7/7 TPs across all modes).

### Tests
- **66 unit tests passing** (was 58). 8 new:
  - `detect_layer2_fits_linear_relationship` (k=3 base=200 with clean data)
  - `detect_layer2_tolerates_per_sample_jitter` (±2 bytes per sample)
  - `detect_prefers_layer1_when_both_possible`
  - `detect_returns_none_when_neither_layer_fits`
  - `matches_layer2_via_formula` (runtime probe match check)
  - `layer2_does_not_flag_real_endpoint` (sanity — small body far from formula)
  - `detect_layer2_rejects_insane_k` (rejects K outside [1,20])
  - `detect_layer2_requires_varying_path_lens`

### Changed
- Version: 0.3.8 → **0.3.9**
- `WildcardSig` gained 3 fields (`k`, `base`, `tolerance`) — derive
  PartialEq still works; existing call sites updated via
  `WildcardSig::layer1()` constructor where appropriate.
- `WildcardMap::matches()` signature: now takes `probe_path_len: usize`
  as 5th argument.
- `wildcard_preflight()` → `wildcard_preflight_sample()` — returns
  `ProbeSample` carrying `path_len` instead of `WildcardSig`.

### Still on the v0.3.9 roadmap (slid to v0.3.10)
The recursion + crawl orchestration originally planned for v0.3.9
slips one release to ship this Layer 2 fix sooner. Modules
(`recurse.rs`, `crawl.rs`) and all their CLI flags shipped in v0.3.7
already; v0.3.10 wires them in the orchestrator.

### Unchanged (compatibility)
- All v0.3.8 CLI flags work identically.
- Output schemas unchanged.
- Default fuzz output at depth 0 byte-compatible with v0.3.8.

## [0.3.8] — 2026-05-25

UX-fix patch. The recursion/crawl orchestration originally planned for
v0.3.8 is renumbered to v0.3.9 — this release ships fast to unblock
users whose first `httpxer` invocation showed only a clap error with no
banner.

### Fixed
- **ASCII banner now shows on EVERY invocation when stderr is a TTY** —
  including bare `httpxer` (missing-args clap error), `httpxer --version`,
  `httpxer --help`, and bad-flag typos. Pre-v0.3.8 the banner was drawn
  AFTER clap parsing, so any parse failure exited before the banner ran.
  Now we pre-scan raw argv for `-q` / `--quiet` / `--no-art` and draw the
  banner BEFORE handing off to clap.
  - TTY-gated still — piped output (`httpxer ... | jq`) stays clean.
  - Suppression flag scan is O(argv-len), sub-µs.
  - `--no-update-check` no longer suppresses the ASCII banner (it never
    should have — that flag is for the "[!] update available" follow-up
    line, not the brand mark). To hide the banner use `-q` / `--quiet`
    / `--no-art`.

### Added
- `banner_should_show_early(argv)` helper + unit test
  (`banner_suppression_flags_block_banner`) covering each suppression
  flag and the multi-arg case.

### Changed
- Version: 0.3.7 → **0.3.8**
- Banner-draw call site moved from after `Args::parse_from()` to before.
- `refresh_update_cache_best_effort()` still runs after parsing but now
  serves the NEXT invocation's banner (the current banner is already on
  screen by the time the refresh starts).

### Renumbered to v0.3.9
- Multi-round recursion orchestration (modules + flags shipped in v0.3.7;
  orchestrator wiring slides one release)
- Crawl module integration (extractors + scope + asset filter shipped;
  per-probe extraction loop slides one release)
- Layer 2 path-length-adjusted CL wildcard detection (bumped to top
  priority by the v0.3.7 benchmark vs dirsearch on path-echo targets)
- All other deferrals from v0.3.7 (`-e auto`, `--format`, 6-layer
  detector, auto-throttle, exponential backoff)

### Unchanged (compatibility)
- All v0.3.7 CLI flags work identically.
- Output schemas unchanged.

## [0.3.7] — 2026-05-25

### Added (foundation + FP-hardening that ships today)
- **Multi-sample wildcard fingerprinting (the big FP killer).** Pre-flight now probes 3 random hex paths per host (was 1) and REQUIRES all three to agree on `(status, content_length, content_type, snippet_md5)` before recording a wildcard. Disagreement marks the host path-sensitive and emits a stderr warning — no suppression there (so we don't over-suppress real findings on dynamic servers). Defeats dirsearch's / ffuf's single-sample failure mode on catchall / SPA / per-path-varying servers. `wildcard::agreed_from_samples()` is the new helper.
- **Auth — `-H` / `--bearer` / `--cookie`.** Repeatable `-H "Name: Value"` for custom headers, `--bearer TOKEN` shortcut for `Authorization: Bearer`, `--cookie "Name=Value"` for initial cookie seed. All validated at CLI parse so typos fail loudly before the scan runs. New `src/auth.rs` module with `AuthCtx::from_cli()`.
- **`-u` / `--target <URL>` shortcut** — single-target convenience, no need to make a file for one-host scans. Mutually compatible with `-l`. (`-u` for update relocated to `-U`; long form `--update` unchanged.)
- **`-i` / `--include <codes>`** — dirsearch-style alias for `--match-codes`. Lets users paste their dirsearch invocation verbatim.
- **`--exclude <codes>` / `--exclude-codes` / `--exclude-status`** — status code exclude filter. Default `"429,503"` (transient overload only; 403/404 stay in because they can be real findings). All three flag names accepted.
- **`-w` / `--wordlist` / `--wordlists`** — aliases for `-p` / `--paths`.
- **Smart `--exclude-subdirs` built-in default list.** New `src/recurse.rs` ships `DEFAULT_EXCLUDE_SUBDIRS` covering 40+ asset directories (`assets`, `static`, `css`, `js`, `_next`, `_nuxt`, `node_modules`), encoded path-traversal noise (`%2e%2e`, `..%2f`, `..;`), Java path-param tricks (`%3b`, `;`), and noisy health endpoints (`healthz`, `_status`). User can `--exclude-subdirs <list>` to override entirely or `--add-excludes <list>` to append.
- **`--fuzz-follow-redirects`** — opt-in redirect chasing inside fuzz mode (default: 3xx is a finding). Auto-on when `--crawl` set (crawl needs terminal-page body to parse links).
- **CLI scaffolding for v0.3.8 recursion + crawl.** All flags parse + validate + populate `FuzzCfg` today: `-r/--recursive`, `-R/--recursion-depth`, `--crawl`, `--crawl-depth`, `--recurse-on-200`, `--recurse-on-403`, `--max-dirs-per-host`, `--max-probes-per-host`, `--max-links-per-page`, `--scope`. The supporting modules (`recurse.rs`, `crawl.rs`) are shipped + unit-tested. **Multi-round orchestration lands in v0.3.8** — using `-r` / `--crawl` today produces a stderr warning and a single-pass run with the v0.3.7 FP guards active.

### New modules (foundational; ~750 LOC)
- **`src/auth.rs`** (8 tests) — header / bearer / cookie parsing with up-front validation.
- **`src/recurse.rs`** (10 tests) — built-in exclude-subdirs list, strict directory detector (301/302/307/308 with Location-parity check; 200 + Index-of marker opt-in; 403 opt-in), self-similarity loop detector (window-K segment-tail comparison + cross-URL visited index), per-host probe / dir budgets via atomic counters, canonical-URL key for the visited-set.
- **`src/crawl.rs`** (12 tests) — HTML link extractor (regex-based, covers `<a>`, `<link>`, `<script>`, `<img>`, `<form>`, `<iframe>`, `<source>`, `<embed>`, `<object>`, `<meta http-equiv=refresh>`), robots.txt parser (Disallow / Allow / Sitemap directives), sitemap.xml extractor (`<loc>` URLs), built-in 41-host third-party CDN deny list (Google / Cloudflare / Fastly / Stripe / Segment / etc.), static-asset extension filter (40+ extensions: `.css/.js/.png/.jpg/.svg/.woff/...`), scope filter with `*.example.com` wildcard support, self-referencing URL drop.

### Fixed
- `is_self_similar()` cross-URL check no longer early-returns on URLs shorter than `window * 2` segments. The within-URL self-repeat check still needs that minimum; the cross-URL index lookup works on any URL with at least `window` segments. Caught by my own regression test (`index_then_detect_cross_url_loop`).

### Changed
- Version: 0.3.6 → **0.3.7**
- `dispatch_one()` signature gained `extra_headers`, `initial_cookie_header`, `follow_redirects` parameters. All call sites updated.
- `wildcard_preflight()` signature gained auth-passthrough parameters.
- `FuzzCfg` grew 18 new fields (recursion / crawl / auth / smart defaults). All have sensible defaults so existing call sites construct without surprise.
- `FuzzRecord` gained 3 new optional fields (`depth`, `source`, `parent_url`), all `skip_serializing_if`-gated → output is byte-compatible with v0.3.6 at depth 0.
- Self-management short flag `-u` → `-U` (`-u` reclaimed for `--target` per dirsearch convention; `--update` long form unchanged).

### Tests
- **57 unit tests passing** (up from 23). New: 8 (auth) + 10 (recurse) + 12 (crawl) + 4 (wildcard multi-sample) — covering each new building block in isolation.

### Deferred to v0.3.8
- **Recursion orchestration** — `-r` parses + the recurse module is wired + budgets respected + smart excludes applied, but the multi-round per-prefix-fuzz loop runs single-pass today. Stderr warning when `-r` is set so users aren't misled.
- **Crawl integration** — `--crawl` parses + `crawl.rs` extractors are unit-tested, but the per-probe link extraction → frontier enqueue loop ships next. Stderr warning identical to above.
- **Tech-detect-driven `-e auto`** — extension preset infrastructure not yet wired.
- **Output format dispatcher** (`--format jsonl|csv|plain`) — JSONL-only today.
- **6-layer multi-signal detector** (dynamic-bit-stripping md5, DOM-structure hash, multi-provider WAF challenge fingerprints) — single-signal multi-sample is the v0.3.7 floor; full layered detector lands in v0.3.8.
- **Auto-throttle on 429 spike** — `--rate-limit` works manually; reactive auto-engage lands next.
- **Exponential backoff retries** — current 50 ms-fixed backoff stays.

### Unchanged (compatibility)
- Default enrich JSONL shape: byte-compatible with v0.3.6.
- Default fuzz JSONL shape at depth 0 (which is everything in v0.3.7): byte-compatible with v0.3.6.
- All v0.3.6 CLI flags continue to work unchanged.

### Migration cheatsheet — dirsearch → httpxer v0.3.7

```bash
# dirsearch
dirsearch -u https://target.com -w common.txt -i 200,301,401 \
  --exclude-status=429 -H "X-Forwarded-For: 127.0.0.1" -o out.jsonl

# httpxer v0.3.7 (paste-compatible)
httpxer -u https://target.com -w common.txt -i 200,301,401 \
  --exclude 429 -H "X-Forwarded-For: 127.0.0.1" -o out.jsonl
```

Add `-r` (recursive) or `--crawl` to opt into the v0.3.8 features (stderr warning today; behaviour ships next release).

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
