# Fix implementation guide — PlutoBook (for Claude Code Sonnet 5)

> **Audience**: the **Sonnet 5** Claude Code agent. This document is the single reference for
> implementing the security audit fixes. The detailed report (nature/risk/repro of each finding)
> is in `security-audit/index.html` and the `Vxx-*/` folders.

## Mission

Fix the 16 security findings **in decreasing order of criticality** (V01 first), **one commit per
finding**. Every limit or bound added must have a **sensible default** AND be **configurable**.
Dangerous protocols must be **re-enablable via configuration**. A **URL validator hook** must allow
filtering any URL before download (default curl fetcher OR custom handler).

## Repo context

- C++ library rendering HTML/XML/CSS/SVG → PDF/Bitmap. Build system: **meson**.
- Working branch: **`security-audit`** (already created; do not work on `main`).
- Threat model: **untrusted input** (server-side rendering of arbitrary HTML/SVG/CSS).
- Public API: `include/plutobook.hpp` (C++) and `include/plutobook.h` (C).
- Default fetcher: `DefaultResourceFetcher` class in `include/plutobook.hpp` (pattern: public
  setters + private members with a default value); implementation in
  `source/resource/resource.cpp`.

## MANDATORY workflow per finding (repeat V01 → V16)

1. Read the finding's page (`security-audit/Vxx-*/index.html`) and the section below.
2. Implement the fix in `source/…` (+ `include/…` API if a knob is added).
3. **Verify**: build + replay the PoC from `security-audit/Vxx-*/poc/` (the dangerous behavior
   must be blocked/bounded; legitimate rendering must stay unchanged). See "Build & verification".
4. Mark the finding as resolved in the **report**: edit `security-audit/tools/genreport.py`, flip
   the relevant finding's `status="todo"` to `status="done"` (and fill in
   `fixcommit="<short hash>"` if known — otherwise leave it empty, the hash will be visible in
   git), then regenerate: `python3 security-audit/tools/genreport.py`.
5. Check off the corresponding row in `security-audit/PROGRESS.md` (status + commit hash).
6. **Single commit** for this finding, including: the code, the regenerated report, PROGRESS.md.

### Commit format

```
sec(Vxx): <short summary of the fix>

<explanation: what was vulnerable, the bound/knob added, the chosen default>

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

Example: `sec(V06): clamp colspan/rowspan/col span (default 1000, configurable)`.

### Resuming after an interruption (quota)

The git history + `PROGRESS.md` are the log. On each start: read `PROGRESS.md` and
`git log --oneline`, resume at the **first non-`done` finding**, never redo a commit that already
exists.

---

## Configuration design (to be put in place, reused by several fixes)

### A. Fetcher knobs (`DefaultResourceFetcher`, `include/plutobook.hpp`)

Add, following the exact pattern of the existing setters (`setFollowRedirects`, `setMaxRedirects`,
`setTimeout`):

| Setter | Member / default | Effect |
|--------|-----------------|-------|
| `setAllowedProtocols(std::string csv)` | `m_allowedProtocols = "http,https,data"` | scheme allowlist; feeds `CURLOPT_PROTOCOLS_STR` + `CURLOPT_REDIR_PROTOCOLS_STR` |
| `setMaxDownloadSize(size_t bytes)` | `m_maxDownloadSize = 32*1024*1024` | cap; `CURLOPT_MAXFILESIZE_LARGE` + hard cap in `writeCallback` |
| `setConnectTimeout(int s)` | `m_connectTimeout = 30` | `CURLOPT_CONNECTTIMEOUT` |
| `setMaxImagePixels(uint64_t px)` | `m_maxImagePixels = 64ULL*1000*1000` | pixel budget before `cairo_image_surface_create` |
| `setMaxFontBytes(size_t bytes)` | `m_maxFontBytes = 8*1024*1024` | font byte cap (V03) |

`file`, `ftp`, `gopher`… are **outside the allowlist by default** → re-enablable via
`setAllowedProtocols`.

### B. URL validator hook (covers both curl AND a custom handler)

Goal: a callback invoked **before any download**, regardless of the fetcher in use.

- C++ type: `using UrlValidator = std::function<bool(std::string_view url)>;` (returning `false` = reject).
- Application point: in `ResourceLoader::loadUrl` (`source/resource/resource.cpp:371`) **before**
  `customFetcher->fetchUrl(...)` — this is the mandatory choke point for both the default fetcher
  AND a custom handler.
- Storage: carry the validator on the context accessible to `loadUrl`. Two acceptable options:
  1. an optional global validator (static setter on `ResourceLoader`/global config), or
  2. pass it through the `Book`/document down to `Document::fetchResource` (`source/document.cpp:1062`).
  Pick whichever option is simplest and consistent with the existing architecture; document the choice.
- Also expose it as a **C API** (`include/plutobook.h`): a function-pointer `typedef`
  `bool (*)(const char* url, void* userdata)` + a setter with `void* userdata`.
- Combine with the allowlist: the scheme is checked first, then the user validator.

### C. Engine limits (parse / layout)

**Done (V06)**: the `EngineLimits` facade now centralizes these engine (parse/layout) limits, as
opposed to the fetcher knobs (section A, specific to network/resource decoding). This is the shared
home for V06-V12: **reuse this class verbatim**, do not create a second mechanism.

- C++ class `plutobook::EngineLimits` (`include/plutobook.hpp`, implementation in
  `source/plutobook.cpp`): one setter/getter pair per limit (e.g. `setMaxTableSpan(uint32_t)` /
  `maxTableSpan() const`), safe default as a member initializer, `0` = unlimited (document
  per-limit if applicable). Private constructor + `friend` singleton accessor, following the exact
  model of `DefaultResourceFetcher` (section A) — **not** a `kMaxImportDepth`-style local,
  non-configurable constant for new limits (`kMaxImportDepth` remains an isolated pre-existing case,
  not reconfigurable, not to be imitated for V07+).
- Global accessor: `plutobook::EngineLimits* plutobook::engineLimits();` (function-local `static`
  singleton, same pattern as `defaultResourceFetcher()`).
- Matching C API (`include/plutobook.h`, implementation in `source/plutobook.cc`): one
  `plutobook_set_<name>(...)` per setter, calling `plutobook::engineLimits()->set<Name>(...)` (see
  `plutobook_set_max_table_span` for the model).
- **To add a limit (V07-V12)**: add a private member + its public setter/getter in `EngineLimits`
  (`plutobook.hpp`), the matching C function in `plutobook.h`/`plutobook.cc`; read the value via
  `engineLimits()->maXxx()` at the enforcement point(s). No other plumbing is required (the
  singleton and its accessor already exist).

| Limit | Proposed default | Concerns | Accessor |
|--------|----------------|----------|-----------|
| max `colspan` / `rowspan` / `col span` | 1000 (HTML spec value) | V06 | `maxTableSpan` — **done** |
| nesting depth (parse/layout/paint/destruction) | 512 | V08 | `maxNestingDepth` — **done** |
| `<use>` expansion budget (instantiated nodes) + depth | 100,000 nodes / depth 512 | V07 | `maxUseExpansion` + `maxUseDepth` — **done** |
| max `column-count` | 1000 | V12 | `maxColumnCount` — **done** |
| max page count | 100,000 | V09 | `maxPageCount` — **done** |
| max counter representation length | 100,000 | V10 | `maxCounterLength` — **done** |

Always: **a default that does not break legitimate rendering**, exposed in C++ and C, and
documented.

---

## Fixes per finding

> Format: location → action → default/knob → verification (folder's PoC).

### V01 — SSRF / multi-scheme fetch — **Critical**
- `source/resource/resource.cpp` `fetchUrl` (~284): before `curl_easy_perform`, set
  `CURLOPT_PROTOCOLS_STR` and `CURLOPT_REDIR_PROTOCOLS_STR` = `m_allowedProtocols`.
- Apply the URL validator (design B) upstream (in `loadUrl`).
- Optional: `CURLOPT_PREREQFUNCTION` to reject internal IPs (loopback/link-local/RFC1918).
- Knob: `setAllowedProtocols` (default `http,https,data`). Verification: `poc/repro.html` +
  `poc/listener.py` → no internal connection, `169.254.169.254`/`gopher` rejected.

### V02 — `file://` file read + traversal — **Critical**

**Trust model to introduce** (key to V02, and fixes a V01 regression): distinguish the
**top-level document** — the URL explicitly supplied by the caller (`Book::loadUrl`, e.g.
`html2pdf ./doc.html`) = **trusted** — from **sub-resources** referenced by the document
(`Document::fetchResource`, e.g. `<img>`, `@import`, `@font-face`) = **untrusted**.

- The default scheme allowlist (`http,https,data`, no `file`) and the internal-IP filter should
  only apply to **sub-resources**. The **top level** keeps the scheme the caller chose (so
  `file://` still works for `html2pdf ./x.html`). Implementation: thread a "top-level / trusted"
  flag through to `ResourceLoader::loadUrl` (or split the code paths between root document loading
  and sub-resource fetching).
- The **URL validator** (V01) is still invoked in **both** cases (so the caller can still enforce
  its own policy even at the top level), but it sees the **resolved** (absolute) URL so it can
  confine access to a root directory.
- Also concerns the non-curl branch (`resource.cpp:331-367`): same treatment.
- **V01 regression to fix here**: `html2pdf file.html` must work again (local input = trusted top
  level) while still rejecting `file://` at the **sub-resource** level by default.
- Verification: (a) `html2pdf security-audit/V02-local-file-read/poc/repro.html out.pdf`: the
  document loads, but the `file:///etc/passwd` stylesheet and the traversal `<img>`
  `../../etc/hostname` (sub-resources) are rejected by default; (b) `html2pdf <a plain local file>`
  works; (c) `setAllowedProtocols(...,"file")` re-enables `file://` for sub-resources.

### V03 — Font bytes → FreeType — **High**
- `source/resource/fontresource.cpp:57`: before `FT_New_Memory_Face`, check size ≤
  `m_maxFontBytes` and plausible magic bytes (`OTTO`, `true`, `ttcf`, `0x00010000`, `wOFF`, `wOF2`).
- Apply the size cap (V04) to font fetches too.
- Knob: `setMaxFontBytes` (default 8 MiB). Verification: `poc/repro.html` + `poc/make-evil-font.py`
  → out-of-format/out-of-size font cleanly rejected.

### V04 — Download size — **High**
- `source/resource/resource.cpp`: `CURLOPT_MAXFILESIZE_LARGE = m_maxDownloadSize`; in
  `writeCallback`, if `response->size() + total > m_maxDownloadSize` → return 0 (curl aborts).
  `writeCallback` must have access to the cap (pass the limit via the `CURLOPT_WRITEDATA` struct).
- Add `CURLOPT_CONNECTTIMEOUT = m_connectTimeout`.
- Knob: `setMaxDownloadSize` (default 32 MiB). Verification: `poc/repro.html` +
  `poc/huge-server.py` → transfer cut off at the cap, no OOM.

### V05 — Image decompression bomb — **High**
- `source/resource/imageresource.cpp`: on all 3 paths (stb `~162`, turbojpeg `~100`, webp `~139`),
  after obtaining width/height (pre-decode: `WebPGetFeatures`, `tjDecompressHeader`, and for stb
  `stbi_info_from_memory`), reject if `(uint64_t)width*height > m_maxImagePixels` **before**
  `cairo_image_surface_create`/full decode.
- Lower `STBI_MAX_DIMENSIONS` (e.g. via `#define` before including `stb_image.h`).
- Knob: `setMaxImagePixels` (default 64 MP). Verification: `poc/make-bomb.py` → `bomb.png` rejected.

### V06 — colspan / col span — **High**
- `source/htmldocument.cpp:858-861` (`colSpan()`) and `:823` (`span()`): clamp to a configurable
  max (default 1000), in addition to the existing min. Model: the `rowSpan` clamp already present
  (`source/layout/tablebox.cpp:1364-1376`).
- Verification: `poc/repro.html` (`colspan=200000000`) → bounded, no OOM.

### V07 — SVG `<use>` expansion — **High**
- `source/svgdocument.cpp:336-406`: add a global counter of nodes instantiated via `<use>`
  (budget) + an expansion depth limit. Stop expanding once exceeded (no further cloning).
- Verification: `poc/make-svg-bomb.py` → `bomb.svg` bounded, no OOM/hang.

### V08 — Unbounded recursion — **High**
- CSS: depth counter in `source/csstokenizer.h` `consumeComponent`/`consumeBlock` (~173), selector
  recursion (`source/cssparser.cpp:740-858`) and at-rules (`:365-373`).
- Tree: nesting limit at parse time (HTML/XML/SVG) covering `finishParsingDocument`
  (`source/document.cpp:267`), `cloneChildren` (`:236`), layout (`source/layout/blockbox.cpp:1541`)
  and destruction (`source/layout/box.cpp:37`).
- Knob: max depth (default 512). Verification: `poc/make-deep.py` → clean rejection, no SIGSEGV.

### V09 — Page count — **Medium+**
- `source/layout/pagebox.cpp:694-723`: bound `pageCount` to a configurable max; guard against
  `UINT32_MAX`/an infinite value **before** the float→`uint32_t` conversion
  (`source/counters.cpp:16`).
- Verification: `poc/repro.html` (`height:1e9px`) → bounded page count.

### V10 — @counter-style pad / additive — **Medium+**
- `source/cssrule.cpp:855-878` (`pad`) and `:766-768` (additive): cap the number of repetitions /
  the representation length (default 100,000).
- Verification: `poc/repro.html` (`pad:2000000000`) → no OOM.

### V11 — stb→cairo stride — **Medium**
- `source/resource/imageresource.cpp:175`: index `imageData` using the **packed** stride
  (`width*4`), not `surfaceStride`. `dst` keeps using `surfaceStride`.
- Pure fix (no knob). Verification: `poc/make-bmp.py` (unaligned width) → no over-read (ASan).

### V12 — column-count — **Medium**
- `source/cssparser.cpp:1479-1486` or at storage time (`source/layout/multicolumnbox.cpp:510`):
  clamp `column-count` to a max (default 1000).
- Verification: `poc/repro.html` (`columns:2000000000`) → no hang.

### V13 — Integer overflow — **Low**
- `source/htmldocument.cpp:224-233`: accumulate with overflow detection + range clamp (instead of
  a bare `output*10+digit`). Same for exponents in `source/csstokenizer.cpp:289`,
  `source/svgproperty.cpp:130`.
- Verification: `poc/repro.html` → huge values bounded, no UB (UBSan).

### V14 — turbojpeg/webp return values — **Low**
- `source/resource/imageresource.cpp:110-123`: check the return value of `tjDecompress2` and the
  `std::malloc` before `memcpy`; free/fail cleanly.
- Verification: malformed/truncated JPEG (see `poc/note.md`) under ASan.

### V15 — Assert-only bounds — **Low (latent)**
- `source/csstokenizer.h:239-286`: make `advance`/`substring`/`consume` safe in release builds
  (clamp `m_offset`, active bounds checks, not just `assert`).
- `source/pointer.h:227-236` (`to<T>()`): consider an active release-mode check on hot box-downcast
  paths. Priority fuzzing target (see `poc/note.md`).

### V16 — expat billion-laughs — **Info**
- `meson.build:8-11`: require `expat >= 2.4.0` (minimum version); otherwise, in
  `source/xmlparser.cpp`, explicitly set
  `XML_SetBillionLaughsAttackProtectionMaximumAmplification`/`…ActivationThreshold`.
- XXE is already unreachable (no external entity handler) — **do not** add one.
- Verification: `poc/lol.xml`.

---

## Build & verification

```bash
# Build (enable the sanitizers if dependencies allow it)
meson setup build -Db_sanitize=address,undefined || meson setup build
meson compile -C build

# Replay a PoC: use the repo's example/CLI that loads an HTML/SVG file and renders a PDF/PNG,
# pointing it at security-audit/Vxx-*/poc/repro.html (or the file produced by the poc script).
# Generate the dynamic PoCs first, e.g.:
python3 security-audit/V05-image-bomb/poc/make-bomb.py     # creates bomb.png
python3 security-audit/V07-svg-use/poc/make-svg-bomb.py    # creates bomb.svg
python3 security-audit/V08-recursion/poc/make-deep.py      # creates deep.html / deep.css.html
```

Criterion: the dangerous behavior is **blocked or bounded** (rejection, clamp, clean error) and
**legitimate document rendering stays unchanged** (replay the repo's existing examples/tests for
non-regression). If sanitizers or a dependency are unavailable in the environment, at least do the
standard build + behavioral verification, and note it in the commit message.
