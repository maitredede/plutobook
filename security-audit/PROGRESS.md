# PROGRESS — PlutoBook security fixes

Progress log. **Resuming**: read this file + `git log --oneline`, resume at the first unchecked
finding. One commit per finding (see `FIX-GUIDE.md`). **Push after every commit.**

- Branch: `security-audit`
- Fix agent: **Claude Code Sonnet 5**
- Order: V01→V16 (initial audit, decreasing criticality), then V17→V21 (follow-up, requested order)

## Status

| Done | ID | Finding | Severity | Commit |
|:----:|----|----------|----------|--------|
| [x] | V01 | SSRF / multi-scheme fetch | Critical | acb32e3 |
| [x] | V02 | `file://` file read + traversal | Critical | 080c0ea |
| [x] | V03 | Font bytes → FreeType | High | 5009198 |
| [x] | V04 | Download size | High | 98950eb |
| [x] | V05 | Image decompression bomb | High | 2806e2d |
| [x] | V06 | colspan / col span | High | c35e686 |
| [x] | V07 | SVG `<use>` expansion | High | 7897a70 |
| [x] | V08 | Unbounded recursion | High | 583dfcf |
| [x] | V09 | Page count | Medium+ | 99efe35 |
| [x] | V10 | @counter-style pad / additive | Medium+ | 37c94d1 |
| [x] | V11 | stb→cairo stride | Medium | 40ad76d |
| [x] | V12 | column-count | Medium | 9821b38 |
| [x] | V13 | Integer overflow | Low | bb826f2 |
| [x] | V14 | turbojpeg/webp return values | Low | 2945ca0 |
| [x] | V15 | Assert-only bounds (latent) | Low | 086414c |
| [x] | V16 | expat billion-laughs | Info | 371a78a |
| [x] | V17 | memcpy on null `data()` (empty string) | Low | see git log |
| [x] | V18 | maxPageCount default > Cairo PDF limit | Medium | see git log |
| [x] | V19 | `Heap::concatenateString` O(n²) | High | see git log |
| [x] | V20 | Exponential nested table layout | High | see git log |
| [x] | V21 | Superlinear multicolumn balancing | Medium | see git log |
| [x] | V22 | TextShape positionForOffset O(n²) (true cause of V21) | High | see git log |

**V01–V16 fixed** (clean rebuild OK, integrated PoCs verified). **V17–V21** = issues discovered
while fixing. **V22** = discovered while diagnosing V21: the real superlinear cost of the
multicolumn PoC is an O(n²) in text shaping (`textshape.cpp`), which also affects any long
single-column document. V21 bounded balancing (defensive); **V22 fixes the real cause** (binary
search in `TextShapeRun` + the same fix extended to `TextShapeView`'s glyph-scanning methods,
needed in practice to make the PoC fast again — details below).

## Follow-up finding details (V17–V22)

- **V17** — memcpy on a null `data()` in `Heap::createString` (`heapstring.h:72`) for an empty
  `string_view`, reachable via `content:"\` + EOF (UB). (found during V15; the neighboring
  `std::abs(INT_MIN)` case had already been fixed in the V13 commit)
- **V18** — Cairo 1.18.4 PDF writer: beyond 65533 pages in a single PDF surface, the shared object
  stream for the Catalog/Pages/Info objects overflows its 2-byte index field (max 65536 entries) →
  corrupted xref/trailer (Cairo bug, no crash; empirically verified by bisection: 65533 pages =
  valid PDF, 65534 = invalid, reproduced across several document shapes). The `maxPageCount=100000`
  default (V09) exceeded this threshold → default lowered to **65533**. (V09)
- **V19** — `Heap::concatenateString` O(n²) (`source/heapstring.h`): `TextNode::appendData` used
  to recopy the whole accumulated string on every character-data callback, onto the monotonic PMR
  arena that's never freed. Confirmed by binary bisection (stash/rebuild): under a 2-3 GiB
  `ulimit -v`, the XML entity bomb (`poc/make-entity-bomb.py`) and even a **legitimate** ~2.1M
  character document fragmented into ~200,000 callbacks (via repeated `&amp;`) both hit
  `std::bad_alloc` before expat's protection (V16) kicks in. Fixed by accumulating fragments in a
  plain `std::string` (normal heap, geometric growth, freed on each reallocation) and only
  materializing into the arena once, on first read (`TextNode::data()`) — O(n) cost instead of
  O(n²), identical text (verified byte-for-byte via `pdftotext`). Additional defense in depth:
  `EngineLimits::maxTextNodeLength` (default 100,000,000 characters, configurable). (V16)
- **V20** — Deeply nested table layout: exponential cost confirmed by call counting
  (2^(N+1)-2 cell layouts for N levels), independent of V08's depth cap (512). Diagnosis: **not**
  the preferred-width computation (already cached per box, O(N) cost measured); the doubling comes
  from CSS's two-pass-per-table layout (natural-height measurement pass, then a stretch pass to the
  row height), each pass fully re-laying-out any table nested inside it. Memoizing a full layout
  (positions/overflow/fragmentation) would have been far more invasive than a width computation —
  the chosen fallback (documented as an acceptable alternative in the V20 folder): new
  `EngineLimits::maxTableNestingDepth` limit (default **8**, configurable, 0 = unlimited); beyond
  it, `TableSectionBox::layoutRows()` skips the stretch pass for that table's cells (same
  content/width/position, just not stretched against a taller sibling cell — cosmetic only, past
  the limit). The default must stay low because the cost is
  O(2^limit &times; total_depth), not just O(2^limit): a default around 100 (a priori reasonable by
  analogy with the other limits) would remain exponential and insufficient — verified empirically.
  Verified: scaling is now linear (0.19/0.63/0.89/0.98s for 50/100/150/200 levels, vs. a hang/timeout
  pre-fix around N≈20-25); the 150-level PoC → ~0.92s (pre-fix: timeout >20s); non-regression via
  **byte-for-byte PDF comparison** (pre-fix binary via `git stash` + separate build, vs. post-fix)
  on a simple grid/colspan-rowspan/2-level nesting/%-fixed-auto widths/caption (all identical) and
  on real nesting up to exactly the limit (depth 8 included, identical); it only differs beyond the
  limit (depth 9+, and only when a row has cells of different natural heights). (V08)
- **V21** — Superlinear multicolumn balancing in content size, even at a legitimate
  `column-count`. Diagnosis **corrected** by instrumentation (per-line/per-pass timing): the
  balancing loop (`MultiColumnFlowBox::layoutContents()`) is **not** the culprit — the initial
  estimate (`distributeImplicitBreaks()`) is exactly `totalHeight / columnCount` when there is no
  explicit column break (verified both algebraically and across many adversarial content shapes):
  it consistently converges in 1-2 iterations, regardless of content size. The real superlinear
  cost (per-line timing: ~4-5x more expensive late in a document than early) comes from
  `TextShapeRun::positionForOffset()`/`offsetForPosition()` (`source/graphics/textshape.cpp`,
  outside this file): these functions rescan the glyph array from index 0 on every call instead of
  resuming from a cached position — reproduces identically on plain text with no columns involved.
  Out of scope for this fix (different file, wide blast radius across all text layout) —
  **flagged as a separate follow-up** for a future audit entry. Fix shipped here (documented
  fallback): new `EngineLimits::maxColumnBalancingIterations` limit (default **10**, configurable,
  0 = unlimited) bounding the number of balancing relayout passes, to guarantee termination even if
  some future content shape defeated the initial estimate (exact in practice today, but not proven
  for every adversarial input). Verified: non-regression via **byte-for-byte** PDF comparison
  (pre-fix binary via `git stash` + separate build) on 2/3-column documents, `column-gap`,
  `column-span:all` (identical); the default (10) is byte-identical to unlimited (0) on the PoC and
  on a document with many spanners; a deliberately low cap (1, dedicated C harness) does trigger a
  measurable early stop (different PDF) while still producing complete, valid output (no content
  lost). Caveat: this fix does **not** make the literal PoC render in linear time — the dominant
  cause is out of scope (see above). (V12)
- **V22** — Root cause of V21: `TextShapeRun::positionForOffset()`/`offsetForPosition()` used to
  rescan the glyph array from index 0 on every call; line layout calls them once per line, so a
  long run became O(n²). Fixed with a binary search (`glyphIndexForOffset()`, new) on
  `characterIndex` (monotonic by HarfBuzz construction, ascending in LTR / descending in RTL,
  regardless of advance sign) + a cumulative advance sum (`advanceUpTo`) precomputed once when the
  run is created, making both functions O(log n) instead of O(n). `offsetForPosition` searches on
  the cumulative sum itself, which is only monotonic if every advance is ≥ 0 (the normal case); a
  sufficiently strong negative `letter-spacing`/`word-spacing` can make an advance negative — in
  that case (rare, detected once per run at creation), the function falls back to the original
  linear scan **verbatim**, to never risk a different result for a case that isn't proven
  monotonic.
  **Diagnosis refined during implementation**: this fix alone wasn't enough — measured empirically
  (5000/10000/20000/40000 words: 0.8s/2.9s/11.4s/42s, still quadratic after the binary search
  alone). Instrumentation via iteration counters: the dominant chunk was actually in
  `TextShapeView::width()`, `maxAscentAndDescent()`, `draw()`, and `expansionOpportunityCount()` —
  same pattern (walk every run of the shape from glyph 0 on every call, including runs entirely
  outside the current view, which they scan for zero effect). Fixed with the same technique via a
  new `rangeForView()` function: skip a run entirely out of range in O(1) (stopping the outer loop
  as soon as the remaining runs are necessarily out of range too, since run order is ascending in
  LTR / descending in RTL) and binary-search the first relevant glyph in the run overlapping the
  view. Special case for `draw()`, which has a visible per-run side effect (cairo calls): unlike
  the other three (pure, no effect for a skipped run), its outer loop still visits every run in the
  same order and issues the same cairo calls for each — only the glyph scan itself is
  shortened/skipped, leaving `numGlyphs` at 0 exactly as the original scan would for such a run.
  Verified: near-linear scaling once all 4 methods were fixed (200k words: 40s+ timeout → 1.4s; 2x
  → 3.7s; 4x → 11.0s — mildly superlinear beyond textshape.cpp itself, confirmed by iteration
  counters that the fixed functions scale perfectly linearly with document size; the residual comes
  from elsewhere in the pipeline, out of scope); V21's PoC (`make-multicol.py`) 60s timeout pre-fix
  → 0.24s post-fix; **non-regression by byte-for-byte comparison** (pre-fix binary via `git stash` +
  separate meson build) on 14 documents covering plain LTR multi-paragraph text, justified text,
  mixed fonts/styles, ligatures, negative `letter-spacing` (fallback path included), Arabic RTL,
  Hebrew RTL, mixed bidi text, tabs, edge cases, SVG text (`draw()` outside linelayout.cpp), and
  reduced longtext/V21 PoCs — all byte-identical (PDF, plus PNG on 6 of these documents). (V21)

## Notes

- The first commit (the report) checks nothing off: every status is "to fix".
- Fixes made by a **Claude Code Sonnet 5** agent, one commit per finding, build+PoC verified,
  pushed after every commit.
- The HTML report's status is driven by `status`/`FIXCOMMITS` in `security-audit/tools/genreport.py`.
