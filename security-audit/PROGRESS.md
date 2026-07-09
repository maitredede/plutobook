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
| [ ] | V17 | memcpy on null `data()` (empty string) | Low | — |
| [ ] | V18 | maxPageCount default > Cairo PDF limit | Medium | — |
| [ ] | V19 | `Heap::concatenateString` O(n²) | High | — |
| [ ] | V20 | Exponential nested table layout | High | — |
| [ ] | V21 | Superlinear multicolumn balancing | Medium | — |

**V01–V16 fixed** (clean rebuild OK, integrated PoCs verified). **V17–V21** = issues discovered
while fixing, now tracked and to be handled in order: V17 → V18 → V19 → V20 → V21.

## Follow-up finding details (V17–V21)

- **V17** — memcpy on a null `data()` in `Heap::createString` (`heapstring.h:72`) for an empty
  `string_view`, reachable via `content:"\` + EOF (UB). (found during V15; the neighboring
  `std::abs(INT_MIN)` case had already been fixed in the V13 commit)
- **V18** — Cairo 1.18.4 PDF writer: corrupted xref/trailer beyond ~65536 pages (Cairo bug, no
  crash). The `maxPageCount=100000` default (V09) exceeds this threshold → lower the default
  ≤ 65536. (V09)
- **V19** — `Heap::concatenateString` O(n²) (`source/heapstring.h`): `TextNode::appendData`
  recopies the whole accumulated string on every character-data callback, onto the monotonic PMR
  arena that's never freed → a deep XML entity bomb can trigger `std::bad_alloc` before expat's
  protection kicks in. (V16)
- **V20** — Deeply nested table layout: exponential intrinsic-width computation cost beyond
  ~80-100 levels (independent of V08's depth cap). CPU DoS. (V08)
- **V21** — Superlinear multicolumn balancing in content size, even at a legitimate
  `column-count`. Performance/CPU DoS, distinct from V12. (V12)

## Notes

- The first commit (the report) checks nothing off: every status is "to fix".
- Fixes made by a **Claude Code Sonnet 5** agent, one commit per finding, build+PoC verified,
  pushed after every commit.
- The HTML report's status is driven by `status`/`FIXCOMMITS` in `security-audit/tools/genreport.py`.
