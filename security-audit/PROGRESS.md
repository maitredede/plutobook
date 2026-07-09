# PROGRESS — PlutoBook security fixes

Progress log. **Resuming**: read this file + `git log --oneline`, resume at the first unchecked
finding. One commit per finding (see `FIX-GUIDE.md`).

- Branch: `security-audit`
- Fix agent: **Claude Code Sonnet 5**
- Order: decreasing criticality (V01 → V16)

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

**16/16 fixed.** Clean rebuild from scratch OK; PoC suite replayed against the integrated state
(everything bounded/rejected, no crash/hang/OOM).

## Follow-up — issues discovered while fixing (outside the scope of the 16)

Found while verifying the fixes; **not fixed** (distinct from the 16 findings), to be addressed
separately:

- **Deeply nested table layout**: exponential intrinsic-width computation time beyond ~80-100
  levels (pre-existing, independent of V08). Residual CPU DoS under the depth cap. (found during
  V08)
- **`Heap::concatenateString` O(n²)** (`source/heapstring.h`): `TextNode::appendData` recopies the
  whole accumulated string on every character-data callback, onto the monotonic PMR arena that's
  never freed → a deep XML entity bomb can trigger `std::bad_alloc` before expat's protection kicks
  in. (V16)
- **Superlinear multicolumn balancing** in content size, even at a legitimate `column-count`.
  Performance issue, distinct from V12. (V12)
- **Cairo 1.18.4 PDF writer**: corrupted xref/trailer beyond ~65536 pages (Cairo bug, no crash).
  The `maxPageCount=100000` default exceeds this threshold → consider a default ≤ 65536. (V09)
- **memcpy on a null `data()`** in `Heap::createString` (`heapstring.h:72`) for an empty
  `string_view`, reachable via `content: "\` + EOF (UB). (found during V15; the neighboring
  `std::abs(INT_MIN)` case was fixed in the V13 commit)

## Notes

- The first commit (the report) checks nothing off: every status is "to fix".
- Fixes made by a **Claude Code Sonnet 5** agent, one commit per finding, build+PoC verified.
- The HTML report's status is driven by `status`/`FIXCOMMITS` in `security-audit/tools/genreport.py`.
