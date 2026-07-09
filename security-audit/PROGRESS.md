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
| [x] | V07 | SVG `<use>` expansion | High | see `git log` |
| [ ] | V08 | Unbounded recursion | High | — |
| [ ] | V09 | Page count | Medium+ | — |
| [ ] | V10 | @counter-style pad / additive | Medium+ | — |
| [ ] | V11 | stb→cairo stride | Medium | — |
| [ ] | V12 | column-count | Medium | — |
| [ ] | V13 | Integer overflow | Low | — |
| [ ] | V14 | turbojpeg/webp return values | Low | — |
| [ ] | V15 | Assert-only bounds (latent) | Low | — |
| [ ] | V16 | expat billion-laughs | Info | — |

## Notes

- (The initial report commit checks nothing off: every status is "to fix".)
- For each fix: check the box, fill in the hash, flip `status="done"` in
  `security-audit/tools/genreport.py`, and regenerate.
