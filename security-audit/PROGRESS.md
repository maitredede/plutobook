# PROGRESS — correctifs de sécurité PlutoBook

Journal de progression. **Reprise** : lire ce fichier + `git log --oneline`, reprendre au premier
problème non coché. Un commit par problème (voir `FIX-GUIDE.md`).

- Branche : `security-audit`
- Agent correctifs : **Claude Code Sonnet 5**
- Ordre : criticité décroissante (V01 → V16)

## État

| Fait | ID | Problème | Sévérité | Commit |
|:----:|----|----------|----------|--------|
| [x] | V01 | SSRF / fetch multi-schéma | Critique | acb32e3 |
| [x] | V02 | Lecture fichiers `file://` + traversal | Critique | 080c0ea |
| [x] | V03 | Octets de police → FreeType | Haute | 5009198 |
| [x] | V04 | Taille de téléchargement | Haute | 98950eb |
| [x] | V05 | Bombe de décompression d'image | Haute | voir `git log` (commit courant) |
| [ ] | V06 | colspan / col span | Haute | — |
| [ ] | V07 | Expansion SVG `<use>` | Haute | — |
| [ ] | V08 | Récursion non bornée | Haute | — |
| [ ] | V09 | Nombre de pages | Moyenne+ | — |
| [ ] | V10 | @counter-style pad / additive | Moyenne+ | — |
| [ ] | V11 | Stride stb→cairo | Moyenne | — |
| [ ] | V12 | column-count | Moyenne | — |
| [ ] | V13 | Overflow entier | Basse | — |
| [ ] | V14 | Retours turbojpeg/webp | Basse | — |
| [ ] | V15 | Bornes en assert (latent) | Basse | — |
| [ ] | V16 | expat billion-laughs | Info | — |

## Notes

- (Le rapport commit initial ne coche rien : tous les statuts sont « à corriger ».)
- À chaque correctif : cocher la case, renseigner le hash, passer `status="done"` dans
  `security-audit/tools/genreport.py` et régénérer.
