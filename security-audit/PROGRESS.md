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
| [x] | V05 | Bombe de décompression d'image | Haute | 2806e2d |
| [x] | V06 | colspan / col span | Haute | c35e686 |
| [x] | V07 | Expansion SVG `<use>` | Haute | 7897a70 |
| [x] | V08 | Récursion non bornée | Haute | 583dfcf |
| [x] | V09 | Nombre de pages | Moyenne+ | 99efe35 |
| [x] | V10 | @counter-style pad / additive | Moyenne+ | 37c94d1 |
| [x] | V11 | Stride stb→cairo | Moyenne | 40ad76d |
| [x] | V12 | column-count | Moyenne | 9821b38 |
| [x] | V13 | Overflow entier | Basse | bb826f2 |
| [x] | V14 | Retours turbojpeg/webp | Basse | 2945ca0 |
| [x] | V15 | Bornes en assert (latent) | Basse | 086414c |
| [x] | V16 | expat billion-laughs | Info | 371a78a |

**16/16 corrigés.** Rebuild propre depuis zéro OK ; batterie de PoC rejouée sur l'état intégré
(tout borné/refusé, aucun crash/hang/OOM).

## Suivi — problèmes découverts pendant les correctifs (hors périmètre des 16)

Trouvés en vérifiant les fixes ; **non corrigés** (distincts des 16 findings), à traiter séparément :

- **Layout de tables profondément imbriquées** : temps de calcul exponentiel de la largeur
  intrinsèque au-delà de ~80-100 niveaux (pré-existant, indépendant de V08). DoS CPU résiduel sous
  le cap de profondeur. (repéré en V08)
- **`Heap::concatenateString` O(n²)** (`source/heapstring.h`) : `TextNode::appendData` recopie toute
  la chaîne accumulée à chaque callback character-data, sur l'arène PMR monotone jamais libérée →
  une bombe d'entités XML profonde peut faire `std::bad_alloc` avant la protection expat. (V16)
- **Balancing multicolonne superlinéaire** en taille de contenu, même à `column-count` légitime.
  Perf, distinct de V12. (V12)
- **Writer PDF Cairo 1.18.4** : xref/trailer corrompu au-delà de ~65536 pages (bug Cairo, sans
  crash). Le défaut `maxPageCount=100000` dépasse ce seuil → envisager un défaut ≤ 65536. (V09)
- **memcpy sur `data()` null** dans `Heap::createString` (`heapstring.h:72`) pour un `string_view`
  vide, atteignable via `content: "\` + EOF (UB). (repéré en V15 ; le `std::abs(INT_MIN)` voisin a
  été corrigé dans le commit V13)

## Notes

- Le premier commit (rapport) ne coche rien : tous les statuts sont « à corriger ».
- Correctifs faits par un agent **Claude Code Sonnet 5**, un commit par problème, build+PoC vérifiés.
- Statut du rapport HTML piloté par `status`/`FIXCOMMITS` dans `security-audit/tools/genreport.py`.
