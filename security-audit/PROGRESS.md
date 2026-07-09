# PROGRESS — correctifs de sécurité PlutoBook

Journal de progression. **Reprise** : lire ce fichier + `git log --oneline`, reprendre au premier
problème non coché. Un commit par problème (voir `FIX-GUIDE.md`). **Pousser après chaque commit.**

- Branche : `security-audit`
- Agent correctifs : **Claude Code Sonnet 5**
- Ordre : V01→V16 (audit initial, criticité décroissante), puis V17→V21 (suivi, ordre demandé)

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
| [x] | V17 | memcpy sur `data()` null (chaîne vide) | Basse | voir git log |
| [x] | V18 | Défaut maxPageCount > limite PDF Cairo | Moyenne | voir git log |
| [x] | V19 | `Heap::concatenateString` O(n²) | Haute | voir git log |
| [ ] | V20 | Layout tables imbriquées exponentiel | Haute | — |
| [ ] | V21 | Balancing multicolonne superlinéaire | Moyenne | — |

**V01–V16 corrigés** (rebuild propre OK, PoC intégrés vérifiés). **V17–V21** = problèmes découverts
pendant les correctifs, désormais suivis et traités dans l'ordre : V17 → V18 → V19 → V20 → V21.

## Détails des problèmes de suivi (V17–V21)

- **V17** — memcpy sur `data()` null dans `Heap::createString` (`heapstring.h:72`) pour un
  `string_view` vide, atteignable via `content:"\` + EOF (UB). (repéré en V15 ; le `std::abs(INT_MIN)`
  voisin avait été corrigé dans le commit V13)
- **V18** — Writer PDF Cairo 1.18.4 : au-delà de 65533 pages dans un même surface PDF, l'object stream
  partagé des objets Catalog/Pages/Info déborde son champ d'index 2 octets (max 65536 entrées) →
  xref/trailer corrompu (bug Cairo, sans crash ; vérifié empiriquement par bisection : 65533 pages =
  PDF valide, 65534 = invalide, reproduit sur plusieurs formes de document). Le défaut
  `maxPageCount=100000` (V09) dépassait ce seuil → défaut abaissé à **65533**. (V09)
- **V19** — `Heap::concatenateString` O(n²) (`source/heapstring.h`) : `TextNode::appendData` recopiait
  toute la chaîne accumulée à chaque callback character-data, sur l'arène PMR monotone jamais libérée.
  Confirmé par bisection binaire (stash/rebuild) : sous `ulimit -v` de 2-3 Gio, la bombe d'entités XML
  (`poc/make-entity-bomb.py`) et même un document **légitime** de ~2,1 M caractères fragmenté en
  ~200 000 callbacks (via `&amp;` répétés) font `std::bad_alloc` avant que la protection expat (V16)
  ne se déclenche. Corrigé en accumulant les fragments dans un `std::string` ordinaire (tas normal,
  croissance géométrique, libéré à chaque réallocation) et en ne matérialisant dans l'arène qu'une
  seule fois, à la première lecture (`TextNode::data()`) — coût O(n) au lieu de O(n²), texte
  identique (vérifié octet pour octet via `pdftotext`). Défense en profondeur additionnelle :
  `EngineLimits::maxTextNodeLength` (défaut 100 000 000 caractères, configurable). (V16)
- **V20** — Layout de tables profondément imbriquées : coût exponentiel du calcul de largeur
  intrinsèque au-delà de ~80-100 niveaux (indépendant du cap de profondeur V08). DoS CPU. (V08)
- **V21** — Balancing multicolonne superlinéaire en taille de contenu, même à `column-count`
  légitime. Perf/DoS CPU, distinct de V12. (V12)

## Notes

- Le premier commit (rapport) ne coche rien : tous les statuts sont « à corriger ».
- Correctifs faits par un agent **Claude Code Sonnet 5**, un commit par problème, build+PoC vérifiés,
  poussés après chaque commit.
- Statut du rapport HTML piloté par `status`/`FIXCOMMITS` dans `security-audit/tools/genreport.py`.
