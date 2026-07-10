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
| [x] | V17 | memcpy sur `data()` null (chaîne vide) | Basse | 524e7f7 |
| [x] | V18 | Défaut maxPageCount > limite PDF Cairo | Moyenne | e4809ac |
| [x] | V19 | `Heap::concatenateString` O(n²) | Haute | aa01f02 |
| [x] | V20 | Layout tables imbriquées exponentiel | Haute | 5e2f11e |
| [x] | V21 | Balancing multicolonne superlinéaire | Moyenne | e655c98 |
| [x] | V22 | TextShape positionForOffset O(n²) (vraie cause de V21) | Haute | f8e4389 |

**V01–V16 corrigés** (rebuild propre OK, PoC intégrés vérifiés). **V17–V21** = problèmes découverts
pendant les correctifs. **V22** = découvert en diagnostiquant V21 : le coût superlinéaire réel du PoC
multicolonne est un O(n²) de shaping de texte (`textshape.cpp`), qui touche aussi tout long document
simple colonne. V21 a borné le balancing (défensif) ; **V22 corrige la vraie cause** (recherche
dichotomique dans `TextShapeRun` + le même correctif étendu aux méthodes de scan de glyphes de
`TextShapeView`, nécessaires en pratique pour que le PoC redevienne rapide — détails ci-dessous).

## Détails des problèmes de suivi (V17–V22)

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
- **V20** — Layout de tables profondément imbriquées : coût exponentiel confirmé par comptage
  d'appels (2^(N+1)-2 layouts de cellule pour N niveaux), indépendant du cap de profondeur V08 (512).
  Diagnostic : **pas** le calcul de largeur préférée (déjà mis en cache par boîte, coût O(N) mesuré) ;
  le doublement vient du layout CSS à deux passes par table (mesure de hauteur naturelle puis
  ré-layout étiré à la hauteur de ligne), chaque passe relayant intégralement toute table imbriquée à
  l'intérieur. Mémoiser un layout complet (positions/overflow/fragmentation) aurait été bien plus
  invasif qu'un calcul de largeur — repli choisi (option documentée dans le dossier V20) : nouvelle
  limite `EngineLimits::maxTableNestingDepth` (défaut **8**, configurable, 0 = illimité) ; au-delà,
  `TableSectionBox::layoutRows()` saute la passe d'étirement pour les cellules de cette table (même
  contenu/largeur/position, simplement pas étirées face à une cellule voisine plus haute — cosmétique
  uniquement, au-delà de la limite). Le défaut doit rester bas car le coût est
  O(2^limite × profondeur_totale), pas seulement O(2^limite) : un défaut de l'ordre de 100 (a priori
  raisonnable par analogie aux autres limites) resterait exponentiel et insuffisant — vérifié
  empiriquement. Vérifié : mise à l'échelle linéaire (0.19/0.63/0.89/0.98 s pour 50/100/150/200
  niveaux, contre hang/timeout pré-fix dès N≈20-25) ; PoC 150 niveaux → ~0.92 s (pré-fix : timeout
  >20 s) ; non-régression par **comparaison PDF octet pour octet** (binaire pré-fix via `git stash` +
  build séparé vs post-fix) sur grille simple/colspan-rowspan/imbrication 2 niveaux/largeurs
  %-fixe-auto/caption (identiques) et sur imbrication réelle jusqu'à exactement la limite (profondeur
  8 incluse, identique) ; ne diffère qu'au-delà (profondeur 9+, et seulement quand une ligne a des
  cellules de hauteurs naturelles différentes). (V08)
- **V21** — Balancing multicolonne superlinéaire en taille de contenu, même à `column-count`
  légitime. Diagnostic **corrigé** par instrumentation (chronométrage par ligne/par passe) : la boucle
  de balancing (`MultiColumnFlowBox::layoutContents()`) n'est **pas** en cause — l'estimation initiale
  (`distributeImplicitBreaks()`) vaut exactement `hauteurTotale / columnCount` sans saut de colonne
  explicite (vérifié algébriquement et sur de nombreuses formes de contenu adversarial) : convergence
  systématique en 1-2 itérations, quelle que soit la taille du contenu. Le vrai coût superlinéaire
  (chronométrage ligne par ligne : ~4-5× plus cher en fin de document qu'en début) vient de
  `TextShapeRun::positionForOffset()`/`offsetForPosition()` (`source/graphics/textshape.cpp`, hors de ce
  fichier) : ces fonctions re-parcourent le tableau de glyphes depuis l'indice 0 à chaque appel au lieu
  de reprendre depuis une position mémorisée — reproductible à l'identique sur du texte simple sans
  colonnes. Hors périmètre de ce correctif (fichier différent, effet de bord large sur tout layout de
  texte) — **signalé comme piste de suivi séparée** pour une prochaine entrée d'audit. Correctif livré
  ici (repli documenté) : nouvelle limite `EngineLimits::maxColumnBalancingIterations` (défaut **10**,
  configurable, 0 = illimité) bornant le nombre de passes de relayout du balancing, pour garantir la
  terminaison même si une forme de contenu future déjouait l'estimation initiale (aujourd'hui exacte en
  pratique mais non prouvée pour toute entrée adversariale). Vérifié : non-régression par comparaison
  PDF **octet pour octet** (binaire pré-fix via `git stash` + build séparé) sur documents 2/3 colonnes,
  `column-gap`, `column-span:all` (identiques) ; défaut (10) identique au byte près à illimité (0) sur
  le PoC et sur un document à spanners multiples ; cap volontairement bas (1, harnais C dédié) déclenche
  bien un arrêt anticipé mesurable (PDF différent) tout en gardant un rendu complet et valide (aucun
  contenu perdu). Mise en garde : ce correctif ne fait **pas** converger le PoC littéral vers un temps
  linéaire, la cause dominante étant hors périmètre (voir ci-dessus). (V12)
- **V22** — Root cause de V21 : `TextShapeRun::positionForOffset()`/`offsetForPosition()`
  re-parcourent le tableau de glyphes depuis l'indice 0 à chaque appel ; le line layout les appelle une
  fois par ligne, donc un long run devient O(n²). Corrigé par recherche dichotomique
  (`glyphIndexForOffset()`, nouveau) sur `characterIndex` (monotone par construction HarfBuzz, croissant
  en LTR / décroissant en RTL, quel que soit le signe des avances) + une somme cumulée des avances
  (`advanceUpTo`) précalculée une seule fois à la création du run, rendant les deux fonctions O(log n)
  au lieu de O(n). `offsetForPosition` recherche sur la somme cumulée elle-même, qui n'est monotone que
  si toutes les avances sont ≥ 0 (cas normal) ; un `letter-spacing`/`word-spacing` négatif assez fort
  peut rendre une avance négative — dans ce cas (rare, détecté une fois par run à la création), la
  fonction retombe sur le rescan linéaire original **verbatim**, pour ne jamais risquer un résultat
  différent d'un cas non prouvé monotone.
  **Diagnostic affiné pendant l'implémentation** : ce seul correctif ne suffisait pas — mesuré
  empiriquement (5000/10000/20000/40000 mots : 0,8s/2,9s/11,4s/42s, toujours quadratique après la
  recherche dichotomique seule). Instrumentation par compteurs d'itérations : le morceau dominant était
  en fait dans `TextShapeView::width()`, `maxAscentAndDescent()`, `draw()` et
  `expansionOpportunityCount()` — même motif (parcourent tous les runs de la shape depuis le glyphe 0 à
  chaque appel, y compris pour les runs entièrement hors de la vue courante, qu'elles balaient en pure
  perte). Corrigées avec la même technique via une nouvelle fonction `rangeForView()` : saut O(1) des
  runs entièrement hors-plage (arrêt de la boucle externe dès que les runs restants le sont
  nécessairement aussi, l'ordre étant croissant en LTR / décroissant en RTL) et recherche dichotomique
  du premier glyphe pertinent dans le run qui chevauche la vue. Cas particulier de `draw()`, qui a un
  effet de bord par run (appels cairo) : sa boucle externe continue de visiter tous les runs dans le même
  ordre et émet les mêmes appels cairo pour chacun — seul le balayage de glyphes est raccourci, laissant
  `numGlyphs` à 0 exactement comme le balayage original l'aurait fait pour un run hors-plage.
  Vérifié : mise à l'échelle quasi linéaire une fois les 4 méthodes corrigées (200k mots : 40s+ timeout →
  1,4s ; 2x → 3,7s ; 4x → 11,0s — légèrement superlinéaire au-delà de textshape.cpp lui-même, confirmé
  par compteurs : les fonctions corrigées scalent, elles, parfaitement linéairement ; résidu hors
  périmètre, ailleurs dans le pipeline) ; PoC V21 (`make-multicol.py`) 60s timeout pré-fix → 0,24s
  post-fix ; **non-régression par comparaison octet pour octet** (binaire pré-fix via `git stash` + build
  meson séparé) sur 14 documents couvrant LTR multi-paragraphe, texte justifié, polices/styles mélangés,
  ligatures, `letter-spacing` négatif (chemin de repli inclus), arabe RTL, hébreu RTL, bidi mixte,
  tabulations, cas limites, texte SVG (`draw()` hors linelayout.cpp), et versions réduites des PoC
  longtext/V21 — tous identiques au byte près (PDF, plus PNG sur 6 de ces documents). (V21)

## Notes

- Le premier commit (rapport) ne coche rien : tous les statuts sont « à corriger ».
- Correctifs faits par un agent **Claude Code Sonnet 5**, un commit par problème, build+PoC vérifiés,
  poussés après chaque commit.
- Statut du rapport HTML piloté par `status`/`FIXCOMMITS` dans `security-audit/tools/genreport.py`.
