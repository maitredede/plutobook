# Guide d'implémentation des correctifs — PlutoBook (pour Claude Code Sonnet 5)

> **Destinataire** : agent Claude Code **Sonnet 5**. Ce document est la référence unique pour
> implémenter les correctifs de l'audit de sécurité. Le rapport détaillé (nature/risque/repro de
> chaque problème) est dans `security-audit/index.html` et les dossiers `Vxx-*/`.

## Mission

Corriger les 16 problèmes de sécurité **par ordre de criticité décroissante** (V01 d'abord),
**un commit par problème**. Chaque limite ou borne ajoutée doit avoir une **valeur par défaut
raisonnable** ET être **configurable**. Les protocoles dangereux doivent être **réactivables par
configuration**. Un **hook validateur d'URL** doit permettre de filtrer toute URL avant
téléchargement (fetcher curl par défaut OU handler custom).

## Contexte du dépôt

- Lib C++ de rendu HTML/XML/CSS/SVG → PDF/Bitmap. Build : **meson**.
- Branche de travail : **`security-audit`** (déjà créée ; ne pas travailler sur `main`).
- Modèle de menace : **input non fiable** (rendu serveur de HTML/SVG/CSS arbitraire).
- API publique : `include/plutobook.hpp` (C++) et `include/plutobook.h` (C).
- Fetcher par défaut : classe `DefaultResourceFetcher` dans `include/plutobook.hpp` (pattern :
  setters publics + membres privés avec valeur par défaut) ; implémentation dans
  `source/resource/resource.cpp`.

## Workflow OBLIGATOIRE par problème (répéter V01 → V16)

1. Lire la page du problème (`security-audit/Vxx-*/index.html`) et cette section ci-dessous.
2. Implémenter le correctif dans `source/…` (+ API `include/…` si un knob est ajouté).
3. **Vérifier** : build + rejouer le PoC de `security-audit/Vxx-*/poc/` (le comportement dangereux
   doit être bloqué/borné ; le rendu légitime doit rester inchangé). Voir « Build & vérification ».
4. Marquer le problème résolu dans le **rapport** : éditer `security-audit/tools/genreport.py`,
   passer le `status="todo"` du finding concerné à `status="done"` (et renseigner
   `fixcommit="<hash court>"` si connu — sinon laisser vide, le hash sera visible dans git),
   puis régénérer : `python3 security-audit/tools/genreport.py`.
5. Cocher la ligne correspondante dans `security-audit/PROGRESS.md` (statut + hash de commit).
6. **Commit unique** pour ce problème, incluant : le code, la régénération du rapport, PROGRESS.md.

### Format de commit

```
sec(Vxx): <résumé court du correctif>

<explication : ce qui était vulnérable, la borne/knob ajouté, défaut choisi>

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

Exemple : `sec(V06): clamp colspan/rowspan/col span (défaut 1000, configurable)`.

### Reprise après interruption (quota)

L'historique git + `PROGRESS.md` sont le journal. À chaque démarrage : lire `PROGRESS.md` et
`git log --oneline`, reprendre au **premier problème non `done`**, ne jamais refaire un commit déjà
présent.

---

## Design de configuration (à mettre en place, réutilisé par plusieurs correctifs)

### A. Knobs du fetcher (`DefaultResourceFetcher`, `include/plutobook.hpp`)

Ajouter, sur le modèle exact des setters existants (`setFollowRedirects`, `setMaxRedirects`,
`setTimeout`) :

| Setter | Membre / défaut | Effet |
|--------|-----------------|-------|
| `setAllowedProtocols(std::string csv)` | `m_allowedProtocols = "http,https,data"` | allowlist de schémas ; sert `CURLOPT_PROTOCOLS_STR` + `CURLOPT_REDIR_PROTOCOLS_STR` |
| `setMaxDownloadSize(size_t bytes)` | `m_maxDownloadSize = 32*1024*1024` | plafond ; `CURLOPT_MAXFILESIZE_LARGE` + cap dur dans `writeCallback` |
| `setConnectTimeout(int s)` | `m_connectTimeout = 30` | `CURLOPT_CONNECTTIMEOUT` |
| `setMaxImagePixels(uint64_t px)` | `m_maxImagePixels = 64ULL*1000*1000` | budget pixel avant `cairo_image_surface_create` |
| `setMaxFontBytes(size_t bytes)` | `m_maxFontBytes = 8*1024*1024` | plafond octets police (V03) |

`file`, `ftp`, `gopher`… sont **hors allowlist par défaut** → réactivables via `setAllowedProtocols`.

### B. Hook validateur d'URL (couvre curl ET handler custom)

Objectif : un callback appelé **avant tout téléchargement**, quel que soit le fetcher.

- Type C++ : `using UrlValidator = std::function<bool(std::string_view url)>;` (retour `false` = refus).
- Point d'application : dans `ResourceLoader::loadUrl` (`source/resource/resource.cpp:371`) **avant**
  `customFetcher->fetchUrl(...)` — c'est le passage obligé du fetcher par défaut ET du handler custom.
- Stockage : porter le validateur sur le contexte accessible à `loadUrl`. Deux options acceptables :
  1. un validateur global optionnel (setter statique sur `ResourceLoader`/config globale), ou
  2. le passer via le `Book`/document jusqu'à `Document::fetchResource` (`source/document.cpp:1062`).
  Choisir l'option la plus simple cohérente avec l'architecture existante ; documenter le choix.
- Exposer aussi en **API C** (`include/plutobook.h`) : un `typedef` de pointeur de fonction
  `bool (*)(const char* url, void* userdata)` + un setter avec `void* userdata`.
- Combiner avec l'allowlist : le schéma est vérifié d'abord, puis le validateur utilisateur.

### C. Limites du moteur (parse / layout)

**Fait (V06)** : la facade `EngineLimits` centralise désormais ces limites moteur (parse/layout),
par opposition aux knobs du fetcher (section A, propres au réseau/decode de ressources). C'est le
foyer partagé pour V06-V12 : **réutiliser cette classe verbatim**, ne pas créer un second mécanisme.

- Classe C++ `plutobook::EngineLimits` (`include/plutobook.hpp`, implémentation dans
  `source/plutobook.cpp`) : un setter/getter par limite (ex. `setMaxTableSpan(uint32_t)` /
  `maxTableSpan() const`), défaut sûr en initialiseur de membre, `0` = illimité (à documenter par
  limite si applicable). Constructeur privé + `friend` de l'accesseur singleton, sur le modèle exact
  de `DefaultResourceFetcher` (section A) — **pas** de `kMaxImportDepth`-style constante locale non
  configurable pour les nouvelles limites (`kMaxImportDepth` reste un cas isolé pré-existant, non
  reconfigurable, à ne pas imiter pour V07+).
- Accesseur global : `plutobook::EngineLimits* plutobook::engineLimits();` (singleton
  function-local `static`, même pattern que `defaultResourceFetcher()`).
- API C correspondante (`include/plutobook.h`, implémentation dans `source/plutobook.cc`) : un
  `plutobook_set_<nom>(...)` par setter, qui appelle `plutobook::engineLimits()->set<Nom>(...)`
  (voir `plutobook_set_max_table_span` pour le modèle).
- **Pour ajouter une limite (V07-V12)** : ajouter un membre privé + son setter/getter public dans
  `EngineLimits` (`plutobook.hpp`), la fonction C correspondante dans `plutobook.h`/`plutobook.cc` ;
  lire la valeur via `engineLimits()->maXxx()` au(x) point(s) d'enforcement. Aucune autre plomberie
  requise (le singleton et son accesseur existent déjà).

| Limite | Défaut proposé | Concerne | Accesseur |
|--------|----------------|----------|-----------|
| `colspan` / `rowspan` / `col span` max | 1000 (valeur spec HTML) | V06 | `maxTableSpan` — **fait** |
| profondeur d'imbrication (parse/layout/paint/destruction) | 512 | V08 | `maxNestingDepth` (à ajouter) |
| budget d'expansion `<use>` (nœuds instanciés) + profondeur | 100 000 nœuds / prof. 512 | V07 | `maxUseExpansion` (+ profondeur, à ajouter) |
| `column-count` max | 1000 | V12 | `maxColumnCount` (à ajouter) |
| nombre de pages max | 100 000 | V09 | `maxPageCount` (à ajouter) |
| longueur max de représentation de compteur | 100 000 | V10 | `maxCounterLength` (à ajouter) |

Toujours : **défaut qui ne casse pas le rendu légitime**, exposé C++ et C, documenté.

---

## Correctifs par problème

> Format : localisation → action → défaut/knob → vérif (PoC du dossier).

### V01 — SSRF / fetch multi-schéma — **Critique**
- `source/resource/resource.cpp` `fetchUrl` (~284) : avant `curl_easy_perform`, définir
  `CURLOPT_PROTOCOLS_STR` et `CURLOPT_REDIR_PROTOCOLS_STR` = `m_allowedProtocols`.
- Appliquer le validateur d'URL (design B) en amont (dans `loadUrl`).
- Optionnel : `CURLOPT_PREREQFUNCTION` pour refuser les IP internes (loopback/link-local/RFC1918).
- Knob : `setAllowedProtocols` (défaut `http,https,data`). Vérif : `poc/repro.html` + `poc/listener.py`
  → aucune connexion interne, `169.254.169.254`/`gopher` refusés.

### V02 — Lecture de fichiers `file://` + traversal — **Critique**

**Modèle de confiance à introduire** (clé de V02 et correction d'une régression de V01) :
distinguer le **document de premier niveau** — l'URL explicitement fournie par l'appelant
(`Book::loadUrl`, ex. `html2pdf ./doc.html`) = **de confiance** — des **sous-ressources**
référencées par le document (`Document::fetchResource`, ex. `<img>`, `@import`, `@font-face`) =
**non fiables**.

- L'allowlist de schémas par défaut (`http,https,data`, sans `file`) et le filtrage IP interne ne
  doivent s'appliquer qu'aux **sous-ressources**. Le **premier niveau** garde le schéma choisi par
  l'appelant (donc `file://` fonctionne pour `html2pdf ./x.html`). Implémentation : propager un
  drapeau « top-level / trusted » jusqu'à `ResourceLoader::loadUrl` (ou séparer les chemins de code
  entre chargement du document racine et fetch de sous-ressource).
- Le **validateur d'URL** (V01) reste appelé dans **les deux** cas (l'appelant peut donc imposer sa
  propre politique même au premier niveau), mais il voit l'URL **résolue** (absolue) pour permettre
  un confinement à une racine.
- Concerne aussi la branche non-curl (`resource.cpp:331-367`) : même traitement.
- **Régression V01 à corriger ici** : `html2pdf fichier.html` doit à nouveau fonctionner (entrée
  locale = premier niveau de confiance) tout en refusant `file://` en **sous-ressource** par défaut.
- Vérif : (a) `html2pdf security-audit/V02-local-file-read/poc/repro.html out.pdf` : le document se
  charge, mais la feuille de style `file:///etc/passwd` et l'`<img>` en traversal `../../etc/hostname`
  (sous-ressources) sont refusés par défaut ; (b) `html2pdf <un fichier local simple>` fonctionne ;
  (c) `setAllowedProtocols(...,"file")` réautorise `file://` en sous-ressource.

### V03 — Octets de police → FreeType — **Haute**
- `source/resource/fontresource.cpp:57` : avant `FT_New_Memory_Face`, vérifier taille ≤
  `m_maxFontBytes` et magic-bytes plausibles (`OTTO`, `true`, `ttcf`, `0x00010000`, `wOFF`, `wOF2`).
- Appliquer le plafond de taille (V04) au fetch des polices.
- Knob : `setMaxFontBytes` (défaut 8 MiB). Vérif : `poc/repro.html` + `poc/make-evil-font.py`
  → police hors format/hors taille rejetée proprement.

### V04 — Taille de téléchargement — **Haute**
- `source/resource/resource.cpp` : `CURLOPT_MAXFILESIZE_LARGE = m_maxDownloadSize` ; dans
  `writeCallback`, si `response->size() + total > m_maxDownloadSize` → retourner 0 (abandon curl).
  `writeCallback` doit accéder au plafond (passer la limite via la struct de `CURLOPT_WRITEDATA`).
- Ajouter `CURLOPT_CONNECTTIMEOUT = m_connectTimeout`.
- Knob : `setMaxDownloadSize` (défaut 32 MiB). Vérif : `poc/repro.html` + `poc/huge-server.py`
  → transfert coupé au plafond, pas d'OOM.

### V05 — Bombe de décompression d'image — **Haute**
- `source/resource/imageresource.cpp` : sur les 3 voies (stb `~162`, turbojpeg `~100`, webp `~139`),
  après avoir obtenu width/height (pré-décodage : `WebPGetFeatures`, `tjDecompressHeader`, et pour
  stb `stbi_info_from_memory`), refuser si `(uint64_t)width*height > m_maxImagePixels` **avant**
  `cairo_image_surface_create`/décodage plein.
- Abaisser `STBI_MAX_DIMENSIONS` (ex. via `#define` avant l'include de `stb_image.h`).
- Knob : `setMaxImagePixels` (défaut 64 MP). Vérif : `poc/make-bomb.py` → `bomb.png` rejeté.

### V06 — colspan / col span — **Haute**
- `source/htmldocument.cpp:858-861` (`colSpan()`) et `:823` (`span()`) : clamper au max configurable
  (défaut 1000), en plus du min existant. Modèle : le clamp `rowSpan` déjà présent
  (`source/layout/tablebox.cpp:1364-1376`).
- Vérif : `poc/repro.html` (`colspan=200000000`) → borné, pas d'OOM.

### V07 — Expansion SVG `<use>` — **Haute**
- `source/svgdocument.cpp:336-406` : ajouter un compteur global de nœuds instanciés par `<use>`
  (budget) + une limite de profondeur d'expansion. Stopper au dépassement (ne pas cloner davantage).
- Vérif : `poc/make-svg-bomb.py` → `bomb.svg` borné, pas d'OOM/hang.

### V08 — Récursion non bornée — **Haute**
- CSS : compteur de profondeur dans `source/csstokenizer.h` `consumeComponent`/`consumeBlock` (~173),
  la récursion sélecteurs (`source/cssparser.cpp:740-858`) et at-rules (`:365-373`).
- Arbre : limite d'imbrication au parsing (HTML/XML/SVG) couvrant `finishParsingDocument`
  (`source/document.cpp:267`), `cloneChildren` (`:236`), le layout (`source/layout/blockbox.cpp:1541`)
  et la destruction (`source/layout/box.cpp:37`).
- Knob : profondeur max (défaut 512). Vérif : `poc/make-deep.py` → refus propre, pas de SIGSEGV.

### V09 — Nombre de pages — **Moyenne+**
- `source/layout/pagebox.cpp:694-723` : borner `pageCount` au max configurable ; garde
  `UINT32_MAX`/valeur finie **avant** la conversion float→`uint32_t` (`source/counters.cpp:16`).
- Vérif : `poc/repro.html` (`height:1e9px`) → nombre de pages borné.

### V10 — @counter-style pad / additive — **Moyenne+**
- `source/cssrule.cpp:855-878` (`pad`) et `:766-768` (additive) : plafonner le nombre de répétitions
  / la longueur de la représentation (défaut 100 000).
- Vérif : `poc/repro.html` (`pad:2000000000`) → pas d'OOM.

### V11 — Stride stb→cairo — **Moyenne**
- `source/resource/imageresource.cpp:175` : indexer `imageData` avec le stride **packé**
  (`width*4`), pas `surfaceStride`. `dst` conserve `surfaceStride`.
- Correctif pur (pas de knob). Vérif : `poc/make-bmp.py` (largeur non alignée) → pas d'over-read (ASan).

### V12 — column-count — **Moyenne**
- `source/cssparser.cpp:1479-1486` ou au stockage (`source/layout/multicolumnbox.cpp:510`) :
  clamper `column-count` au max (défaut 1000).
- Vérif : `poc/repro.html` (`columns:2000000000`) → pas de hang.

### V13 — Overflow entier — **Basse**
- `source/htmldocument.cpp:224-233` : accumulation avec détection de dépassement + clamp de plage
  (au lieu de `output*10+digit` nu). Idem exposants `source/csstokenizer.cpp:289`,
  `source/svgproperty.cpp:130`.
- Vérif : `poc/repro.html` → valeurs énormes bornées, pas d'UB (UBSan).

### V14 — Retours turbojpeg/webp — **Basse**
- `source/resource/imageresource.cpp:110-123` : tester le retour de `tjDecompress2` et le
  `std::malloc` avant `memcpy` ; libérer/échouer proprement.
- Vérif : JPEG malformé/tronqué (voir `poc/note.md`) sous ASan.

### V15 — Bornes en assert — **Basse (latent)**
- `source/csstokenizer.h:239-286` : rendre `advance`/`substring`/`consume` sûrs en release (clamp
  `m_offset`, vérif de bornes actives, pas seulement `assert`).
- `source/pointer.h:227-236` (`to<T>()`) : envisager une vérif active en release sur les chemins
  chauds de downcast de box. Cible de fuzzing prioritaire (voir `poc/note.md`).

### V16 — expat billion-laughs — **Info**
- `meson.build:8-11` : imposer `expat >= 2.4.0` (version minimale) ; sinon, dans
  `source/xmlparser.cpp`, fixer explicitement
  `XML_SetBillionLaughsAttackProtectionMaximumAmplification`/`…ActivationThreshold`.
- XXE déjà non atteignable (aucun handler d'entité externe) — **ne pas** en ajouter.
- Vérif : `poc/lol.xml`.

---

## Build & vérification

```bash
# Build (activer les sanitizers si les dépendances le permettent)
meson setup build -Db_sanitize=address,undefined || meson setup build
meson compile -C build

# Rejouer un PoC : utiliser l'exemple/CLI du dépôt qui charge un fichier HTML/SVG et rend un PDF/PNG,
# en pointant sur security-audit/Vxx-*/poc/repro.html (ou le fichier généré par le script poc).
# Générer les PoC dynamiques d'abord, ex. :
python3 security-audit/V05-image-bomb/poc/make-bomb.py     # crée bomb.png
python3 security-audit/V07-svg-use/poc/make-svg-bomb.py    # crée bomb.svg
python3 security-audit/V08-recursion/poc/make-deep.py      # crée deep.html / deep.css.html
```

Critère : le comportement dangereux est **bloqué ou borné** (refus, clamp, erreur propre) et le
**rendu de documents légitimes reste inchangé** (rejouer les exemples/tests existants du dépôt pour
la non-régression). Si les sanitizers ou une dépendance manquent dans l'environnement, faire au moins
le build standard + vérification comportementale, et le noter dans le message de commit.
