"""
Foto-Echtheit: Content Credentials (C2PA), KI-Generator-Spuren, Kamera-Fingerabdruck (PRNU).

* C2PA: Manifest-Speicher (JPEG APP11/JUMBF, PNG caBX, XMP-Verweis) erkennen,
  Generator und deklarierte KI-Erzeugung (digitalSourceType trainedAlgorithmicMedia)
  auslesen. Die kryptografische Prüfung der Signatur braucht die C2PA-Bibliothek –
  ohne sie wird das Manifest als „nicht verifiziert“ gemeldet.
* KI-Marker: nur harte Spuren (IPTC-Quelltyp, Generator-Parameter in PNG-Text,
  bekannte Generator-Namen in Software/XMP) – keine Pixel-Raterei.
* PRNU: Rauschrest des Sensors (Bild minus geglättetes Bild) aus einem zentralen
  Ausschnitt als kompakter Fingerabdruck. Der Verlauf vergleicht ihn mit anderen
  Fotos gleicher Auflösung (Korrelation) → Indiz „gleiche Kamera“.
  Belastbar nur für Original-Fotos (nicht verkleinert/neu komprimiert).
"""
import base64
import re
import struct

from .base import finding

PRNU_CROP = 384                   # zentraler Ausschnitt in voller Auflösung (kein Binning – PRNU ist Pixel-Rauschen)
PRNU_MAX_PIXELS = 60_000_000
PRNU_Z = 6.0                      # Korrelation muss ≥ 6 σ über dem Zufallsniveau liegen (σ = 1/√N)
SAME_CAMERA_NCC = PRNU_Z / PRNU_CROP

AI_SOFTWARE = re.compile(rb"(Stable Diffusion|Midjourney|DALL[\-\xb7 ]?E|OpenAI|Adobe Firefly|Firefly|NovelAI|"
                         rb"ComfyUI|Automatic1111|InvokeAI|Leonardo\.Ai|Ideogram|Imagen|Gemini|Bing Image Creator|"
                         rb"Microsoft Designer|Flux|Runway|Craiyon|DreamStudio|NightCafe)", re.I)
SOURCE_TYPE = re.compile(rb"digitalsourcetype[^A-Za-z]{0,40}?(?:http://cv\.iptc\.org/newscodes/digitalsourcetype/)?"
                         rb"(trainedAlgorithmicMedia|compositeWithTrainedAlgorithmicMedia|algorithmicMedia|"
                         rb"compositeSynthetic|digitalCapture|compositeCapture|screenCapture)", re.I)
SD_PARAMS = re.compile(rb"Steps:\s*\d+,\s*Sampler:\s*[^,]+,\s*CFG scale:", re.I)


def _png_text_chunks(data):
    """tEXt/iTXt/zTXt-Schlüssel + (gekürzte) Werte, und ob ein caBX-Chunk (C2PA) existiert."""
    out, c2pa = {}, False
    pos = 8
    while pos + 8 <= len(data) and len(out) < 50:
        length, typ = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + length]
        if typ == b"caBX":
            c2pa = True
        elif typ in (b"tEXt", b"iTXt", b"zTXt"):
            key, _, val = body.partition(b"\x00")
            if typ == b"zTXt":
                import zlib
                try:
                    val = zlib.decompress(val[1:])[:200_000]
                except zlib.error:
                    val = b""
            elif typ == b"iTXt":
                val = val.split(b"\x00", 3)[-1] if val.count(b"\x00") >= 3 else val
            out[key.decode("latin-1")[:60]] = val[:200_000]
        if typ == b"IEND":
            break
        pos += 12 + length
    return out, c2pa


def _jpeg_app11_c2pa(data):
    """JUMBF-Boxen in APP11 (0xFFEB) mit C2PA-Kennung."""
    pos, found = 2, False
    while pos + 4 <= len(data) and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker in (0xD9, 0xDA):          # EOI / Start of Scan → Metadaten vorbei
            break
        seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if marker == 0xEB and b"c2pa" in data[pos + 4:pos + 2 + seg_len]:
            found = True
        pos += 2 + seg_len
    return found


def c2pa_info(data, subtype):
    present = False
    if subtype == "jpeg":
        present = _jpeg_app11_c2pa(data)
    elif subtype == "png":
        present = _png_text_chunks(data)[1]
    if not present and re.search(rb"c2pa\.(?:claim|assertions|signature)|urn:uuid:[0-9a-f-]{36}.{0,40}c2pa", data[:4 << 20], re.I):
        present = True
    if not present:
        return None
    region = data[:8 << 20]
    gen = re.search(rb"claim_generator[^A-Za-z0-9]{0,8}([ -~]{3,80})", region)
    ai = SOURCE_TYPE.search(region)
    actions = sorted({m.decode() for m in re.findall(rb"c2pa\.(created|edited|opened|placed|cropped|resized|"
                                                      rb"color_adjustments|drawing|converted|filtered)", region)})
    verified = None
    try:                                    # optional: echte Signaturprüfung
        import c2pa  # noqa: F401
        verified = "library present – full validation available via c2pa-python"
    except ImportError:
        verified = "signature NOT verified (install c2pa-python for cryptographic validation)"
    return {"present": True, "generator": gen.group(1).decode("latin-1").strip(" \"'") if gen else None,
            "source_type": ai.group(1).decode() if ai else None, "actions": actions, "verification": verified}


def ai_markers(data, subtype, meta_text=b""):
    marks = []
    if subtype == "png":
        chunks, _ = _png_text_chunks(data)
        for k, v in chunks.items():
            lk = k.lower()
            if lk == "parameters" and SD_PARAMS.search(v):
                marks.append(("Stable Diffusion generation parameters in PNG text chunk 'parameters'", "strong"))
            elif lk in ("prompt", "workflow") and v.lstrip()[:1] in (b"{", b"["):
                marks.append((f"ComfyUI {k} graph (JSON) embedded in PNG", "strong"))
            elif lk in ("software", "source", "comment", "description", "title") and AI_SOFTWARE.search(v):
                marks.append((f"PNG text '{k}': {AI_SOFTWARE.search(v).group(0).decode('latin-1')}", "strong"))
            elif lk == "dream":
                marks.append(("InvokeAI 'dream' prompt in PNG", "strong"))
    head = data[:2 << 20] + meta_text
    st = SOURCE_TYPE.search(head)
    if st and st.group(1).lower() in (b"trainedalgorithmicmedia", b"compositewithtrainedalgorithmicmedia",
                                      b"algorithmicmedia"):
        marks.append((f"IPTC DigitalSourceType = {st.group(1).decode()}", "strong"))
    sw = re.search(rb"(?:Software|CreatorTool|creator_tool)[^A-Za-z0-9]{0,12}([ -~]{2,60})", head)
    if sw and AI_SOFTWARE.search(sw.group(1)):
        marks.append((f"Software/CreatorTool: {sw.group(1).decode('latin-1').strip()}", "strong"))
    elif not marks:
        m = AI_SOFTWARE.search(data[:512_000])
        if m and subtype in ("png", "webp", "jpeg"):
            marks.append((f"Generator name in metadata: {m.group(0).decode('latin-1')}", "weak"))
    uniq, seen = [], set()
    for t, s in marks:
        if t not in seen:
            seen.add(t)
            uniq.append({"marker": t, "strength": s})
    return uniq


def prnu_fingerprint(path):
    """→ {'w','h','crop','ncc_base64'} oder None. Rauschrest eines zentralen Ausschnitts (float16)."""
    import numpy as np
    from PIL import Image
    with Image.open(path) as im:
        w, h = im.size
        if w * h > PRNU_MAX_PIXELS or min(w, h) < PRNU_CROP + 16:
            return None
        im = im.convert("L")
        x0, y0 = (w - PRNU_CROP) // 2, (h - PRNU_CROP) // 2
        a = np.asarray(im.crop((x0, y0, x0 + PRNU_CROP, y0 + PRNU_CROP)), dtype=np.float32)
    # Glättung (3×3-Mittelwert über kumulative Summen) → Rauschrest = Bild − Glättung
    p = np.pad(a, 1, mode="reflect")
    c = p.cumsum(0).cumsum(1)
    c = np.pad(c, ((1, 0), (1, 0)))
    smooth = (c[3:, 3:] - c[:-3, 3:] - c[3:, :-3] + c[:-3, :-3]) / 9.0
    res = a - smooth
    # Zeilen-/Spalten-Mittel (JPEG-/Sensor-Artefakte) entfernen, Ausreißer (Kanten) kappen
    res -= res.mean(axis=0, keepdims=True)
    res -= res.mean(axis=1, keepdims=True)
    std = float(res.std())
    if std < 1e-3:
        return None
    res = np.clip((res - res.mean()) / std, -3, 3)
    q = np.round(res * 40).astype(np.int8)          # int8: 147 KB statt 590 KB (float32)
    return {"w": w, "h": h, "crop": PRNU_CROP, "data": base64.b64encode(q.tobytes()).decode()}


def prnu_value(fp):
    """Kompakte Speicherform für den Verlauf: 'WxH:base64'."""
    return f"{fp['w']}x{fp['h']}:{fp['data']}"


def prnu_ncc(a, b):
    """Normalisierte Kreuzkorrelation zweier gespeicherter Fingerabdrücke (None bei anderer Auflösung)."""
    import numpy as np
    ra, _, da = a.partition(":")
    rb, _, db = b.partition(":")
    if ra != rb:                            # nur gleiche Auflösung ist vergleichbar
        return None
    x = np.frombuffer(base64.b64decode(da), dtype=np.int8).astype(np.float32)
    y = np.frombuffer(base64.b64decode(db), dtype=np.int8).astype(np.float32)
    if x.shape != y.shape or not len(x):
        return None
    x -= x.mean()
    y -= y.mean()
    den = float(np.sqrt((x * x).sum() * (y * y).sum())) or 1.0
    return float((x * y).sum() / den)


class PhotoAnalyzer:
    name = "photo"

    def applies(self, ctx):
        return ctx.category == "image" and ctx.subtype in ("jpeg", "png", "webp", "tiff", "heic")

    def run(self, ctx):
        data = ctx.data
        d, findings = {}, []
        c2 = c2pa_info(data, ctx.subtype)
        if c2:
            d["c2pa"] = c2
            ai_decl = c2.get("source_type") and "algorithmic" in c2["source_type"].lower()
            findings.append(finding("c2pa_present", f"Content Credentials (C2PA) vorhanden – Generator: "
                                                    f"{c2.get('generator') or 'unbekannt'}; {c2['verification']}", "INFO"))
            if ai_decl:
                findings.append(finding("c2pa_ai_declared", f"C2PA-Manifest erklärt das Bild als KI-erzeugt "
                                                            f"({c2['source_type']})", "WARN"))
        marks = ai_markers(data, ctx.subtype)
        if marks:
            d["ai_markers"] = marks
            strong = [m for m in marks if m["strength"] == "strong"]
            if strong:
                findings.append(finding("ai_generated", "KI-generiertes Bild: " + "; ".join(m["marker"] for m in strong[:3]),
                                        "WARN"))
            else:
                findings.append(finding("ai_generated_hint", "Möglicher KI-Generator erwähnt: " + marks[0]["marker"], "INFO"))
        try:
            fp = prnu_fingerprint(ctx.path)
        except Exception:
            fp = None
        if fp:
            d["prnu"] = {"w": fp["w"], "h": fp["h"], "crop": fp["crop"]}
            ctx.shared["prnu"] = prnu_value(fp)
        return {"data": d, "findings": findings}
