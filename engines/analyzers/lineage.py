"""
Herkunftsmerkmale für den Dokument-Stammbaum.

* PDF:  Trailer-/ID [<permanent> <diese Version>] – die erste ID bleibt über alle
        Versionen gleich; Zahl der Speicherstände (%%EOF, inkrementelle Updates)
* XMP:  xmpMM:OriginalDocumentID / DocumentID / InstanceID, DerivedFrom (Eltern-IDs),
        History (frühere InstanceIDs) – Adobe-, Office- und viele Kamera-/Bildprogramme
* DOCX: word/settings.xml → rsidRoot (Ursprungsdokument) + alle RSIDs (Bearbeitungssitzungen)
"""
import re
import zipfile

MAX_RSIDS = 800

_PDF_ID = re.compile(rb"/ID\s*\[\s*<([0-9A-Fa-f]{8,64})>\s*<([0-9A-Fa-f]{8,64})>\s*\]")


def _xmp_values(data, tag):
    """Werte eines XMP-Feldes als Attribut (tag="…") oder Element (<tag>…</tag>)."""
    t = re.escape(tag)
    vals = re.findall(rb"%s\s*=\s*[\"']([^\"']{6,120})[\"']" % t.encode(), data)
    vals += re.findall(rb"<%s>\s*([^<]{6,120})\s*</%s>" % (t.encode(), t.encode()), data)
    return [v.decode("latin-1").strip() for v in vals]


def _norm(v):
    return re.sub(r"^(xmp\.(did|iid):|uuid:|adobe:docid:[a-z]+:)", "", v.strip(), flags=re.I).lower()


def xmp_lineage(data):
    region = data[: 16 << 20]
    if b"xmpMM" not in region and b"stRef" not in region:
        return {}
    doc = _xmp_values(region, "xmpMM:DocumentID")
    orig = _xmp_values(region, "xmpMM:OriginalDocumentID")
    inst = _xmp_values(region, "xmpMM:InstanceID")
    derived = _xmp_values(region, "stRef:documentID") + _xmp_values(region, "stRef:instanceID") \
        + _xmp_values(region, "stRef:originalDocumentID")
    hist = _xmp_values(region, "stEvt:instanceID")
    out = {}
    if doc:
        out["xmp_doc"] = _norm(doc[0])
    if orig:
        out["xmp_orig"] = _norm(orig[0])
    if inst:
        out["xmp_inst"] = _norm(inst[0])
    own = {out.get("xmp_doc"), out.get("xmp_inst")}
    if derived:
        out["xmp_derived"] = sorted({_norm(v) for v in derived} - own)[:10]
    if hist:
        out["xmp_hist"] = sorted({_norm(v) for v in hist} - own)[:30]
    return {k: v for k, v in out.items() if v}


def pdf_lineage(data):
    ids = _PDF_ID.findall(data)
    if not ids:
        return {}
    first, current = ids[-1]
    return {"pdf_id0": first.decode().lower(), "pdf_id1": current.decode().lower(),
            "pdf_saves": max(1, data.count(b"%%EOF"))}


def docx_lineage(path):
    try:
        with zipfile.ZipFile(path) as z:
            if "word/settings.xml" not in z.namelist():
                return {}
            zi = z.getinfo("word/settings.xml")
            if zi.file_size > 4 << 20:
                return {}
            xml = z.read(zi)
    except (zipfile.BadZipFile, OSError, KeyError, RuntimeError):
        return {}
    root = re.search(rb"<w:rsidRoot\s+w:val=\"([0-9A-Fa-f]{8})\"", xml)
    rsids = re.findall(rb"<w:rsid\s+w:val=\"([0-9A-Fa-f]{8})\"", xml)
    out = {}
    if root:
        out["rsid_root"] = root.group(1).decode().upper()
    if rsids:
        out["rsids"] = sorted({r.decode().upper() for r in rsids})[:MAX_RSIDS]
    return out


class LineageAnalyzer:
    name = "lineage"

    def applies(self, ctx):
        return ctx.category in ("pdf", "document", "image") or ctx.subtype in ("docx", "xlsx", "pptx")

    def run(self, ctx):
        data = ctx.data
        d = {}
        if ctx.category == "pdf":
            d.update(pdf_lineage(data))
        if ctx.subtype == "docx" or ctx.ext in (".docx", ".docm", ".dotx"):
            d.update(docx_lineage(ctx.path))
        d.update(xmp_lineage(data))
        if d.get("pdf_saves", 1) > 1:
            d["note"] = f"{d['pdf_saves']} Speicherstände (inkrementelle Änderungen) in der PDF"
        return {"data": d, "findings": []}
