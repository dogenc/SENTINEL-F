"""
Vorher-Nachher-Vergleich zweier Dateien.

content_diff(a, b)   – liest die INHALTE (läuft im Sandbox-Worker, Modus --sentinel-diff):
    * Text (Skripte, Web, Mail, Office, PDF): zeilenweiser Unified-Diff + Ähnlichkeit
    * PDF: welche Seiten wurden geändert / ergänzt / entfernt (Hash je Seiteninhalt)
    * Bild: Pixel-Differenz, Anteil geänderter Pixel, Regionen, Heatmap-PNG
    * sonst: geänderte Byte-Bereiche
report_diff(ra, rb)  – vergleicht zwei gespeicherte Analyse-Ergebnisse (ohne die Dateien):
    Metadaten, Signale, Urteil
"""
import difflib
import hashlib
from pathlib import Path

MAX_TEXT = 2 << 20
MAX_DIFF_LINES = 1500
PIXEL_THRESHOLD = 40            # Summe |ΔR|+|ΔG|+|ΔB| ab der ein Pixel als geändert gilt
BLOCK = 24


def _text_of(path, kind):
    p = Path(path)
    ext = p.suffix.lower()
    if ext in (".docx", ".docm", ".dotx", ".xlsx", ".xlsm", ".pptx", ".pptm"):
        from engines.sandbox_worker import _document_text
        return _document_text(str(p), ext)
    if kind == "pdf":
        return "\n".join(_pdf_pages(path)[1])
    raw = p.read_bytes()[:MAX_TEXT]
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    return raw.decode("utf-8", "replace")


def _pdf_pages(path):
    """→ (Hash je Seite, Text je Seite)."""
    import pikepdf
    hashes, texts = [], []
    with pikepdf.open(path) as pdf:
        for page in pdf.pages[:500]:
            try:
                data = page.obj.get("/Contents")
                if data is None:
                    raw = b""
                elif isinstance(data, pikepdf.Array):
                    raw = b"".join(s.read_bytes() for s in data)
                else:
                    raw = data.read_bytes()
            except Exception:
                raw = b""
            hashes.append(hashlib.sha256(raw).hexdigest()[:16])
            import re
            parts = re.findall(rb"\(((?:[^()\\]|\\.){1,400})\)\s*Tj|\[(.*?)\]\s*TJ", raw, re.S)
            txt = []
            for a, b in parts:
                if a:
                    txt.append(a.decode("latin-1"))
                elif b:
                    txt += [x.decode("latin-1") for x in re.findall(rb"\(((?:[^()\\]|\\.)*)\)", b)]
            texts.append(" ".join(txt).strip())
    return hashes, texts


def _text_diff(ta, tb):
    la, lb = ta.splitlines(), tb.splitlines()
    ud = list(difflib.unified_diff(la, lb, "A", "B", lineterm="", n=2))
    added = sum(1 for l in ud if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in ud if l.startswith("-") and not l.startswith("---"))
    sm = difflib.SequenceMatcher(None, ta[:200_000], tb[:200_000], autojunk=False)
    return {"added_lines": added, "removed_lines": removed, "similarity": round(sm.quick_ratio(), 3),
            "unified": ud[:MAX_DIFF_LINES], "truncated": len(ud) > MAX_DIFF_LINES}


def _image_diff(a, b, out_png=None):
    import numpy as np
    from PIL import Image
    with Image.open(a) as ia, Image.open(b) as ib:
        size_a, size_b = ia.size, ib.size
        A = np.asarray(ia.convert("RGB"), dtype=np.int16)
        ib2 = ib.convert("RGB")
        if ib2.size != ia.size:
            ib2 = ib2.resize(ia.size)
        B = np.asarray(ib2, dtype=np.int16)
    d = np.abs(A - B).sum(axis=2)
    mask = d > PIXEL_THRESHOLD
    h, w = mask.shape
    gh, gw = (h + BLOCK - 1) // BLOCK, (w + BLOCK - 1) // BLOCK
    pad = np.zeros((gh * BLOCK, gw * BLOCK), bool)
    pad[:h, :w] = mask
    blocks = pad.reshape(gh, BLOCK, gw, BLOCK).mean(axis=(1, 3)) > 0.02
    regions = _regions(blocks)
    out = {"size_a": list(size_a), "size_b": list(size_b), "resized": size_a != size_b,
           "changed_ratio": round(float(mask.mean()), 5), "max_delta": int(d.max()) if d.size else 0,
           "regions": [[x * BLOCK, y * BLOCK, min(w, (x2 + 1) * BLOCK) - x * BLOCK, min(h, (y2 + 1) * BLOCK) - y * BLOCK]
                       for x, y, x2, y2 in regions[:30]]}
    if out_png:
        base = (A.mean(axis=2) * 0.35).astype(np.uint8)
        rgb = np.stack([base, base, base], axis=2)
        inten = np.clip(d * 2, 0, 255).astype(np.uint8)
        rgb[..., 0] = np.maximum(rgb[..., 0], inten)
        img = Image.fromarray(rgb)
        img.thumbnail((1600, 1600))
        img.save(out_png, "PNG")
    return out


def _regions(blocks):
    """Zusammenhängende Block-Regionen (4er-Nachbarschaft) → Rechtecke (x, y, x2, y2) in Blöcken."""
    import numpy as np
    seen = np.zeros_like(blocks)
    out = []
    H, W = blocks.shape
    for y in range(H):
        for x in range(W):
            if blocks[y, x] and not seen[y, x]:
                stack, xs, ys = [(y, x)], [], []
                seen[y, x] = True
                while stack:
                    cy, cx = stack.pop()
                    xs.append(cx)
                    ys.append(cy)
                    for ny, nx in ((cy + 1, cx), (cy - 1, cx), (cy, cx + 1), (cy, cx - 1)):
                        if 0 <= ny < H and 0 <= nx < W and blocks[ny, nx] and not seen[ny, nx]:
                            seen[ny, nx] = True
                            stack.append((ny, nx))
                out.append((min(xs), min(ys), max(xs), max(ys), len(xs)))
    out.sort(key=lambda r: -r[4])
    return [r[:4] for r in out]


def _bytes_diff(a, b):
    da, db = Path(a).read_bytes()[:MAX_TEXT], Path(b).read_bytes()[:MAX_TEXT]
    sm = difflib.SequenceMatcher(None, da, db, autojunk=False) if max(len(da), len(db)) < 400_000 else None
    ranges = []
    if sm:
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag != "equal" and len(ranges) < 50:
                ranges.append({"op": tag, "a": [i1, i2], "b": [j1, j2]})
    return {"size_a": len(da), "size_b": len(db), "similarity": round(sm.ratio(), 3) if sm else None,
            "ranges": ranges}


def content_diff(a, b, out_png=None):
    from core.filetype import identify
    fa, fb = identify(a), identify(b)
    ha = hashlib.sha256(Path(a).read_bytes()).hexdigest()
    hb = hashlib.sha256(Path(b).read_bytes()).hexdigest()
    out = {"identical": ha == hb, "sha256": [ha, hb], "type_a": fa["description"], "type_b": fb["description"],
           "category": fa["category"] if fa["category"] == fb["category"] else "mixed"}
    if out["identical"]:
        return out
    cat = out["category"]
    try:
        if cat == "image":
            out["image"] = _image_diff(a, b, out_png)
        elif cat == "pdf":
            pa, ta = _pdf_pages(a)
            pb, tb = _pdf_pages(b)
            pages = []
            for i in range(max(len(pa), len(pb))):
                if i >= len(pa):
                    pages.append({"page": i + 1, "status": "added"})
                elif i >= len(pb):
                    pages.append({"page": i + 1, "status": "removed"})
                elif pa[i] != pb[i]:
                    pages.append({"page": i + 1, "status": "changed",
                                  "text_similarity": round(difflib.SequenceMatcher(None, ta[i], tb[i]).ratio(), 3)})
            out["pdf"] = {"pages_a": len(pa), "pages_b": len(pb), "pages": pages}
            out["text"] = _text_diff("\n".join(ta), "\n".join(tb))
        elif cat in ("text", "script", "web", "email", "document") or fa.get("is_text"):
            out["text"] = _text_diff(_text_of(a, cat), _text_of(b, cat))
        else:
            out["bytes"] = _bytes_diff(a, b)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# ── Befund-Vergleich (ohne Dateien) ─────────────────────────────────────────
def report_diff(ra, rb):
    ma = ((ra.get("report") or {}).get("metadata") or {})
    mb = ((rb.get("report") or {}).get("metadata") or {})
    ma = ma if isinstance(ma, dict) else {}
    mb = mb if isinstance(mb, dict) else {}
    meta = []
    for k in sorted(set(ma) | set(mb)):
        if str(k).startswith("piexif."):
            continue
        va, vb = ma.get(k), mb.get(k)
        if va != vb:
            status = "added" if k not in ma else "removed" if k not in mb else "changed"
            meta.append({"key": k, "a": None if va is None else str(va)[:300],
                         "b": None if vb is None else str(vb)[:300], "status": status})
    fa = {(f.get("code"), f.get("desc")) for f in (ra.get("score") or {}).get("findings", [])}
    fb = {(f.get("code"), f.get("desc")) for f in (rb.get("score") or {}).get("findings", [])}
    sa, sb = ra.get("score") or {}, rb.get("score") or {}
    return {"metadata": meta,
            "findings_added": sorted([{"code": c, "desc": d} for c, d in fb - fa], key=lambda x: x["code"] or ""),
            "findings_removed": sorted([{"code": c, "desc": d} for c, d in fa - fb], key=lambda x: x["code"] or ""),
            "verdict": [f"{sa.get('level')} {sa.get('score')}", f"{sb.get('level')} {sb.get('score')}"]}
