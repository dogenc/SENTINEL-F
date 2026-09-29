"""
Dokument-Stammbaum: welche Dateien im Verlauf stammen voneinander ab?

Beziehungen (mit Begründung):
  ancestor   – die andere Datei ist eine FRÜHERE Fassung / Quelle dieser Datei
  descendant – die andere Datei ist eine SPÄTERE Fassung / davon abgeleitet
  sibling    – gleicher Ursprung, aber getrennt weiterbearbeitet (Zweig)

Belege: PDF-/ID (permanente ID + Speicherstände), XMP DerivedFrom/History/
OriginalDocumentID, Word rsidRoot + RSID-Teilmengen.
"""

EXACT_KINDS = ("pdf_id0", "xmp_orig", "rsid_root")
GENERIC_LIMIT = 15           # teilen mehr Dateien eine ID, ist es eine Vorlage/ein Generator – keine Herkunft


def _candidates(db, me):
    ids = set()
    for k in EXACT_KINDS:
        if me.get(k):
            hit = {r["analysis_id"] for r in db._query(
                "SELECT analysis_id FROM fingerprints WHERE kind = ? AND value = ?", (k, me[k]))}
            if len(hit) <= GENERIC_LIMIT:
                ids |= hit
    mine = [v for v in (me.get("xmp_doc"), me.get("xmp_inst")) if v]
    back = list(me.get("xmp_derived") or []) + list(me.get("xmp_hist") or [])
    if mine:
        m = ",".join("?" * len(mine))
        ids |= {r["analysis_id"] for r in db._query(
            f"SELECT analysis_id FROM fingerprints WHERE kind IN ('xmp_derived','xmp_hist') AND value IN ({m})", mine)}
    if back:
        m = ",".join("?" * len(back))
        ids |= {r["analysis_id"] for r in db._query(
            f"SELECT analysis_id FROM fingerprints WHERE kind IN ('xmp_doc','xmp_inst') AND value IN ({m})", back)}
    return ids


def _saves(db, aid):
    res = db.get_result(aid) or {}
    lin = (((res.get("report") or {}).get("analyzers") or {}).get("lineage") or {})
    meta = (res.get("report") or {}).get("metadata") or {}
    return lin.get("pdf_saves") or 1, str(meta.get("ModDate") or meta.get("Modified") or "")


def relation(db, my_id, me, other_id, other):
    """→ (beziehung, begründung) oder None."""
    back = set(me.get("xmp_derived") or []) | set(me.get("xmp_hist") or [])
    oback = set(other.get("xmp_derived") or []) | set(other.get("xmp_hist") or [])
    mine = {v for v in (me.get("xmp_doc"), me.get("xmp_inst")) if v}
    theirs = {v for v in (other.get("xmp_doc"), other.get("xmp_inst")) if v}
    if theirs & back:
        return "ancestor", "XMP: this file lists it as source (DerivedFrom/History)"
    if mine & oback:
        return "descendant", "XMP: it lists this file as its source (DerivedFrom/History)"
    if me.get("rsid_root") and me.get("rsid_root") == other.get("rsid_root"):
        a, b = set(me.get("rsids") or []), set(other.get("rsids") or [])
        if a == b:
            # identische Sitzungen: beide unbearbeitet aus derselben Vorlage – kein Herkunftsbeleg
            return None
        if b and a and b < a:
            return "ancestor", f"Word: same origin (rsidRoot {me['rsid_root']}); its {len(b)} editing sessions " \
                               f"are all contained here plus {len(a - b)} later ones"
        if a and b and a < b:
            return "descendant", f"Word: same origin (rsidRoot {me['rsid_root']}); contains all {len(a)} sessions of " \
                                 f"this file plus {len(b - a)} later ones"
        shared = len(a & b)
        return "sibling", f"Word: same origin document or template (rsidRoot {me['rsid_root']}), {shared} shared " \
                          f"editing sessions, then edited separately"
    if me.get("pdf_id0") and me.get("pdf_id0") == other.get("pdf_id0"):
        (s1, d1), (s2, d2) = _saves(db, my_id), _saves(db, other_id)
        why = f"PDF: same permanent document ID {me['pdf_id0'][:12]}…"
        if s2 < s1 or (s1 == s2 and d2 and d1 and d2 < d1):
            return "ancestor", f"{why}; earlier version ({s2} vs {s1} saves)"
        if s2 > s1 or (s1 == s2 and d2 and d1 and d2 > d1):
            return "descendant", f"{why}; later version ({s2} vs {s1} saves)"
        return "sibling", f"{why}; parallel version"
    if me.get("xmp_orig") and me.get("xmp_orig") == other.get("xmp_orig"):
        return "sibling", "XMP: same OriginalDocumentID – both derived from one original"
    return None


def relatives(db, analysis_id):
    """Verwandte Dokumente einer Analyse (ohne identische Kopien)."""
    me = db.lineage_for(analysis_id)
    if not me:
        return []
    row = db._query("SELECT sha256 FROM analyses WHERE id = ?", (analysis_id,))
    my_sha = row[0]["sha256"] if row else None
    out, seen = [], set()
    for oid in sorted(_candidates(db, me) - {analysis_id}):
        r = db._query("SELECT a.id, a.name, a.path, a.sha256, a.level, a.score, a.analyzed_at, c.name AS case_name "
                      "FROM analyses a LEFT JOIN cases c ON c.id = a.case_id WHERE a.id = ?", (oid,))
        if not r or r[0]["sha256"] == my_sha or r[0]["sha256"] in seen:
            continue
        rel = relation(db, analysis_id, me, oid, db.lineage_for(oid))
        if rel:
            seen.add(r[0]["sha256"])
            out.append(dict(r[0], relation=rel[0], evidence=rel[1]))
    order = {"ancestor": 0, "sibling": 1, "descendant": 2}
    out.sort(key=lambda x: (order[x["relation"]], x["analyzed_at"]))
    return out
