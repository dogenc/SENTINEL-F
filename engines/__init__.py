"""
Engines facade — exposes a unified forensic-run entry-point.

Ablauf je Datei:
  1. Stat, Hashes, Typerkennung (Magic Bytes, unabhängig von der Endung)
  2. Klassische Tiefen-Engine, falls zuständig (Bild / PDF / Office)
  3. Universelle Analysatoren (engines/analyzers) – laufen für JEDE Datei
  4. Gemeinsames Scoring aller Findings
"""
import datetime

from core.utils import (
    all_hashes, file_stat_snapshot, detect_file_type, route_file
)
from core.filetype import identify
from .score_engine import ScoreEngine
from config.settings import T as THEME
from .analyzers import FileContext, run_all, default_analyzers
from .attack import map_findings
from .timeline import build_timeline
from . import similarity
from . import payloads as payload_chain

# Kategorie aus core.filetype → "kind" für GUI/Report, wenn keine klassische Engine greift
KIND_BY_CATEGORY = {
    "executable": "executable", "archive": "archive", "container": "archive", "script": "script",
    "web": "web", "email": "email", "database": "database", "shortcut": "shortcut", "media": "media",
    "text": "text", "rtf": "rtf", "system": "system", "capture": "capture", "font": "font",
    "crypto": "crypto", "image": "image", "pdf": "pdf", "document": "document", "ole": "document",
    "binary": "binary",
}

# Kurzlabels für die Zusammenfassung (Quelle → Bedrohungsfamilie)
FAMILY_LABELS = {
    "archive": "Archiv/Zipbomb", "pe": "Windows-Programm", "elf": "Linux-Programm", "script": "Skript",
    "web": "Web/Phishing", "lnk": "Verknüpfung", "rtf": "RTF-Exploit", "email": "E-Mail",
    "yara": "YARA", "baseline": "Datei-Tarnung/IOCs", "sqlite": "Datenbank", "sandbox": "Sandbox",
}


def _legacy_image(path, progress_fn, log):
    from .image_engine import ImageForensicEngine
    eng = ImageForensicEngine(path, log_fn=log)
    report = eng.run_full_analysis(progress_fn)
    # normalize report keys so ScoreEngine is happy
    rep = report
    normalized = {
        "metadata":   rep.get("metadata") or {},
        "consistency": {
            "issues": [
                {"msg": f["detail"], "severity": f["severity"].upper() if f["severity"] else "WARN"}
                for f in (rep.get("findings") or [])
                if f.get("type") in ("METADATA", "THUMBNAIL", "HISTORY", "SOFTWARE")
            ]
        },
        "ela":        rep.get("ela") or {},
        "jpeg_ghost": rep.get("jpeg_ghost") or {},
        "clone":      rep.get("clones") or {},
        "lsb":        rep.get("lsb") or {},
    }
    # lsb suspicious flag
    lsb = rep.get("lsb") or {}
    if lsb:
        total_anom = lsb.get("anomaly_score", 0)
        normalized["lsb"]["suspicious"] = total_anom > 0.15
        normalized["lsb"]["score"] = total_anom
    return report, ScoreEngine().score_image(normalized)


def _legacy_pdf(path, progress_fn, log):
    from .pdf_engine import RawPDFParser, PIKEPDF_OK
    parser = RawPDFParser(path)
    info = parser.find_info_dict()
    report = {
        "info": {
            "version":       parser.get_version(),
            "page_count":    parser.count_pages(),
            "is_encrypted":  parser.is_encrypted(),
            "has_javascript": parser.has_javascript(),
        },
        "metadata":         info,
        "redactions":       parser.find_redaction_annotations(),
        "embedded_images":  parser.find_embedded_images(),
        "links":            parser.find_links(),
        "black_rectangles": parser.count_black_rectangles(),
        "text_sample":      parser.extract_text_raw()[:400] if progress_fn else "",
    }
    if progress_fn:
        progress_fn("PDF deep scan", 60)

    # Unused-object detection (via pikepdf if available)
    if PIKEPDF_OK:
        try:
            import pikepdf
            with pikepdf.open(path) as pdf:
                referenced = set()
                def walk(obj, seen=None):
                    seen = seen or set()
                    oid = id(obj)
                    if oid in seen:
                        return
                    seen.add(oid)
                    try:
                        if isinstance(obj, pikepdf.Dictionary):
                            for k, v in obj.items():
                                walk(v, seen)
                        elif isinstance(obj, pikepdf.Array):
                            for v in obj:
                                walk(v, seen)
                        if hasattr(obj, "objgen"):
                            referenced.add(obj.objgen)
                    except Exception:
                        pass
                walk(pdf.trailer)
                all_objs = {o.objgen for o in pdf.objects}
                unused = all_objs - referenced
                report["unused_objects"] = len(unused)
        except Exception:
            report["unused_objects"] = 0
    else:
        report["unused_objects"] = 0

    return report, ScoreEngine().score_pdf(report)


def _legacy_document(path, progress_fn, log):
    from .document_engine import DocumentForensicEngine
    eng = DocumentForensicEngine(path, log_fn=log)
    rep = eng.run_full_analysis(progress_fn)

    # normalize for scoring — the document engine returns mixed
    # list/dict shapes, so we coerce defensively here.
    def _as_list(x):
        if x is None:           return []
        if isinstance(x, list): return x
        if isinstance(x, dict):
            for k in ("items", "objects", "revisions", "external", "entries"):
                if isinstance(x.get(k), list):
                    return x[k]
            # fall back to values if the dict looks like a collection
            vals = [v for v in x.values() if isinstance(v, list)]
            return vals[0] if vals else []
        return []

    def _as_dict(x):
        return x if isinstance(x, dict) else {}

    macros = _as_dict(rep.get("macros"))
    ext_rels = []
    rel_raw = rep.get("relationships")
    if isinstance(rel_raw, dict):
        ext_rels = rel_raw.get("external") or []
    elif isinstance(rel_raw, list):
        # engine returns a flat list of rel dicts — filter by target mode
        ext_rels = [r for r in rel_raw
                    if isinstance(r, dict) and
                    (r.get("TargetMode") == "External" or r.get("external"))]

    normalized = {
        "macros": {
            "has_macros": bool(macros.get("has_macros") or
                               macros.get("vba_modules")),
            "suspicious_keywords": macros.get("suspicious_keywords", []),
        },
        "hidden":        {"count": len(_as_list(rep.get("hidden_content")))},
        "objects":       {"count": len(_as_list(rep.get("embedded_objects")))},
        "relationships": {"external": ext_rels},
        "revisions":     {"count": len(_as_list(rep.get("revision_history")))},
        "entropy":       {"overall": _as_dict(rep.get("entropy")).get("overall", 0)},
    }
    return rep, ScoreEngine().score_document(normalized)


LEGACY = {"image": _legacy_image, "pdf": _legacy_pdf, "document": _legacy_document}


def _threat_summary(score):
    findings = [f for f in score.get("findings", []) if f.get("severity") in ("WARN", "CRIT")]
    families = []
    for f in sorted(findings, key=lambda x: -x.get("weight", 0)):
        label = FAMILY_LABELS.get(f.get("source"), None)
        if label and label not in families:
            families.append(label)
    top = max(findings, key=lambda x: x.get("weight", 0), default=None)
    return {
        "verdict": score.get("level"),
        "score": score.get("score"),
        "critical": sum(1 for f in findings if f["severity"] == "CRIT"),
        "warnings": sum(1 for f in findings if f["severity"] == "WARN"),
        "families": families,
        "headline": top["desc"] if top else "Keine auffälligen Indikatoren",
    }


def run_forensic(path, progress_fn=None, log_fn=None, analyzers=None, _depth=0, _budget=None):
    """
    Route a file to its forensic engine, run the universal analyzers, then score.

    Returns:
        {
          'ok':       bool,
          'kind':     'image'|'pdf'|'document'|'archive'|'executable'|'script'|…,
          'file':     stat snapshot dict,
          'hashes':   {md5, sha1, sha256},
          'magic':    (category, subtype, hex),
          'filetype': core.filetype.identify() result,
          'report':   engine-specific dict + report['analyzers'][name],
          'score':    {score, level, color, findings, top, total_signals},
          'threat':   {verdict, score, critical, warnings, families, headline},
          'attack':   MITRE ATT&CK techniques + tactic counts (engines/attack.py),
          'timeline': all timestamps + contradictions (engines/timeline.py),
          'payloads': tree of extracted stages, each fully analysed (engines/payloads.py),
          'fingerprints': {tlsh, imphash, rich} for similarity search (engines/similarity.py),
          'error':    str or None,
        }
    """
    log = log_fn or (lambda m, l="INFO": None)
    out = {"ok": False, "kind": "unknown", "file": None, "hashes": None,
           "magic": None, "filetype": None, "report": None, "score": None, "threat": None, "error": None,
           "timestamp": datetime.datetime.now().isoformat(sep=" ", timespec="seconds")}

    try:
        if progress_fn:
            progress_fn("Reading file stat", 2)
        out["file"] = file_stat_snapshot(path)

        if progress_fn:
            progress_fn("Computing cryptographic hashes", 5)
        out["hashes"] = all_hashes(path)

        if progress_fn:
            progress_fn("Detecting file type", 8)
        out["magic"] = detect_file_type(path)
        ft = identify(path)
        out["filetype"] = ft
        # Der echte Inhalt entscheidet, nicht die Endung: route_file() fällt sonst
        # bei getarnten Dateien (EXE als .pdf) auf die Endung zurück.
        if ft["category"] in ("image", "pdf", "document", "ole"):
            kind = route_file(path)
            if kind == "unknown":
                kind = KIND_BY_CATEGORY[ft["category"]]
        else:
            kind = KIND_BY_CATEGORY.get(ft["category"], "binary")
        out["kind"] = kind
        log(f"File classified as: {kind} ({ft['description']})", "OK")

        report, legacy_score = {}, None
        if kind in LEGACY:
            try:
                report, legacy_score = LEGACY[kind](path, progress_fn, log)
            except Exception as e:
                # Präparierte Dateien dürfen die Bedrohungsanalyse nicht verhindern
                import traceback
                report = {"legacy_error": f"{type(e).__name__}: {e}"}
                out["traceback"] = traceback.format_exc()
                log(f"{kind} engine failed: {e} — continuing with threat analysis", "WARN")

        if progress_fn:
            progress_fn("Universal threat analysis", 70)
        ctx = FileContext(path, ft)
        data, findings = run_all(ctx, analyzers if analyzers is not None else default_analyzers(),
                                 log=log, progress=progress_fn, start=70, end=97)
        report = report if isinstance(report, dict) else {"engine_report": report}
        report["analyzers"] = data
        out["report"] = report

        # Payload-Kette: versteckte Stufen extrahieren und rekursiv analysieren
        budget = _budget or payload_chain.Budget()
        if progress_fn:
            progress_fn("Payload chain", 97)
        tree, parent_f, child_f = payload_chain.expand(
            path, ft, report, _depth, budget,
            lambda p, d, b: run_forensic(p, analyzers=analyzers, _depth=d, _budget=b))
        findings = list(findings) + parent_f
        out["payloads"] = tree
        if tree:
            log(f"Payload chain: {sum(1 for _ in payload_chain.flatten(tree))} stage(s) analysed", "INFO")

        base = (legacy_score or {}).get("findings")
        out["score"] = ScoreEngine().score_findings(findings, base=base)
        worst = max((n.get("score") or 0 for n in tree), default=0)
        if worst > out["score"]["score"]:
            # Gefahr erbt: ein Behälter ist nie harmloser als seine gefährlichste Stufe
            eng = ScoreEngine()
            level, key = eng._level_for(worst)
            out["score"].update(score=worst, level=level, color_key=key,
                                color=THEME[key], inherited=True)
        out["threat"] = _threat_summary(out["score"])
        out["attack"] = map_findings(out["score"]["findings"] + child_f)
        if _depth:
            out["_payload_findings"] = child_f          # Enkel-Stufen an die Wurzel weiterreichen
        out["fingerprints"] = {"tlsh": similarity.compute(path), "prnu": ctx.shared.get("prnu")}
        out["fingerprints"] = similarity.fingerprints(out)
        try:
            out["timeline"] = build_timeline(out)
        except Exception as e:                      # Zeitleiste ist Beiwerk, nie ein Abbruchgrund
            log(f"timeline failed: {e}", "WARN")

        if progress_fn:
            progress_fn("Scoring complete", 100)
        out["ok"] = True
        return out

    except Exception as e:
        import traceback
        out["error"] = f"{type(e).__name__}: {e}"
        out["traceback"] = traceback.format_exc()
        log(out["error"], "ERR")
        return out
