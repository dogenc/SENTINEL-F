"""
Forensische Berichte (HTML, optional PDF) – je Datei oder je Fall.

Grundsätze:
  * eigenständig: kein JavaScript, keine externen Ressourcen, offline lesbar
  * alles, was aus der untersuchten Datei stammt, wird HTML-escaped
  * IOCs werden entschärft (hxxp, [.]) – niemand klickt versehentlich auf C2
  * Beweiskette: SHA-256 zum Analysezeitpunkt, beim Berichtserstellen erneut
    geprüft; neben dem Bericht wird <bericht>.sha256 geschrieben
  * Vorschaubild nur aus der Sandbox (neu kodiertes PNG), nie das Original
  * das HTML nutzt nur Tabellen/Inline-Stile, damit Qt es 1:1 als PDF druckt
"""
import base64
import datetime
import getpass
import hashlib
import html
import platform
import uuid
from pathlib import Path

from config.settings import APP_NAME, APP_VERSION, APP_CODENAME, SCORE_LEVELS

SEV_COLOR = {"CRIT": "#c4001d", "WARN": "#b36b00", "INFO": "#56606b"}
LEVEL_COLOR = {"CLEAN": "#1b7f3b", "LOW RISK": "#4d7f1b", "ELEVATED": "#b36b00",
               "HIGH RISK": "#c44a00", "CRITICAL": "#c4001d"}
IOC_TYPES = ("url", "domain", "ipv4", "email", "onion", "btc", "xmr", "unc_path", "registry")


def esc(v):
    return html.escape("" if v is None else str(v), quote=True)


def defang(v):
    s = str(v)
    for a, b in (("https://", "hxxps://"), ("http://", "hxxp://"), ("ftp://", "fxp://")):
        s = s.replace(a, b).replace(a.upper(), b)
    if "@" in s and "://" not in s:
        s = s.replace("@", "[@]")
    return s.replace(".", "[.]")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_custody(result):
    """SHA-256 der Datei jetzt erneut bilden (nur Hash, kein Parsen) und vergleichen."""
    fi = result.get("file") or {}
    want = ((result.get("hashes") or {}).get("sha256") or "").lower()
    path = fi.get("path")
    now = datetime.datetime.now().isoformat(sep=" ", timespec="seconds")
    if not path or not Path(path).is_file():
        return {"status": "UNAVAILABLE", "checked_at": now, "detail": "File no longer at the recorded path"}
    try:
        got = sha256_file(path)
    except OSError as e:
        return {"status": "UNAVAILABLE", "checked_at": now, "detail": str(e)}
    if got == want:
        return {"status": "MATCH", "checked_at": now, "detail": "File unchanged since analysis", "sha256": got}
    return {"status": "MISMATCH", "checked_at": now, "sha256": got,
            "detail": "File CHANGED since analysis – re-analyse before relying on this report"}


# ── Bausteine ────────────────────────────────────────────────────────────────
CSS = """
body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 10pt; color: #1b2330; background: #ffffff;
       margin: 24px; }
h1 { font-size: 18pt; margin: 0 0 2px 0; color: #0b1320; }
h2 { font-size: 12.5pt; margin: 22px 0 6px 0; padding-bottom: 3px; border-bottom: 2px solid #0b1320;
     color: #0b1320; }
h3 { font-size: 11pt; margin: 14px 0 4px 0; color: #0b1320; }
table { border-collapse: collapse; width: 100%; margin: 4px 0 8px 0; }
th { background: #e9edf2; text-align: left; padding: 4px 6px; font-size: 8.5pt; color: #3a4452;
     border: 1px solid #cfd6de; }
td { padding: 4px 6px; border: 1px solid #dde2e8; vertical-align: top; font-size: 9pt; }
td.k { width: 190px; color: #56606b; background: #f6f8fa; }
.mono { font-family: Consolas, 'DejaVu Sans Mono', monospace; font-size: 8.5pt; }
.muted { color: #6b7684; }
.small { font-size: 8pt; }
a { color: #0b57d0; }
"""


def _kv(rows):
    out = ['<table>']
    for k, v, *mono in rows:
        cls = ' class="mono"' if mono and mono[0] else ""
        out.append(f'<tr><td class="k">{esc(k)}</td><td{cls}>{v}</td></tr>')
    out.append("</table>")
    return "".join(out)


def _verdict_box(result):
    sc, th = result.get("score") or {}, result.get("threat") or {}
    level = sc.get("level") or th.get("verdict") or "—"
    col = LEVEL_COLOR.get(level, "#56606b")
    fam = " · ".join(th.get("families") or []) or "—"
    return (f'<table><tr><td style="background:{col}; color:#ffffff; width:190px; text-align:center;'
            f' font-size:15pt; font-weight:bold; padding:10px;">{esc(level)}<br>'
            f'<span style="font-size:10pt;">{esc(sc.get("score", "—"))} / 100</span></td>'
            f'<td style="padding:10px;"><b>{esc(th.get("headline") or "—")}</b><br>'
            f'<span class="muted">{esc(th.get("critical", 0))} critical · {esc(th.get("warnings", 0))} warnings'
            f' · areas: {esc(fam)}</span></td></tr></table>')


def _findings(result, limit=None):
    fs = [f for f in (result.get("score") or {}).get("findings", []) if isinstance(f, dict)]
    fs.sort(key=lambda f: ({"CRIT": 0, "WARN": 1}.get(f.get("severity"), 2), -(f.get("weight") or 0)))
    if limit:
        fs = fs[:limit]
    if not fs:
        return '<p class="muted">No findings.</p>'
    rows = "".join(
        f'<tr><td style="color:{SEV_COLOR.get(f.get("severity"), "#333")}; font-weight:bold;">'
        f'{esc(f.get("severity"))}</td><td class="mono">{esc(f.get("code"))}</td>'
        f'<td>{esc(f.get("desc"))}</td><td>{esc(f.get("source") or "")}</td>'
        f'<td style="text-align:right;">{esc(f.get("weight", ""))}</td></tr>' for f in fs)
    return ('<table><tr><th>SEV</th><th>CODE</th><th>EVIDENCE</th><th>SOURCE</th><th>WEIGHT</th></tr>'
            f'{rows}</table>')


def _attack(result):
    from engines.attack import map_result
    techs = map_result(result)["techniques"]
    if not techs:
        return '<p class="muted">No signal maps to a MITRE ATT&amp;CK technique.</p>'
    rows = "".join(
        f'<tr><td class="mono"><a href="{esc(t["url"])}">{esc(t["id"])}</a></td><td>{esc(t["name"])}</td>'
        f'<td>{esc(", ".join(t["tactics"]))}</td>'
        f'<td style="color:{SEV_COLOR.get(t["severity"], "#333")};">{esc(t["severity"])}</td>'
        f'<td class="mono small">{esc(", ".join(t["codes"]))}</td></tr>' for t in techs)
    return ('<table><tr><th>TECHNIQUE</th><th>NAME</th><th>TACTIC(S)</th><th>SEV</th><th>SIGNALS</th></tr>'
            f'{rows}</table><p class="small muted">Static indicators mapped to ATT&amp;CK – not observed behaviour.</p>')


def _timeline(result):
    from engines.timeline import build_timeline
    try:
        tl = result.get("timeline") or build_timeline(result)
    except Exception:
        return '<p class="muted">Timeline unavailable.</p>'
    out = []
    for a in tl["anomalies"]:
        col = SEV_COLOR["CRIT"] if a["severity"] == "WARN" else SEV_COLOR["INFO"]
        out.append(f'<p style="color:{col}; margin:2px 0;"><b>{"⚠" if a["severity"] == "WARN" else "ℹ"}</b> '
                   f'{esc(a["desc"])}</p>')
    if not tl["anomalies"]:
        out.append('<p class="muted">No timestamp contradictions.</p>')
    rows = "".join(f'<tr><td class="mono">{esc(e["ts"])}</td><td>{esc(e["source"])}</td><td>{esc(e["label"])}</td>'
                   f'<td class="mono small">{esc(e["raw"])}</td></tr>' for e in tl["events"])
    out.append(f'<table><tr><th>TIME (local)</th><th>SOURCE</th><th>EVENT</th><th>RAW</th></tr>{rows}</table>')
    return "".join(out)


def _iocs(result):
    iocs = ((((result.get("report") or {}).get("analyzers") or {}).get("baseline") or {}).get("iocs") or {})
    rows = []
    for t in IOC_TYPES:
        for v in (iocs.get(t) or [])[:40]:
            if isinstance(v, str):
                rows.append(f'<tr><td>{esc(t)}</td><td class="mono">{esc(defang(v))}</td></tr>')
    if not rows:
        return '<p class="muted">No network or host indicators extracted.</p>'
    return ('<table><tr><th>TYPE</th><th>INDICATOR (defanged)</th></tr>' + "".join(rows) + '</table>')


def _narrative(result, similar):
    from engines import detective
    ev = detective.build_evidence(result, similar=similar)
    text = detective.narrative(ev, lang="en")
    lines = "".join(f"<p style=\"margin:3px 0;\">{esc(l)}</p>" for l in text.splitlines())
    items = "".join(f'<tr><td class="mono">{esc(e["id"])}</td><td>{esc(e["kind"])}</td><td>{esc(e["text"])}</td></tr>'
                    for e in ev)
    return (f'{lines}<p class="small muted">Rule-based and deterministic: every statement cites the evidence '
            f'items below.</p><table><tr><th>ID</th><th>KIND</th><th>EVIDENCE</th></tr>{items}</table>')


def _chain(result):
    from engines.payloads import flatten
    rows = list(flatten(result.get("payloads")))
    if not rows:
        return '<p class="muted">No hidden stages found.</p>'
    body = "".join(
        f'<tr><td style="padding-left:{6 + 18 * (d - 1)}px;">{"└ " if d > 1 else ""}{esc(n.get("name"))}</td>'
        f'<td>{esc(n.get("source"))}</td><td>{esc(n.get("true_type") or n.get("kind"))}</td>'
        f'<td style="color:{LEVEL_COLOR.get(n.get("level"), "#333")}; font-weight:bold;">{esc(n.get("level"))} '
        f'{esc(n.get("score"))}</td><td class="mono small">{esc((n.get("sha256") or "")[:16])}…</td>'
        f'<td>{esc(n.get("cause") or n.get("error") or "")}</td></tr>' for d, n in rows)
    return ('<table><tr><th>STAGE</th><th>FOUND AS</th><th>TRUE TYPE</th><th>VERDICT</th><th>SHA-256</th>'
            f'<th>CAUSE</th></tr>{body}</table><p class="small muted">Extracted in memory and analysed; '
            'nothing was executed.</p>')


def _similar(rows):
    if not rows:
        return '<p class="muted">No similar file in the local history.</p>'
    body = "".join(
        f'<tr><td>{esc(r.get("name"))}</td><td>{esc("TLSH " + str(r["distance"]) if r.get("distance") is not None else ("camera noise r=" + str(r["ncc"])) if r.get("ncc") is not None else "exact")}</td>'
        f'<td>{esc(", ".join(r.get("match") or []))}</td><td>{esc(r.get("level"))} {esc(r.get("score"))}</td>'
        f'<td>{esc(r.get("case_name") or "—")}</td><td class="mono small">{esc((r.get("sha256") or "")[:16])}…</td></tr>'
        for r in rows)
    return ('<table><tr><th>FILE</th><th>SIMILARITY</th><th>MATCHED BY</th><th>VERDICT</th><th>CASE</th><th>SHA-256</th></tr>'
            f'{body}</table>')


def _preview(result):
    sb = result.get("sandbox") or {}
    png = sb.get("preview_png")
    if not (sb.get("isolated") and png and Path(png).is_file()):
        return ""
    try:
        data = Path(png).read_bytes()
    except OSError:
        return ""
    if len(data) > 4 << 20 or not data.startswith(b"\x89PNG"):
        return ""
    return (f'<h2>Preview</h2><p class="small muted">Re-encoded inside the sandbox – the original file was never '
            f'rendered by the report.</p><img src="data:image/png;base64,{base64.b64encode(data).decode()}" '
            f'width="420">')


def _header(title, subtitle, examiner, report_id):
    now = datetime.datetime.now().isoformat(sep=" ", timespec="seconds")
    return (f'<table><tr><td style="border:none; padding:0;"><h1>{esc(title)}</h1>'
            f'<span class="muted">{esc(subtitle)}</span></td>'
            f'<td style="border:none; text-align:right; padding:0;" class="small muted">'
            f'{esc(APP_CODENAME)} · {esc(APP_NAME)} v{esc(APP_VERSION)}<br>Report ID {esc(report_id)}<br>'
            f'Generated {esc(now)}<br>Examiner: {esc(examiner or "—")}</td></tr></table>')


def _footer():
    return ('<p class="small muted" style="margin-top:24px;">Heuristic scores and mappings are indicators, '
            'not proof. Verify critical findings manually. Indicators are defanged. This report contains no '
            'executable content. Integrity: compare the SHA-256 of this file with the accompanying '
            '<span class="mono">.sha256</span> file.</p>')


def _wrap(title, body):
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>{esc(title)}</title>'
            f'<style>{CSS}</style></head><body>{body}</body></html>')


# ── Datei-Bericht ────────────────────────────────────────────────────────────
def file_report_html(result, examiner="", similar=None, custody=None):
    fi, hs = result.get("file") or {}, result.get("hashes") or {}
    ft = result.get("filetype") or {}
    fp = result.get("fingerprints") or {}
    sb = result.get("sandbox") or {}
    custody = custody or verify_custody(result)
    rid = uuid.uuid4().hex[:12].upper()
    name = fi.get("name") or "—"
    cust_col = {"MATCH": "#1b7f3b", "MISMATCH": "#c4001d"}.get(custody["status"], "#b36b00")

    parts = [_header(f"Forensic Report · {name}", "Single-file analysis", examiner, rid),
             "<h2>Verdict</h2>", _verdict_box(result)]
    parts += ["<h2>Evidence item</h2>", _kv([
        ("File name", esc(name)), ("Recorded path", esc(fi.get("path")), True),
        ("Size", f'{esc(fi.get("size_h"))} ({esc(fi.get("size"))} bytes)'),
        ("True type", esc(ft.get("description") or result.get("kind"))),
        ("Extension", esc(fi.get("extension"))),
        ("MD5", esc(hs.get("md5")), True), ("SHA-1", esc(hs.get("sha1")), True),
        ("SHA-256", esc(hs.get("sha256")), True),
        ("TLSH", esc(fp.get("tlsh") or "—"), True), ("Imphash", esc(fp.get("imphash") or "—"), True),
        ("Rich header", esc(fp.get("rich") or "—"), True),
    ])]
    iso = ("Isolated worker · integrity {} · no child processes · RAM ≤ {} GiB · {} s".format(
        sb.get("integrity", "?"), (sb.get("memory_limit") or 0) >> 30, sb.get("seconds", "?"))
        if sb.get("isolated") else "Analysed in-process (sandbox not available on this platform)")
    hist = result.get("history") or {}
    parts += ["<h2>Chain of custody</h2>", _kv([
        ("Analysed at", esc(result.get("timestamp"))),
        ("Analysis environment", esc(iso)),
        ("Workstation / user", esc(f"{platform.node()} / {getpass.getuser()}")),
        ("History record", esc(f"#{hist['id']} (stored result)" if hist.get("id") else "live analysis")),
        ("SHA-256 at analysis", esc(hs.get("sha256")), True),
        ("Re-verified at report time", f'<b style="color:{cust_col};">{esc(custody["status"])}</b> · '
                                      f'{esc(custody["checked_at"])} · {esc(custody["detail"])}'),
        ("File modified / created (FS)", esc(f'{fi.get("modified", "—")} / {fi.get("created", "—")}')),
    ])]
    parts += ["<h2>Investigator narrative</h2>", _narrative(result, similar)]
    parts += ["<h2>Findings</h2>", _findings(result)]
    parts += ["<h2>Payload chain</h2>", _chain(result)]
    parts += ["<h2>MITRE ATT&amp;CK</h2>", _attack(result)]
    parts += ["<h2>Timeline</h2>", _timeline(result)]
    parts += ["<h2>Indicators of compromise</h2>", _iocs(result)]
    if similar is not None:
        parts += ["<h2>Similar files (local history)</h2>", _similar(similar)]
    if result.get("intel"):
        rows = "".join(f'<tr><td>{esc(k)}</td><td>{esc(v.get("status"))}</td><td>{esc(v.get("detail"))}</td></tr>'
                       for k, v in result["intel"].items() if not k.startswith("_"))
        parts += ["<h2>Threat intelligence (hash lookup)</h2>",
                  f'<table><tr><th>SERVICE</th><th>RESULT</th><th>DETAIL</th></tr>{rows}</table>'
                  '<p class="small muted">Only the SHA-256 was sent to these services.</p>']
    meta = (result.get("report") or {}).get("metadata")
    if isinstance(meta, dict) and meta:
        rows = [(k, esc(str(v)[:300])) for k, v in list(meta.items())[:60] if not str(k).startswith("piexif.")]
        parts += ["<h2>Metadata (excerpt)</h2>", _kv(rows)]
    parts.append(_preview(result))
    parts.append(_footer())
    return _wrap(f"{APP_CODENAME} report · {name}", "".join(parts))


# ── Fall-Bericht ─────────────────────────────────────────────────────────────
def case_report_html(db, case_id, examiner="", per_file_findings=5):
    from engines.attack import map_result
    from core.iocgraph import graph_from_db
    case = next((c for c in db.list_cases() if c["id"] == case_id), None)
    if case is None:
        raise ValueError(f"case {case_id} not found")
    rows = db.list_analyses(case_id=case_id, limit=5000)
    results = [(r, db.get_result(r["id"])) for r in rows]
    rid = uuid.uuid4().hex[:12].upper()
    levels = {}
    for r in rows:
        levels[r["level"]] = levels.get(r["level"], 0) + 1
    order = [lab for _, lab, _k in SCORE_LEVELS][::-1]
    dist = " · ".join(f'<b style="color:{LEVEL_COLOR.get(l, "#333")}">{esc(l)}</b> {levels[l]}'
                      for l in order if levels.get(l)) or "—"

    parts = [_header(f"Case Report · {case['name']}", case.get("description") or "Case summary", examiner, rid),
             "<h2>Summary</h2>", _kv([
                 ("Case", esc(case["name"])), ("Opened", esc(case["created_at"])),
                 ("Analyses", esc(len(rows))), ("Unique files", esc(len({r['sha256'] for r in rows}))),
                 ("Verdicts", dist), ("Highest score", esc(max((r["score"] or 0) for r in rows) if rows else "—")),
             ])]
    body = "".join(
        f'<tr><td class="mono small">{esc(r["analyzed_at"])}</td><td>{esc(r["name"])}</td>'
        f'<td style="color:{LEVEL_COLOR.get(r["level"], "#333")}; font-weight:bold;">{esc(r["level"])} {esc(r["score"])}</td>'
        f'<td>{esc(r["headline"])}</td><td class="mono small">{esc(r["sha256"][:16])}…</td></tr>'
        for r in sorted(rows, key=lambda r: -(r["score"] or 0)))
    parts += ["<h2>Evidence items</h2>",
              f'<table><tr><th>ANALYSED</th><th>FILE</th><th>VERDICT</th><th>HEADLINE</th><th>SHA-256</th></tr>{body}</table>']

    techs = {}
    for _r, res in results:
        for t in map_result(res or {})["techniques"]:
            if t["severity"] == "INFO":
                continue
            e = techs.setdefault(t["id"], dict(t, files=0))
            e["files"] += 1
    if techs:
        trs = "".join(f'<tr><td class="mono"><a href="{esc(t["url"])}">{esc(t["id"])}</a></td><td>{esc(t["name"])}</td>'
                      f'<td>{esc(", ".join(t["tactics"]))}</td><td style="text-align:right;">{t["files"]}</td></tr>'
                      for t in sorted(techs.values(), key=lambda t: -t["files"]))
        parts += ["<h2>MITRE ATT&amp;CK across the case</h2>",
                  f'<table><tr><th>TECHNIQUE</th><th>NAME</th><th>TACTIC(S)</th><th>FILES</th></tr>{trs}</table>']

    g = graph_from_db(db, case_id=case_id)
    parts.append("<h2>Shared infrastructure</h2>")
    if g["iocs"] or g["clusters"]:
        trs = "".join(f'<tr><td>{esc(i["type"])}</td><td class="mono">{esc(defang(i["value"]))}</td>'
                      f'<td>{esc(", ".join(g["files"][s]["name"] for s in i["files"]))}</td></tr>' for i in g["iocs"][:60])
        parts.append(f'<table><tr><th>TYPE</th><th>INDICATOR (defanged)</th><th>SEEN IN</th></tr>{trs}</table>')
        for c in g["clusters"]:
            parts.append(f'<p><b>{esc(c["name"])}</b> – {len(c["files"])} files, {len(c["iocs"])} shared IOCs, '
                         f'max score {esc(c["max_score"])}: {esc(", ".join(g["files"][s]["name"] for s in c["files"]))}</p>')
    else:
        parts.append('<p class="muted">No indicators shared between files of this case.</p>')

    parts.append("<h2>Per-file detail</h2>")
    for r, res in results:
        if not res:
            continue
        hs = res.get("hashes") or {}
        parts += [f'<h3>{esc(r["name"])}</h3>', _verdict_box(res),
                  _kv([("SHA-256", esc(hs.get("sha256")), True), ("Path", esc((res.get("file") or {}).get("path")), True),
                       ("Analysed", esc(r["analyzed_at"]))]),
                  _findings(res, limit=per_file_findings)]
    parts.append(_footer())
    return _wrap(f"{APP_CODENAME} case report · {case['name']}", "".join(parts))


# ── Schreiben ────────────────────────────────────────────────────────────────
def write_report(html_text, path):
    """HTML oder PDF (nach Endung) schreiben + <datei>.sha256. → SHA-256 des Berichts."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".pdf":
        _write_pdf(html_text, path)
    else:
        path.write_text(html_text, encoding="utf-8")
    digest = sha256_file(path)
    Path(str(path) + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return digest


def _write_pdf(html_text, path):
    from PyQt6.QtGui import QTextDocument, QPageSize, QPageLayout
    from PyQt6.QtCore import QMarginsF
    from PyQt6.QtPrintSupport import QPrinter
    printer = QPrinter(QPrinter.PrinterMode.HighResolution)
    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
    printer.setOutputFileName(str(path))
    printer.setPageLayout(QPageLayout(QPageSize(QPageSize.PageSizeId.A4), QPageLayout.Orientation.Portrait,
                                      QMarginsF(12, 12, 12, 12), QPageLayout.Unit.Millimeter))
    doc = QTextDocument()
    doc.setDocumentMargin(0)
    doc.setHtml(html_text.replace("margin: 24px;", "margin: 0;"))
    doc.setPageSize(printer.pageRect(QPrinter.Unit.Point).size())   # volle Druckbreite nutzen
    doc.print(printer)
