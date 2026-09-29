"""Vorher-Nachher-Vergleich zweier Analysen: Inhalt (aus der Sandbox), Seiten, Metadaten, Signale."""
import html
import threading
from pathlib import Path

from PyQt6.QtCore import Qt, QObject, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPixmap
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTabWidget, QTextEdit, QTableWidget,
    QTableWidgetItem, QAbstractItemView, QScrollArea
)

from config.settings import T, FONT_MONO
from engines.diff import report_diff

STATUS_COLOR = {"added": T["ok"], "removed": T["err"], "changed": T["warn"]}


class _Bridge(QObject):
    done = pyqtSignal(dict, str)


class DiffDialog(QDialog):
    def __init__(self, parent, res_a, res_b, diff_fn=None, run_async=True):
        super().__init__(parent)
        self.ra, self.rb = res_a, res_b
        self.diff_fn = diff_fn
        na, nb = (res_a.get("file") or {}).get("name", "A"), (res_b.get("file") or {}).get("name", "B")
        self.setWindowTitle(f"Compare · {na} ⇄ {nb}")
        self.resize(1250, 780)
        self.setStyleSheet(f"QDialog{{background:{T['bg_alt']};}} QLabel{{color:{T['text']};}}")
        lay = QVBoxLayout(self)
        self.lbl = QLabel()
        self.lbl.setWordWrap(True)
        self.lbl.setTextFormat(Qt.TextFormat.RichText)
        self.lbl.setStyleSheet(f"padding:8px; background:{T['card']}; border:1px solid {T['border']};")
        lay.addWidget(self.lbl)
        self.tabs = QTabWidget()
        self.txt_content = QTextEdit()
        self.txt_content.setReadOnly(True)
        self.txt_content.setFont(QFont(FONT_MONO, 9))
        self.tabs.addTab(self.txt_content, "CONTENT")
        self.img = QLabel("")
        self.img.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sc = QScrollArea()
        sc.setStyleSheet(f"QScrollArea, QLabel{{background:{T['bg']};}}")
        sc.setWidget(self.img)
        sc.setWidgetResizable(True)
        self.tabs.addTab(sc, "PIXEL HEATMAP")
        self.tbl_pages = self._table(["PAGE", "STATUS", "TEXT SIMILARITY"])
        self.tabs.addTab(self.tbl_pages, "PAGES")
        self.tbl_meta = self._table(["METADATA KEY", "A (before)", "B (after)", "STATUS"])
        self.tabs.addTab(self.tbl_meta, "METADATA")
        self.tbl_find = self._table(["CHANGE", "SIGNAL", "EVIDENCE"])
        self.tabs.addTab(self.tbl_find, "SIGNALS")
        lay.addWidget(self.tabs, stretch=1)
        row = QHBoxLayout()
        row.addStretch(1)
        close = QPushButton("CLOSE")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        lay.addLayout(row)
        self.content = None
        self._render_report()
        self.bridge = _Bridge()
        self.bridge.done.connect(self._render_content)
        self._start_content(run_async)

    def _table(self, headers):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.verticalHeader().setVisible(False)
        t.horizontalHeader().setStretchLastSection(True)
        t.setColumnWidth(0, 220)
        t.setColumnWidth(1, 330)
        t.setColumnWidth(2, 330)
        return t

    # ── Befund-Ebene ──────────────────────────────────────────────────
    def _render_report(self):
        d = report_diff(self.ra, self.rb)
        self.report = d
        self.tbl_meta.setRowCount(len(d["metadata"]))
        for i, m in enumerate(d["metadata"]):
            for c, v in enumerate([m["key"], m["a"] or "—", m["b"] or "—", m["status"]]):
                it = QTableWidgetItem(str(v))
                if c == 3:
                    it.setForeground(QColor(STATUS_COLOR[m["status"]]))
                self.tbl_meta.setItem(i, c, it)
        rows = [("new in B", f) for f in d["findings_added"]] + [("gone in B", f) for f in d["findings_removed"]]
        self.tbl_find.setRowCount(len(rows))
        for i, (what, f) in enumerate(rows):
            for c, v in enumerate([what, f["code"], f["desc"]]):
                it = QTableWidgetItem(str(v))
                if c == 0:
                    it.setForeground(QColor(T["ok"] if what.startswith("new") else T["err"]))
                self.tbl_find.setItem(i, c, it)
        self.tabs.setTabText(3, f"METADATA  {len(d['metadata'])}")
        self.tabs.setTabText(4, f"SIGNALS  +{len(d['findings_added'])} / −{len(d['findings_removed'])}")
        self._header()

    def _header(self, extra=""):
        fa, fb = self.ra.get("file") or {}, self.rb.get("file") or {}
        self.lbl.setText(
            f"<b>A</b> {html.escape(str(fa.get('name')))} · {html.escape(self.report['verdict'][0])} &nbsp;⇄&nbsp; "
            f"<b>B</b> {html.escape(str(fb.get('name')))} · {html.escape(self.report['verdict'][1])}<br>"
            f"{len(self.report['metadata'])} metadata difference(s) · {len(self.report['findings_added'])} new / "
            f"{len(self.report['findings_removed'])} vanished signal(s)" + extra)

    # ── Inhalts-Ebene (Sandbox) ───────────────────────────────────────
    def _start_content(self, run_async):
        pa, pb = (self.ra.get("file") or {}).get("path"), (self.rb.get("file") or {}).get("path")
        missing = [p for p in (pa, pb) if not p or not Path(p).is_file()]
        if missing:
            self.txt_content.setPlainText("Content comparison needs both files at their recorded paths.\n"
                                          f"Missing: {', '.join(str(m) for m in missing)}\n\n"
                                          "Metadata and signal differences (other tabs) are still available.")
            return
        self.txt_content.setPlainText("Comparing contents inside the sandbox …")
        fn = self.diff_fn
        if fn is None:
            from core.sandbox import diff_isolated as fn

        def work():
            try:
                res, png = fn(pa, pb)
            except Exception as e:
                res, png = {"error": f"{type(e).__name__}: {e}"}, None
            try:
                self.bridge.done.emit(res, png or "")
            except RuntimeError:              # Dialog wurde vor dem Ende geschlossen
                pass
        if run_async:
            threading.Thread(target=work, daemon=True).start()
        else:
            work()

    def _render_content(self, res, png):
        self.content = res
        parts = []
        # Hash-Gleichheit der Datei mit der Analyse prüfen (Datei seitdem verändert?)
        sha = res.get("sha256") or [None, None]
        for tag, r, s in (("A", self.ra, sha[0]), ("B", self.rb, sha[1] if len(sha) > 1 else None)):
            want = ((r.get("hashes") or {}).get("sha256") or "").lower()
            if s and want and s != want:
                parts.append(f"<span style='color:{T['err']}'>⚠ File {tag} changed since its analysis – "
                             "comparing the current file.</span>")
        if res.get("error"):
            parts.append(f"<span style='color:{T['err']}'>Content comparison failed: {html.escape(res['error'])}</span>")
        if res.get("identical"):
            parts.append(f"<span style='color:{T['ok']}'>Contents are byte-identical.</span>")
        body = []
        if res.get("text"):
            t = res["text"]
            parts.append(f"Text: +{t['added_lines']} / −{t['removed_lines']} lines · similarity {t['similarity'] * 100:.1f}%")
            for line in t["unified"]:
                col = T["ok"] if line.startswith("+") and not line.startswith("+++") else \
                    T["err"] if line.startswith("-") and not line.startswith("---") else \
                    T["cyan"] if line.startswith("@@") else T["text_dim"]
                body.append(f"<span style='color:{col}'>{html.escape(line) or '&nbsp;'}</span>")
            if t.get("truncated"):
                body.append("<i>… diff truncated</i>")
        if res.get("pdf"):
            p = res["pdf"]
            pages = p["pages"]
            parts.append(f"PDF: {p['pages_a']} → {p['pages_b']} pages · "
                         + (", ".join(f"page {x['page']} {x['status']}" for x in pages[:8]) or "no page changed"))
            self.tbl_pages.setRowCount(len(pages))
            for i, x in enumerate(pages):
                for c, v in enumerate([x["page"], x["status"], x.get("text_similarity", "")]):
                    it = QTableWidgetItem(str(v))
                    if c == 1:
                        it.setForeground(QColor(STATUS_COLOR.get(x["status"], T["text"])))
                    self.tbl_pages.setItem(i, c, it)
            self.tabs.setTabText(2, f"PAGES  {len(pages)}")
        if res.get("image"):
            im = res["image"]
            parts.append(f"Image: {im['changed_ratio'] * 100:.2f}% of pixels changed in {len(im['regions'])} region(s)"
                         + (f" · sizes differ {im['size_a']} → {im['size_b']} (B resized for comparison)"
                            if im["resized"] else ""))
            body += [f"Region {i + 1}: x={r[0]} y={r[1]} {r[2]}×{r[3]} px" for i, r in enumerate(im["regions"])]
        if res.get("bytes"):
            b = res["bytes"]
            parts.append(f"Binary: {b['size_a']:,} → {b['size_b']:,} bytes · "
                         f"{len(b['ranges'])} changed range(s)"
                         + (f" · similarity {b['similarity'] * 100:.1f}%" if b.get("similarity") is not None else ""))
            body += [f"{r['op']:<8} A[{r['a'][0]}:{r['a'][1]}] → B[{r['b'][0]}:{r['b'][1]}]" for r in b["ranges"]]
        sb = res.get("sandbox") or {}
        parts.append("<span style='color:%s'>%s</span>" % (
            T["text_mute"], "🛡 compared inside the sandbox" if sb.get("isolated") else "compared in-process"))
        self.txt_content.setHtml("<br>".join(parts) + "<hr>" + "<br>".join(body))
        if png and Path(png).is_file():
            pm = QPixmap(png)
            if not pm.isNull():
                self.img.setPixmap(pm)
                self.tabs.setCurrentIndex(1)
        self._header()
