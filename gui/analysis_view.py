"""
╔══════════════════════════════════════════════════════════════╗
║          ANALYSIS VIEW — detailed forensic output            ║
╚══════════════════════════════════════════════════════════════╝
"""
import json
import datetime
import io
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPixmap, QImage
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPlainTextEdit,
    QTabWidget, QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem,
    QFrame, QPushButton, QFileDialog, QMessageBox, QScrollArea
)

from .attack_widget import AttackMatrix
from .timeline_widget import TimelineView
from .similar_widget import SimilarView
from .chain_widget import ChainView
from .lineage_widget import LineageView
from .intel_widget import IntelView
from engines.attack import map_result as attack_map
from config.settings import (
    T, FONT_MONO, REPORT_DIR, EXT_IMAGE,
    EXT_PDF, EXT_DOC_OOX, EXT_DOC_OLE
)


def _history_db():
    from core.history import default_db
    return default_db()


class AnalysisView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._result = None
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        # Top bar
        top = QHBoxLayout()
        top.setSpacing(10)

        title = QLabel("▸  FORENSIC INTELLIGENCE  ·  DETAILED ANALYSIS")
        title.setObjectName("SectionHeader")
        top.addWidget(title)
        top.addStretch(1)

        self.btn_export_json = QPushButton("EXPORT JSON")
        self.btn_export_json.clicked.connect(self._export_json)
        self.btn_export_txt  = QPushButton("EXPORT TXT")
        self.btn_export_txt.clicked.connect(self._export_txt)
        self.btn_report = QPushButton("📄  REPORT")
        self.btn_report.setObjectName("PrimaryBtn")
        self.btn_report.setToolTip("Forensic report (HTML/PDF) with chain of custody")
        self.btn_report.clicked.connect(lambda: self.export_report())

        for b in (self.btn_report, self.btn_export_json, self.btn_export_txt):
            b.setEnabled(False)
            top.addWidget(b)

        root.addLayout(top)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setObjectName("AnalysisTabs")      # kompakte Tabs: 14 Reiter passen auch bei 1400 px
        self.tabs.addTab(self._build_preview_tab(),    "PREVIEW")
        self.tabs.addTab(self._build_overview_tab(),   "OVERVIEW")
        self.tabs.addTab(self._build_threats_tab(),    "THREATS")
        self.chain = ChainView()
        self.tabs.addTab(self.chain,                   "CHAIN")
        self.attack = AttackMatrix()
        self.tabs.addTab(self.attack,                  "ATT&&CK")
        self.timeline = TimelineView()
        self.tabs.addTab(self.timeline,                "TIMELINE")
        self.similar = SimilarView()
        self.tabs.addTab(self.similar,                 "SIMILAR")
        self.lineage = LineageView()
        self.tabs.addTab(self.lineage,                 "LINEAGE")
        self.intel = IntelView(db_fn=_history_db)
        self.tabs.addTab(self.intel,                   "INTEL")
        self.tabs.addTab(self._build_metadata_tab(),   "META")
        self.tabs.addTab(self._build_findings_tab(),   "FINDINGS")
        self.tabs.addTab(self._build_hashes_tab(),     "HASHES")
        self.tabs.addTab(self._build_raw_tab(),        "JSON")
        root.addWidget(self.tabs, stretch=1)

    # ── Tab: Preview ─────────────────────────────────────────────────
    def _build_preview_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(6)

        self.preview_header = QLabel("  —  no file loaded")
        self.preview_header.setStyleSheet(
            f"color:{T['text_dim']}; font-size:9pt; letter-spacing:2px; padding:4px;"
        )
        lay.addWidget(self.preview_header)

        # Image preview (for IMG + PDF rendered page)
        self.preview_image = QLabel()
        self.preview_image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_image.setStyleSheet(
            f"background:{T['bg']}; border:1px solid {T['border']};"
        )
        self.preview_image.setMinimumHeight(420)

        img_scroll = QScrollArea()
        img_scroll.setWidget(self.preview_image)
        img_scroll.setWidgetResizable(True)
        img_scroll.setFrameShape(QFrame.Shape.NoFrame)
        img_scroll.setStyleSheet(f"background:{T['bg']};")
        lay.addWidget(img_scroll, stretch=1)

        # Text preview (for DOCX/XLSX/PPTX or fallback)
        self.preview_text = QPlainTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setFont(QFont(FONT_MONO, 9))
        self.preview_text.setStyleSheet(
            f"background:{T['card']}; color:{T['text']};"
            f"border:1px solid {T['border']};"
        )
        self.preview_text.setMinimumHeight(180)
        self.preview_text.setPlainText(
            "  No file loaded.\n\n"
            "  → Any file type appears here after analysis (images, PDFs, Office,\n"
            "    programs, archives, scripts, mails … as rendering or hex view)."
        )
        lay.addWidget(self.preview_text)
        return w

    # ── Tab: Threats (universelle Analysatoren) ──────────────────────
    def _build_threats_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(6)

        self.lbl_threat = QLabel("  —  no file analyzed")
        self.lbl_threat.setWordWrap(True)
        self.lbl_threat.setStyleSheet(
            f"color:{T['text_dim']}; font-size:10pt; letter-spacing:1px; padding:8px;"
            f"border:1px solid {T['border']}; background:{T['card']};"
        )
        lay.addWidget(self.lbl_threat)

        self.tree_threats = QTreeWidget()
        self.tree_threats.setHeaderLabels(["ANALYZER / KEY", "VALUE"])
        self.tree_threats.setFont(QFont(FONT_MONO, 9))
        self.tree_threats.setAlternatingRowColors(True)
        self.tree_threats.setColumnWidth(0, 340)
        lay.addWidget(self.tree_threats, stretch=1)
        return w

    # ── Tab: Overview ────────────────────────────────────────────────
    def _build_overview_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(6)

        self.txt_overview = QPlainTextEdit()
        self.txt_overview.setReadOnly(True)
        self.txt_overview.setFont(QFont(FONT_MONO, 10))
        self.txt_overview.setPlainText(
            "  No file analyzed yet.\n\n"
            "  → Drop a file on the dashboard, or open one via the sidebar.\n"
            "  → Supported: ANY file type — deep forensics for images, PDFs and Office;\n"
            "    threat analysis for programs, archives (zip bombs), scripts, web,\n"
            "    shortcuts, RTF, e-mails, databases and everything else."
        )
        lay.addWidget(self.txt_overview)
        return w

    # ── Tab: Metadata ────────────────────────────────────────────────
    def _build_metadata_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)

        self.tbl_meta = QTableWidget(0, 2)
        self.tbl_meta.setHorizontalHeaderLabels(["KEY", "VALUE"])
        self.tbl_meta.horizontalHeader().setStretchLastSection(True)
        self.tbl_meta.verticalHeader().setVisible(False)
        self.tbl_meta.setAlternatingRowColors(True)
        self.tbl_meta.setFont(QFont(FONT_MONO, 9))
        lay.addWidget(self.tbl_meta)
        return w

    # ── Tab: Findings ────────────────────────────────────────────────
    def _build_findings_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)

        self.tbl_find = QTableWidget(0, 4)
        self.tbl_find.setHorizontalHeaderLabels(
            ["SEVERITY", "CODE", "WEIGHT", "DESCRIPTION"]
        )
        self.tbl_find.horizontalHeader().setStretchLastSection(True)
        self.tbl_find.verticalHeader().setVisible(False)
        self.tbl_find.setAlternatingRowColors(True)
        self.tbl_find.setFont(QFont(FONT_MONO, 9))
        lay.addWidget(self.tbl_find)
        return w

    # ── Tab: Hashes ──────────────────────────────────────────────────
    def _build_hashes_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)

        self.tbl_hash = QTableWidget(0, 2)
        self.tbl_hash.setHorizontalHeaderLabels(["ALGORITHM", "DIGEST"])
        self.tbl_hash.horizontalHeader().setStretchLastSection(True)
        self.tbl_hash.verticalHeader().setVisible(False)
        self.tbl_hash.setFont(QFont(FONT_MONO, 10))
        lay.addWidget(self.tbl_hash)

        info = QLabel(
            "  Cryptographic digests — copy to clipboard by selecting + Ctrl+C."
        )
        info.setStyleSheet(f"color:{T['text_mute']}; font-size:8pt; padding:6px;")
        lay.addWidget(info)
        return w

    # ── Tab: Raw JSON ────────────────────────────────────────────────
    def _build_raw_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)

        self.txt_raw = QPlainTextEdit()
        self.txt_raw.setReadOnly(True)
        self.txt_raw.setFont(QFont(FONT_MONO, 9))
        self.txt_raw.setPlainText("// no data")
        lay.addWidget(self.txt_raw)
        return w

    # ─────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────
    def load_result(self, result):
        self._result = result
        self.btn_export_json.setEnabled(True)
        self.btn_export_txt.setEnabled(True)
        self.btn_report.setEnabled(True)

        # Preview
        self._render_preview(result)

        # Overview
        self.txt_overview.setPlainText(self._render_overview(result))

        # Threats
        self._render_threats(result)
        self.attack.set_result(result)
        self.chain.set_result(result)
        self.intel.set_result(result)
        self.tabs.setTabText(self.tabs.indexOf(self.chain),
                             f"CHAIN  {self.chain.count}" if self.chain.count else "CHAIN")
        self.timeline.set_result(result)
        n_tl = sum(1 for a in self.timeline.data["anomalies"] if a["severity"] == "WARN")
        self.tabs.setTabText(self.tabs.indexOf(self.timeline), f"TIMELINE  ⚠{n_tl}" if n_tl else "TIMELINE")

        # Metadata
        self._render_metadata_table(result)

        # Findings
        self._render_findings_table(result)

        # Hashes
        self._render_hashes_table(result)

        # Raw
        try:
            raw = json.dumps(self._json_safe(result), indent=2,
                             ensure_ascii=False)
        except Exception as e:
            raw = f"// serialization error: {e}"
        self.txt_raw.setPlainText(raw)

    def set_lineage(self, rows):
        self.lineage.set_data(self._result, rows)
        self.tabs.setTabText(self.tabs.indexOf(self.lineage), f"LINEAGE  {len(rows)}" if rows else "LINEAGE")

    def set_similar(self, rows, fp=None):
        """Ähnliche Dateien aus dem Verlauf (vom Hauptfenster geliefert)."""
        self._similar_rows = rows
        self.similar.set_fingerprints(fp)
        self.similar.set_matches(rows)
        idx = self.tabs.indexOf(self.similar)
        self.tabs.setTabText(idx, f"SIMILAR  {len(rows)}" if rows else "SIMILAR")

    def reset(self):
        self._result = None
        self.btn_export_json.setEnabled(False)
        self.btn_export_txt.setEnabled(False)
        self.btn_report.setEnabled(False)
        self.txt_overview.setPlainText(
            "  No file analyzed yet.\n\n"
            "  → Drop a file on the dashboard, or open one via the sidebar."
        )
        self.tbl_meta.setRowCount(0)
        self.tbl_find.setRowCount(0)
        self.tbl_hash.setRowCount(0)
        self.tree_threats.clear()
        self.attack.set_result(None)
        self.chain.set_result(None)
        self.intel.set_result(None)
        self.tabs.setTabText(self.tabs.indexOf(self.chain), "CHAIN")
        self.timeline.set_result(None)
        self.set_similar(None)
        self.lineage.set_data(None, None)
        self.tabs.setTabText(self.tabs.indexOf(self.lineage), "LINEAGE")
        self.tabs.setTabText(self.tabs.indexOf(self.timeline), "TIMELINE")
        self.lbl_threat.setText("  —  no file analyzed")
        self.txt_raw.setPlainText("// no data")
        self.preview_header.setText("  —  no file loaded")
        self.preview_image.clear()
        self.preview_image.setText("")
        self.preview_text.setPlainText(
            "  No file loaded.\n\n"
            "  → Any file type appears here after analysis."
        )

    # ─────────────────────────────────────────────────────────────────
    # Renderers
    # ─────────────────────────────────────────────────────────────────
    def _render_preview(self, r):
        """Render file preview based on detected kind."""
        fi = r.get("file") or {}
        path = fi.get("path") or ""
        name = fi.get("name") or "—"
        ext = (fi.get("extension") or "").lower()
        kind = (r.get("kind") or "").lower()

        self.preview_image.clear()
        self.preview_image.setText("")
        self.preview_text.clear()

        if not path or not Path(path).exists():
            self.preview_header.setText("  —  file unavailable")
            self.preview_text.setPlainText("  File no longer accessible at recorded path.")
            return

        self.preview_header.setText(f"  PREVIEW  ·  {name}  ·  {ext or kind}")

        sb = r.get("sandbox") or {}
        if sb.get("isolated"):
            # Sicherer Pfad: das Original wird in der App NIE geparst – nur das
            # in der Sandbox neu kodierte PNG bzw. deren Textauszug wird gezeigt.
            self.preview_header.setText(f"  PREVIEW  ·  {name}  ·  {ext or kind}  ·  🛡 SANDBOX-RENDERED")
            self._preview_sandboxed(path, r, sb)
            return

        try:
            if ext in EXT_IMAGE or kind == "image":
                self._preview_image_file(path)
            elif ext in EXT_PDF or kind == "pdf":
                self._preview_pdf(path)
            elif ext in EXT_DOC_OOX or ext in EXT_DOC_OLE or kind == "document":
                self._preview_document(path, ext)
            else:
                self._preview_generic(path, r)
        except Exception as e:
            self.preview_text.setPlainText(
                f"  Preview error: {e}\n\n  (Analysis itself is unaffected.)"
            )

    def _preview_image_file(self, path):
        pm = QPixmap(path)
        if pm.isNull():
            try:
                from PIL import Image
                img = Image.open(path).convert("RGB")
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                qimg = QImage.fromData(buf.getvalue(), "PNG")
                pm = QPixmap.fromImage(qimg)
            except Exception as e:
                self.preview_text.setPlainText(f"  Could not decode image: {e}")
                return
        if pm.isNull():
            self.preview_text.setPlainText("  Image could not be decoded.")
            return
        scaled = pm.scaled(
            1200, 900,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.preview_image.setPixmap(scaled)
        self.preview_text.setPlainText(
            f"  {pm.width()} × {pm.height()} px  ·  rendered from source image."
        )

    def _preview_pdf(self, path):
        text_lines = []
        # Try pdf2image for visual preview (requires poppler)
        rendered = False
        try:
            from pdf2image import convert_from_path
            pages = convert_from_path(path, first_page=1, last_page=1, dpi=110)
            if pages:
                img = pages[0]
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                qimg = QImage.fromData(buf.getvalue(), "PNG")
                pm = QPixmap.fromImage(qimg).scaled(
                    1200, 1400,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
                self.preview_image.setPixmap(pm)
                rendered = True
        except Exception as e:
            text_lines.append(f"  [pdf2image unavailable: {e}]")
            text_lines.append("  Install poppler to enable visual PDF preview.")
            text_lines.append("")

        # Always try to extract text for the lower pane
        try:
            import pikepdf
            with pikepdf.open(path) as pdf:
                text_lines.append(f"  Pages: {len(pdf.pages)}")
                try:
                    with pdf.open_metadata() as md:
                        for k, v in list(md.items())[:20]:
                            text_lines.append(f"  {k}: {str(v)[:200]}")
                except Exception:
                    pass
        except Exception as e:
            text_lines.append(f"  (pikepdf read error: {e})")

        if not rendered:
            self.preview_image.setText(
                "  PDF visual preview unavailable.\n"
                "  Install poppler-windows + pdf2image for page rendering."
            )
            self.preview_image.setStyleSheet(
                f"background:{T['bg']}; border:1px solid {T['border']};"
                f"color:{T['text_mute']}; font-size:10pt; padding:40px;"
            )

        self.preview_text.setPlainText("\n".join(text_lines) or "  (no text extracted)")

    def _preview_document(self, path, ext):
        lines = []
        try:
            if ext == ".docx":
                from docx import Document
                doc = Document(path)
                lines.append(f"  DOCX  ·  {len(doc.paragraphs)} paragraphs  ·  "
                             f"{len(doc.tables)} tables")
                lines.append("  " + "─" * 60)
                lines.append("")
                shown = 0
                for p in doc.paragraphs:
                    txt = (p.text or "").strip()
                    if txt:
                        lines.append("  " + txt[:400])
                        shown += 1
                        if shown >= 120:
                            lines.append("  …")
                            break
            elif ext == ".xlsx":
                from openpyxl import load_workbook
                wb = load_workbook(path, data_only=True, read_only=True)
                lines.append(f"  XLSX  ·  sheets: {wb.sheetnames}")
                lines.append("  " + "─" * 60)
                for sname in wb.sheetnames[:6]:
                    ws = wb[sname]
                    lines.append(f"\n  ── SHEET: {sname} ──")
                    rowcount = 0
                    for row in ws.iter_rows(values_only=True):
                        cells = [str(c) if c is not None else "" for c in row[:10]]
                        lines.append("  " + " | ".join(cells)[:400])
                        rowcount += 1
                        if rowcount >= 40:
                            lines.append("  …")
                            break
            elif ext == ".pptx":
                from pptx import Presentation
                pres = Presentation(path)
                lines.append(f"  PPTX  ·  {len(pres.slides)} slides")
                lines.append("  " + "─" * 60)
                for i, slide in enumerate(pres.slides[:40], 1):
                    lines.append(f"\n  ── SLIDE {i} ──")
                    for shape in slide.shapes:
                        if shape.has_text_frame:
                            for para in shape.text_frame.paragraphs:
                                txt = (para.text or "").strip()
                                if txt:
                                    lines.append("  " + txt[:300])
            elif ext in (".doc", ".xls", ".ppt"):
                lines.append(f"  Legacy OLE document ({ext}).")
                lines.append("  Textual preview not supported for legacy binary "
                             "Office formats — see OVERVIEW / METADATA tabs.")
            else:
                lines.append(f"  Unsupported document extension: {ext}")
        except Exception as e:
            lines.append(f"  Document parse error: {e}")

        self.preview_text.setPlainText("\n".join(lines) or "  (empty document)")
        self.preview_image.setText(
            f"  {ext.upper().lstrip('.')} DOCUMENT\n\n  Text preview shown below."
        )
        self.preview_image.setStyleSheet(
            f"background:{T['bg']}; border:1px solid {T['border']};"
            f"color:{T['text_dim']}; font-size:11pt; letter-spacing:2px; padding:60px;"
        )

    def _preview_generic(self, path, r):
        """Hex-Ansicht + Kurzprofil für alle Typen ohne eigene Vorschau.
        Liest nur die ersten 2 KB – die Datei wird nie geöffnet/ausgeführt."""
        ft = r.get("filetype") or {}
        an = (r.get("report") or {}).get("analyzers") or {}
        base = an.get("baseline") or {}
        with open(path, "rb") as f:
            head = f.read(2048)
        lines = [f"  {ft.get('description', 'Unknown')}  ·  {len(head)} of "
                 f"{(r.get('file') or {}).get('size', 0):,} bytes shown", ""]
        for off in range(0, len(head), 16):
            chunk = head[off:off + 16]
            hx = " ".join(f"{b:02X}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "·" for b in chunk)
            lines.append(f"  {off:08X}  {hx:<47}  {asc}")
        iocs = base.get("iocs") or {}
        if iocs:
            lines += ["", "  ─── INDICATORS ───────────────────────────────"]
            for k, vals in iocs.items():
                for v in vals[:8]:
                    lines.append(f"    {k:<9} {v.get('sample', v) if isinstance(v, dict) else v}")
        if ft.get("is_text"):
            try:
                txt = head.decode("utf-8", "replace")
                lines += ["", "  ─── TEXT (first 2 KB, never executed) ───────", txt]
            except Exception:
                pass
        self.preview_text.setPlainText("\n".join(lines))
        self.preview_image.setText(f"  {ft.get('description', 'BINARY').upper()}\n\n"
                                   f"  {r.get('threat', {}).get('verdict', '')}\n\n  Hex view below.")
        self.preview_image.setStyleSheet(
            f"background:{T['bg']}; border:1px solid {T['border']};"
            f"color:{T['text_dim']}; font-size:11pt; letter-spacing:2px; padding:60px;"
        )

    def _preview_sandboxed(self, path, r, sb):
        self._preview_generic(path, r)          # Hexdump + IOCs (nur rohe Bytes, kein Parser)
        text = sb.get("preview_text")
        if text:
            self.preview_text.setPlainText("  ─── CONTENT (extracted inside sandbox) ───\n\n" + text
                                           + "\n\n" + self.preview_text.toPlainText())
        png = sb.get("preview_png")
        if png and Path(png).is_file():
            data = Path(png).read_bytes()
            if data[:8] == b"\x89PNG\r\n\x1a\n":          # nur das von uns erzeugte PNG
                qimg = QImage.fromData(data, "PNG")
                if not qimg.isNull():
                    pm = QPixmap.fromImage(qimg).scaled(
                        1200, 900, Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation)
                    self.preview_image.setStyleSheet(f"background:{T['bg']}; border:1px solid {T['border']};")
                    self.preview_image.setPixmap(pm)
        if sb.get("violation"):
            self.preview_image.setText(f"  🛡 SANDBOX STOPPED THE ANALYSIS\n\n  {sb['violation']}")

    def _render_threats(self, r):
        th = r.get("threat") or {}
        score = r.get("score") or {}
        color = score.get("color", T['text_dim'])
        fam = " · ".join(th.get("families") or []) or "—"
        self.lbl_threat.setText(
            f"  VERDICT  {th.get('verdict', '—')}  ·  {th.get('score', 0)}/100  ·  "
            f"{th.get('critical', 0)} CRIT / {th.get('warnings', 0)} WARN\n"
            f"  AREAS    {fam}\n  ▸ {th.get('headline', '—')}"
        )
        self.lbl_threat.setStyleSheet(
            f"color:{color}; font-size:10pt; letter-spacing:1px; padding:8px;"
            f"border:1px solid {color}; background:{T['card']};"
        )
        self.tree_threats.clear()
        an = (r.get("report") or {}).get("analyzers") or {}
        sev_by_src = {}
        for f in score.get("findings") or []:
            src = f.get("source")
            if src:
                sev_by_src.setdefault(src, []).append(f)
        order = {"CRIT": 0, "WARN": 1, "INFO": 2}
        for name, data in an.items():
            fs = sorted(sev_by_src.get(name, []), key=lambda f: order.get(f["severity"], 3))
            worst = fs[0]["severity"] if fs else "OK"
            top = QTreeWidgetItem([f"{name.upper()}", f"{len(fs)} signal(s) · worst: {worst}"])
            top.setForeground(0, self._qc({"CRIT": T['err'], "WARN": T['warn'],
                                           "INFO": T['info']}.get(worst, T['ok'])))
            self.tree_threats.addTopLevelItem(top)
            if fs:
                fnode = QTreeWidgetItem(["signals", str(len(fs))])
                top.addChild(fnode)
                for f in fs:
                    it = QTreeWidgetItem([f"[{f['severity']}] {f['code']}", f.get("desc", "")])
                    it.setForeground(0, self._qc({"CRIT": T['err'], "WARN": T['warn']}.get(f["severity"], T['info'])))
                    fnode.addChild(it)
                fnode.setExpanded(True)
            self._tree_fill(top, data)
            top.setExpanded(worst in ("CRIT", "WARN"))

    def _tree_fill(self, parent, obj, depth=0, budget=None):
        """Füllt den Baum rekursiv – mit Limits, damit riesige Archive die GUI nicht lähmen."""
        budget = budget if budget is not None else [4000]
        if budget[0] <= 0 or depth > 6:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k).startswith("_") and k != "_error":
                    continue
                budget[0] -= 1
                if isinstance(v, (dict, list)) and v:
                    node = QTreeWidgetItem([str(k), f"{len(v)} item(s)"])
                    parent.addChild(node)
                    self._tree_fill(node, v, depth + 1, budget)
                else:
                    parent.addChild(QTreeWidgetItem([str(k), self._short(v, 400)]))
        elif isinstance(obj, list):
            for i, v in enumerate(obj[:300]):
                budget[0] -= 1
                if isinstance(v, dict):
                    label = v.get("name") or v.get("rule") or v.get("filename") or v.get("code") or f"[{i}]"
                    node = QTreeWidgetItem([str(label)[:120], ""])
                    parent.addChild(node)
                    self._tree_fill(node, v, depth + 1, budget)
                else:
                    parent.addChild(QTreeWidgetItem([f"[{i}]", self._short(v, 400)]))
            if len(obj) > 300:
                parent.addChild(QTreeWidgetItem(["…", f"{len(obj) - 300} more"]))

    def _render_overview(self, r):
        fi    = r.get("file") or {}
        score = r.get("score") or {}
        magic = r.get("magic") or ("?", "?", "?")

        findings = score.get("findings") or []
        top      = score.get("top") or []

        lines = []
        lines.append("╔══════════════════════════════════════════════════════════════╗")
        lines.append("║           FORENSIC INTELLIGENCE REPORT — SENTINEL-F          ║")
        lines.append("╚══════════════════════════════════════════════════════════════╝")
        lines.append("")
        lines.append(f"  TIMESTAMP  : {r.get('timestamp', datetime.datetime.now().isoformat(sep=' '))}")
        if r.get("history"):
            lines.append(f"  SOURCE     : HISTORY #{r['history']['id']} — stored result, file not re-analysed")
        lines.append(f"  FILE       : {fi.get('name', '—')}")
        lines.append(f"  PATH       : {fi.get('path', '—')}")
        lines.append(f"  SIZE       : {fi.get('size_h', '—')}  ({fi.get('size', 0):,} bytes)")
        lines.append(f"  MODIFIED   : {fi.get('modified', '—')}")
        lines.append(f"  EXT        : {fi.get('extension', '—')}")
        ft = r.get("filetype") or {}
        cat = (f"{ft['category']} / {ft['subtype']}" if ft and magic[0] == "unknown"
               else f"{magic[0]} / {magic[1]}")
        lines.append(f"  CATEGORY   : {cat}")
        lines.append(f"  MAGIC      : {magic[2]}")
        if ft:
            lines.append(f"  TRUE TYPE  : {ft.get('description', '—')}"
                         + ("   ⚠ EXTENSION MISMATCH" if ft.get("extension_mismatch") else ""))
        lines.append("")
        th = r.get("threat") or {}
        if th:
            lines.append("  ─── THREAT ANALYSIS ─────────────────────────────────────────")
            lines.append(f"    VERDICT  : {th.get('verdict', '—')}   "
                         f"({th.get('critical', 0)} critical · {th.get('warnings', 0)} warnings)")
            if th.get("families"):
                lines.append(f"    AREAS    : {' · '.join(th['families'])}")
            lines.append(f"    HEADLINE : {th.get('headline', '—')}")
            tl_warn = [a for a in (r.get("timeline") or {}).get("anomalies", []) if a["severity"] == "WARN"]
            for a in tl_warn[:3]:
                lines.append(f"    TIMELINE : ⚠ {a['desc']}")
            hot = [t for t in attack_map(r)["techniques"] if t["severity"] != "INFO"]
            if hot:
                lines.append(f"    ATT&CK   : {' · '.join(t['id'] for t in hot[:8])}"
                             + (f" (+{len(hot) - 8})" if len(hot) > 8 else ""))
            an = (r.get("report") or {}).get("analyzers") or {}
            ran = [f"{k} ({v.get('_ms', '?')} ms)" for k, v in an.items() if isinstance(v, dict)]
            if ran:
                lines.append(f"    ENGINES  : {', '.join(ran)}")
            sb = r.get("sandbox") or {}
            if sb.get("isolated"):
                lines.append(f"    SANDBOX  : isolated · integrity {sb.get('integrity', '?')} · no child processes · "
                             f"RAM ≤ {(sb.get('memory_limit') or 0) >> 30} GiB · peak "
                             f"{(sb.get('peak_memory') or 0) >> 20} MiB · {sb.get('seconds', '?')} s")
                if sb.get("violation"):
                    lines.append(f"    ⚠ STOPPED: {sb['violation']}")
            elif sb:
                lines.append("    SANDBOX  : not available — analysed in-process")
            arc = (an.get("archive") or {}).get("stats")
            if arc:
                lines.append(f"    ARCHIVE  : {arc.get('entries', 0)} entries · ratio "
                             f"{max(arc.get('declared_ratio') or 0, arc.get('measured_ratio') or 0, arc.get('cumulative_ratio') or 0):,.1f}:1"
                             f" · depth {arc.get('max_depth', 0)}")
            if (r.get("report") or {}).get("legacy_error"):
                lines.append(f"    NOTE     : classic engine failed — {r['report']['legacy_error'][:80]}")
            lines.append("")
        lines.append("  ─── CRYPTOGRAPHIC DIGESTS ───────────────────────────────────")
        hashes = r.get("hashes") or {}
        lines.append(f"    MD5      : {hashes.get('md5',    '—')}")
        lines.append(f"    SHA-1    : {hashes.get('sha1',   '—')}")
        lines.append(f"    SHA-256  : {hashes.get('sha256', '—')}")
        lines.append("")
        lines.append("  ─── MANIPULATION ASSESSMENT ─────────────────────────────────")
        lines.append(f"    SCORE    : {score.get('score', 0)} / 100")
        lines.append(f"    LEVEL    : {score.get('level', '—')}")
        lines.append(f"    SIGNALS  : {len(findings)} total")
        lines.append("")
        if top:
            lines.append("  ─── TOP-WEIGHT SIGNALS ──────────────────────────────────────")
            for f in top:
                lines.append(
                    f"    [{f.get('severity','?'):<4}]  +{f.get('weight',0):>5.1f}  "
                    f"{f.get('code','?'):<26}  {f.get('desc','')}"
                )
            lines.append("")
        if r.get("error"):
            lines.append("  ─── ERROR ───────────────────────────────────────────────────")
            lines.append(f"    {r['error']}")
            lines.append("")
        lines.append("  ─── END OF REPORT ───────────────────────────────────────────")
        return "\n".join(lines)

    def _render_metadata_table(self, r):
        """Flatten engine metadata into key/value rows."""
        self.tbl_meta.setRowCount(0)
        rep = r.get("report") or {}

        rows = []
        # Always include file stat
        fi = r.get("file") or {}
        for k, v in fi.items():
            rows.append((f"file.{k}", str(v)))

        # Engine-specific metadata sections
        for section_key in ("metadata", "info", "meta_checks"):
            sec = rep.get(section_key)
            if isinstance(sec, dict):
                for k, v in sec.items():
                    rows.append((f"{section_key}.{k}", self._short(v)))
            elif isinstance(sec, list):
                for i, item in enumerate(sec):
                    rows.append((f"{section_key}[{i}]", self._short(item)))

        # Document-specific structural info
        for section_key in ("zip_structure", "entropy", "relationships",
                            "revision_history"):
            sec = rep.get(section_key)
            if isinstance(sec, dict):
                for k, v in sec.items():
                    rows.append((f"{section_key}.{k}", self._short(v)))

        # Channel / histogram / noise summaries for images
        for section_key in ("channels", "histogram", "noise", "lsb",
                            "jpeg_ghost", "clones"):
            sec = rep.get(section_key)
            if isinstance(sec, dict):
                for k, v in sec.items():
                    if isinstance(v, (dict, list)):
                        rows.append((f"{section_key}.{k}", self._short(v)))
                    else:
                        rows.append((f"{section_key}.{k}", str(v)))

        # PDF-specific — some engines report a count (int), others the list itself
        def _count(val):
            if val is None:
                return None
            if isinstance(val, (list, tuple, dict, set)):
                return len(val)
            if isinstance(val, (int, float)):
                return int(val)
            return None

        for key, label in (
            ("redactions",       "redactions.count"),
            ("embedded_images",  "pdf.embedded_images"),
            ("links",            "pdf.links"),
        ):
            c = _count(rep.get(key))
            if c is not None:
                rows.append((label, str(c)))

        if rep.get("black_rectangles") is not None:
            rows.append(("pdf.black_rectangles", str(rep["black_rectangles"])))
        if rep.get("unused_objects") is not None:
            rows.append(("pdf.unused_objects", str(rep["unused_objects"])))

        self.tbl_meta.setRowCount(len(rows))
        for i, (k, v) in enumerate(rows):
            k_item = QTableWidgetItem(str(k))
            v_item = QTableWidgetItem(str(v)[:600])
            k_item.setForeground(self._qc(T['cyan']))
            self.tbl_meta.setItem(i, 0, k_item)
            self.tbl_meta.setItem(i, 1, v_item)
        self.tbl_meta.resizeColumnsToContents()
        self.tbl_meta.setColumnWidth(0, max(240, self.tbl_meta.columnWidth(0)))

    def _render_findings_table(self, r):
        self.tbl_find.setRowCount(0)
        score = r.get("score") or {}
        findings = sorted(
            score.get("findings") or [],
            key=lambda f: f.get("weight", 0), reverse=True
        )
        self.tbl_find.setRowCount(len(findings))
        for i, f in enumerate(findings):
            sev = f.get("severity", "INFO")
            color_map = {"CRIT": T['err'], "WARN": T['warn'],
                         "INFO": T['info'], "OK": T['ok']}
            sev_item  = QTableWidgetItem(sev)
            sev_item.setForeground(self._qc(color_map.get(sev, T['info'])))
            code_item = QTableWidgetItem(f.get("code", "?"))
            code_item.setForeground(self._qc(T['cyan']))
            w_item    = QTableWidgetItem(f"{f.get('weight', 0):.1f}")
            w_item.setForeground(self._qc(T['accent']))
            d_item    = QTableWidgetItem(f.get("desc", ""))

            for item in (sev_item, code_item, w_item, d_item):
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)

            self.tbl_find.setItem(i, 0, sev_item)
            self.tbl_find.setItem(i, 1, code_item)
            self.tbl_find.setItem(i, 2, w_item)
            self.tbl_find.setItem(i, 3, d_item)
        self.tbl_find.resizeColumnsToContents()
        self.tbl_find.setColumnWidth(3, 600)

    def _render_hashes_table(self, r):
        self.tbl_hash.setRowCount(0)
        hashes = r.get("hashes") or {}
        rows = [("MD5", hashes.get("md5", "—")),
                ("SHA-1", hashes.get("sha1", "—")),
                ("SHA-256", hashes.get("sha256", "—"))]
        self.tbl_hash.setRowCount(len(rows))
        for i, (alg, digest) in enumerate(rows):
            a_it = QTableWidgetItem(alg)
            a_it.setForeground(self._qc(T['cyan']))
            d_it = QTableWidgetItem(digest)
            d_it.setForeground(self._qc(T['accent']))
            self.tbl_hash.setItem(i, 0, a_it)
            self.tbl_hash.setItem(i, 1, d_it)
        self.tbl_hash.resizeColumnsToContents()
        self.tbl_hash.setColumnWidth(1, 700)

    # ── Helpers ──────────────────────────────────────────────────────
    def _short(self, v, limit=260):
        if isinstance(v, (dict, list)):
            try:
                s = json.dumps(self._json_safe(v), ensure_ascii=False)
            except Exception:
                s = str(v)
        else:
            s = str(v)
        return s[:limit] + ("…" if len(s) > limit else "")

    def _json_safe(self, obj, depth=0):
        if depth > 8:
            return "<max depth>"
        if isinstance(obj, dict):
            return {str(k): self._json_safe(v, depth + 1) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._json_safe(x, depth + 1) for x in obj]
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        # bytes, PIL images, numpy arrays, etc.
        try:
            return f"<{type(obj).__name__}>"
        except Exception:
            return "<?>"

    def _qc(self, hex_color):
        from PyQt6.QtGui import QColor
        return QColor(hex_color)

    # ── Exports ──────────────────────────────────────────────────────
    def export_report(self):
        if not self._result:
            return None
        from core.report import file_report_html
        from .report_dialog import save_report
        r = self._result
        return save_report(self, lambda ex: file_report_html(r, examiner=ex,
                                                             similar=getattr(self, "_similar_rows", None)),
                           f"report_{(r.get('file') or {}).get('name', 'file')}")

    def _export_json(self):
        if not self._result:
            return
        default = REPORT_DIR / (
            f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON Report", str(default), "JSON (*.json)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._json_safe(self._result), f,
                          indent=2, ensure_ascii=False)
            QMessageBox.information(self, "Export", f"Report written:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export failed", str(e))

    def _export_txt(self):
        if not self._result:
            return
        default = REPORT_DIR / (
            f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Text Report", str(default), "Text (*.txt)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.txt_overview.toPlainText())
                f.write("\n\n")
                f.write("=== ALL FINDINGS ===\n")
                for fnd in (self._result.get("score") or {}).get("findings", []):
                    f.write(
                        f"[{fnd.get('severity','?'):<4}] +{fnd.get('weight',0):>5.1f}  "
                        f"{fnd.get('code','?'):<28}  {fnd.get('desc','')}\n"
                    )
            QMessageBox.information(self, "Export", f"Report written:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export failed", str(e))
