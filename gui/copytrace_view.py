"""
╔══════════════════════════════════════════════════════════════╗
║   COPYTRACE VIEW — Exfiltration / Copy Indicator Analyzer    ║
║   Detects file copies from a mounted Windows system disk      ║
╚══════════════════════════════════════════════════════════════╝

Platten-/verzeichnisbasierter Forensik-View (read-only). Eigenstaendig
gegenueber dem datei-orientierten run_forensic-Pfad: eigener Pfad-Picker
und eigener Worker-Thread, da CopyTrace eine ganze Systempartition
analysiert statt einer Einzeldatei.
"""
import os
import json
import datetime
import threading
import traceback

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QMessageBox, QTabWidget, QTableWidget,
    QTableWidgetItem, QPlainTextEdit, QFrame, QHeaderView, QAbstractItemView,
    QProgressBar
)

from config.settings import T, FONT_MONO, REPORT_DIR
from core.utils import LOG

try:
    from engines import copytrace_engine as ce
    _CE_IMPORT_ERR = None
except Exception as _e:  # pragma: no cover
    ce = None
    _CE_IMPORT_ERR = str(_e)


# ── Thread bridge ─────────────────────────────────────────────────────────────
class _CTBridge(QObject):
    log      = pyqtSignal(str, str)   # (level, msg)
    done     = pyqtSignal(dict)
    failed   = pyqtSignal(str)


# ── Worker log adapter (engine expects .info/.ok/.warn/.debug) ───────────────
class _WorkerLog:
    def __init__(self, emit):
        self.warnings = []
        self._emit = emit
        self.verbose = False

    def info(self, m):  self._emit("INFO", m)
    def ok(self, m):    self._emit("OK", m)
    def warn(self, m):  self.warnings.append(m); self._emit("WARN", m)
    def debug(self, m): pass


# ══════════════════════════════════════════════════════════════════════════════
class CopyTraceView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._result = None
        self._busy = False

        self.bridge = _CTBridge()
        self.bridge.log.connect(self._append_log)
        self.bridge.done.connect(self._on_done)
        self.bridge.failed.connect(self._on_failed)

        self._build()

    # ── UI ────────────────────────────────────────────────────────────
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        # Header
        top = QHBoxLayout()
        title = QLabel("▸  COPYTRACE  ·  EXFILTRATION / COPY INDICATOR ANALYZER")
        title.setObjectName("SectionHeader")
        top.addWidget(title)
        top.addStretch(1)
        self.btn_html = QPushButton("EXPORT HTML")
        self.btn_html.clicked.connect(self._export_html)
        self.btn_json = QPushButton("EXPORT JSON")
        self.btn_json.clicked.connect(self._export_json)
        for b in (self.btn_html, self.btn_json):
            b.setEnabled(False)
            top.addWidget(b)
        root.addLayout(top)

        # Methodik-Hinweis
        note = QLabel(
            "⚠  Windows fuehrt keinen Kopier-Zaehler. Eintraege sind INDIZIEN: "
            "eine Datei auf einem Wechseldatentraeger, die dort geoeffnet wurde, "
            "ist ein starkes Indiz fuer eine Kopie — kein Beweis ueber die exakte Anzahl."
        )
        note.setWordWrap(True)
        note.setStyleSheet(
            f"color:{T['text_dim']}; background:{T['card']}; "
            f"border-left:3px solid {T['warn']}; border-radius:4px; "
            f"padding:8px 12px; font-size:9pt;"
        )
        root.addWidget(note)

        # Input rows
        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)

        lbl_root = QLabel("EVIDENCE PATH")
        lbl_root.setObjectName("CardTitle")
        grid.addWidget(lbl_root, 0, 0)
        self.root_edit = QLineEdit()
        self.root_edit.setPlaceholderText(
            "Wurzel der Windows-Partition (enthaelt Windows\\ und Users\\), "
            "z.B. E:\\ oder /mnt/evidence"
        )
        self._style_edit(self.root_edit)
        grid.addWidget(self.root_edit, 0, 1)
        b1 = QPushButton("BROWSE")
        b1.setObjectName("NavBtn")
        b1.clicked.connect(self._pick_root)
        grid.addWidget(b1, 0, 2)

        lbl_usn = QLabel("USN JOURNAL")
        lbl_usn.setObjectName("CardTitle")
        grid.addWidget(lbl_usn, 1, 0)
        self.usn_edit = QLineEdit()
        self.usn_edit.setPlaceholderText("optional · separat extrahiertes $UsnJrnl:$J")
        self._style_edit(self.usn_edit)
        grid.addWidget(self.usn_edit, 1, 1)
        b2 = QPushButton("BROWSE")
        b2.setObjectName("NavBtn")
        b2.clicked.connect(self._pick_usn)
        grid.addWidget(b2, 1, 2)

        grid.setColumnStretch(1, 1)
        root.addLayout(grid)

        # Action row
        act = QHBoxLayout()
        self.btn_run = QPushButton("▶  RUN COPYTRACE")
        self.btn_run.setObjectName("PrimaryBtn")
        self.btn_run.clicked.connect(self._run)
        act.addWidget(self.btn_run)
        act.addStretch(1)
        self.progress = QProgressBar()
        self.progress.setFixedWidth(220)
        self.progress.setRange(0, 0)        # indeterminate
        self.progress.setTextVisible(False)
        self.progress.hide()
        act.addWidget(self.progress)
        root.addLayout(act)

        # Stat cards
        cards = QHBoxLayout()
        cards.setSpacing(10)
        self.card_usb  = self._stat_card("USB DEVICES")
        self.card_find = self._stat_card("COPY INDICATORS")
        self.card_high = self._stat_card("HIGH CONFIDENCE")
        self.card_usn  = self._stat_card("USN EVENTS")
        for c in (self.card_usb, self.card_find, self.card_high, self.card_usn):
            cards.addWidget(c["frame"])
        cards.addStretch(1)
        root.addLayout(cards)

        # Tabs
        self.tabs = QTabWidget()
        self.tbl_find = self._make_table(
            ["FILE (TARGET PATH)", "VOLUME", "TYPE", "DEVICE", "ACCESSED", "SIZE", "SOURCE", "CONF"])
        self.tbl_usb = self._make_table(
            ["DEVICE", "SERIAL", "FIRST INSTALL", "LAST CONNECTED", "LAST REMOVED"])
        self.tbl_shell = self._make_table(["FOLDER / HINT", "TRAIL", "ITEM MTIME", "KEY LAST WRITE"])
        self.tbl_usn = self._make_table(["TIMESTAMP", "REASON", "FILE"])

        self.tabs.addTab(self.tbl_find,  "COPY INDICATORS")
        self.tabs.addTab(self.tbl_usb,   "USB DEVICES")
        self.tabs.addTab(self.tbl_shell, "SHELLBAGS")
        self.tabs.addTab(self.tbl_usn,   "USN JOURNAL")
        root.addWidget(self.tabs, stretch=3)

        # Log
        log_hdr = QLabel("▸  ANALYSIS LOG")
        log_hdr.setObjectName("CardTitle")
        root.addWidget(log_hdr)
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont(FONT_MONO, 9))
        self.log_text.setMaximumHeight(150)
        self.log_text.setStyleSheet(
            f"background:{T['bg']}; color:{T['text_dim']}; border:1px solid {T['border']};"
        )
        root.addWidget(self.log_text, stretch=1)

        if ce is None:
            self._append_log("ERR", f"CopyTrace-Engine nicht geladen: {_CE_IMPORT_ERR}")
            self.btn_run.setEnabled(False)

    def _style_edit(self, e):
        e.setStyleSheet(
            f"QLineEdit{{background:{T['card']}; border:1px solid {T['border']};"
            f"border-radius:6px; padding:7px 10px; color:{T['text']};}}"
            f"QLineEdit:focus{{border:1px solid {T['accent']};}}"
        )

    def _stat_card(self, label):
        frame = QFrame()
        frame.setObjectName("Card")
        frame.setMinimumWidth(150)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(14, 10, 14, 10)
        num = QLabel("0")
        num.setStyleSheet(f"color:{T['accent']}; font-size:24pt; font-weight:bold;")
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color:{T['text_mute']}; font-size:8pt; letter-spacing:1px;")
        lay.addWidget(num)
        lay.addWidget(lbl)
        return {"frame": frame, "num": num}

    def _make_table(self, headers):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.verticalHeader().setVisible(False)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        t.setWordWrap(False)
        t.setStyleSheet(
            f"QTableWidget{{background:{T['bg']}; alternate-background-color:{T['bg_alt']};"
            f"gridline-color:{T['grid']}; border:1px solid {T['border']}; color:{T['text']};}}"
            f"QTableWidget::item:selected{{background:{T['border_hot']};}}"
            f"QHeaderView::section{{background:{T['panel']}; color:{T['text_mute']};"
            f"padding:6px 8px; border:none; border-bottom:1px solid {T['border']};}}"
        )
        return t

    # ── Dialogs ─────────────────────────────────────────────────────────
    def _pick_root(self):
        d = QFileDialog.getExistingDirectory(self, "Select Windows partition root")
        if d:
            self.root_edit.setText(d)

    def _pick_usn(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select extracted $UsnJrnl:$J")
        if f:
            self.usn_edit.setText(f)

    # ── Log ─────────────────────────────────────────────────────────────
    def _append_log(self, level, msg):
        col = {"INFO": T["info"], "OK": T["ok"], "WARN": T["warn"],
               "ERR": T["err"]}.get(level, T["info"])
        tag = {"INFO": "[*]", "OK": "[+]", "WARN": "[!]", "ERR": "[x]"}.get(level, "[ ]")
        self.log_text.appendHtml(
            f"<span style='color:{col};'>{tag}</span> "
            f"<span style='color:{T['text_dim']};'>{self._esc(msg)}</span>"
        )
        # Also mirror into the global telemetry log
        try:
            LOG.log(f"[CopyTrace] {msg}", level if level in ("INFO","OK","WARN","ERR") else "INFO")
        except Exception:
            pass

    @staticmethod
    def _esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # ── Run ─────────────────────────────────────────────────────────────
    def _run(self):
        if self._busy or ce is None:
            return
        root = self.root_edit.text().strip()
        if not root:
            QMessageBox.warning(self, "Path missing", "Bitte Beweismittel-Pfad angeben.")
            return
        if not os.path.isdir(root):
            QMessageBox.warning(self, "Invalid path", f"Kein Verzeichnis:\n{root}")
            return

        self._busy = True
        self.log_text.clear()
        self.btn_run.setEnabled(False)
        self.btn_html.setEnabled(False)
        self.btn_json.setEnabled(False)
        self.progress.show()

        usn = self.usn_edit.text().strip() or None

        def emit_log(level, msg):
            self.bridge.log.emit(level, msg)

        def worker():
            try:
                log = _WorkerLog(emit_log)
                res = self._analyze(root, usn, log)
                self.bridge.done.emit(res)
            except Exception as e:
                self.bridge.failed.emit(f"{type(e).__name__}: {e}\n{traceback.format_exc()}")

        threading.Thread(target=worker, daemon=True).start()

    def _analyze(self, root, usn_path, log):
        log.info(f"Analysiere Beweismittel: {root}")
        art = ce.find_artifacts(root)
        if not art["system_hive"] and not art["users"]:
            log.warn("Weder SYSTEM-Hive noch Benutzerprofile gefunden. "
                     "Ist der Pfad die Wurzel einer Windows-Systempartition?")

        usb_devices, mounted, computer = ([], {}, None)
        if art["system_hive"]:
            log.ok("SYSTEM-Hive gefunden")
            usb_devices, mounted, computer = ce.parse_system_hive(art["system_hive"], log)
            log.ok(f"{len(usb_devices)} USB-Massenspeicher, {len(mounted)} MountedDevices")
        letter_usb_map = ce.map_letter_to_usb(mounted, usb_devices)

        setupapi_events = ce.parse_setupapi(art["setupapi"], log) if art["setupapi"] else []

        lnk_records, jump_records, shellbags = [], [], []
        for u in art["users"]:
            log.info(f"Benutzer: {u['name']}")
            if u["recent"]:
                r = ce.parse_recent_dir(u["recent"], u["name"], log)
                lnk_records += r
                log.ok(f"  {len(r)} LNK-Eintraege")
            if u["autodest"] or u["customdest"]:
                j = ce.parse_jumplists(u["autodest"], u["customdest"], u["name"], log)
                jump_records += j
                log.ok(f"  {len(j)} Jump-List-Eintraege")
            if u["usrclass"]:
                sb = ce.parse_shellbags(u["usrclass"], u["name"], log)
                shellbags += sb
                log.ok(f"  {len(sb)} ShellBag-Eintraege")

        usn_events = []
        if usn_path and os.path.isfile(usn_path):
            log.info("Parse USN-Journal ...")
            usn_events = ce.parse_usn(usn_path, log)
            log.ok(f"  {len(usn_events)} USN-Ereignisse")

        findings = ce.correlate(lnk_records, jump_records, letter_usb_map)
        log.ok(f"Analyse abgeschlossen: {len(findings)} Kopier-Indizien")

        return {
            "root": root, "computer": computer, "usb_devices": usb_devices,
            "findings": findings, "shellbags": shellbags, "usn_events": usn_events,
            "setupapi_events": setupapi_events, "warnings": log.warnings,
        }

    # ── Bridge handlers ─────────────────────────────────────────────────
    def _on_failed(self, msg):
        self._busy = False
        self.progress.hide()
        self.btn_run.setEnabled(True)
        self._append_log("ERR", "FEHLER: " + msg.splitlines()[0])
        QMessageBox.critical(self, "CopyTrace failed", msg[:800])

    def _on_done(self, res):
        self._busy = False
        self._result = res
        self.progress.hide()
        self.btn_run.setEnabled(True)
        self.btn_html.setEnabled(True)
        self.btn_json.setEnabled(True)
        self._populate(res)

    # ── Populate ────────────────────────────────────────────────────────
    def _populate(self, r):
        findings = r["findings"]
        high = sum(1 for f in findings if f["confidence"] >= 80)
        self._set_card(self.card_usb,  len(r["usb_devices"]), danger=False)
        self._set_card(self.card_find, len(findings), danger=True)
        self._set_card(self.card_high, high, danger=True)
        self._set_card(self.card_usn,  len(r["usn_events"]), danger=False)

        # Findings
        self.tbl_find.setRowCount(0)
        for f in findings:
            dev = f.get("matched_device")
            devname = (dev.get("friendly_name") or dev.get("product")) if dev else \
                (f.get("volume_label") or "-")
            conf = f["confidence"]
            conf_col = T["err"] if conf >= 80 else (T["warn"] if conf >= 60 else T["text_mute"])
            dt = f.get("drive_type", "")
            type_col = T["err"] if dt == "DRIVE_REMOVABLE" else None
            self._add_row(self.tbl_find, [
                (f.get("target_path", ""), T["text_hot"]),
                (f"{f.get('drive_letter','?')}  {f.get('volume_label') or ''}", None),
                (dt, type_col),
                (devname, None),
                (ce.iso(f.get("target_accessed")), None),
                (self._fmt_size(f.get("file_size")), None),
                (f"{f.get('user','')} / {f.get('source','')}", T["text_mute"]),
                (f"{conf}%", conf_col),
            ])
        self.tbl_find.resizeColumnsToContents()
        self.tbl_find.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)

        # USB
        self.tbl_usb.setRowCount(0)
        for d in r["usb_devices"]:
            fn = d.get("friendly_name") or d["product"]
            self._add_row(self.tbl_usb, [
                (fn, T["text_hot"]),
                (d.get("serial", ""), None),
                (ce.iso(d.get("first_install")) or "-", None),
                (ce.iso(d.get("last_connected")) or "-", None),
                (ce.iso(d.get("last_removed")) or "-", None),
            ])
        self.tbl_usb.resizeColumnsToContents()
        self.tbl_usb.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)

        # ShellBags
        self.tbl_shell.setRowCount(0)
        for s in r["shellbags"][:1000]:
            self._add_row(self.tbl_shell, [
                (s.get("path_hint", ""), T["text_hot"]),
                (s.get("trail", ""), T["text_mute"]),
                (s.get("item_mtime", "") or "-", None),
                (ce.iso(s.get("last_write")), T["text_mute"]),
            ])
        self.tbl_shell.resizeColumnsToContents()
        self.tbl_shell.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)

        # USN
        self.tbl_usn.setRowCount(0)
        for ev in r["usn_events"][:5000]:
            self._add_row(self.tbl_usn, [
                (ce.iso(ev.get("timestamp")), None),
                (ev.get("reason", ""), T["text_mute"]),
                (ev.get("filename", ""), T["text_hot"]),
            ])
        self.tbl_usn.resizeColumnsToContents()
        self.tbl_usn.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)

        # Tab counters
        self.tabs.setTabText(0, f"COPY INDICATORS ({len(findings)})")
        self.tabs.setTabText(1, f"USB DEVICES ({len(r['usb_devices'])})")
        self.tabs.setTabText(2, f"SHELLBAGS ({len(r['shellbags'])})")
        self.tabs.setTabText(3, f"USN JOURNAL ({len(r['usn_events'])})")

    def _set_card(self, card, value, danger=False):
        card["num"].setText(str(value))
        col = T["err"] if (danger and value) else T["accent"]
        card["num"].setStyleSheet(f"color:{col}; font-size:24pt; font-weight:bold;")

    def _add_row(self, table, cells):
        row = table.rowCount()
        table.insertRow(row)
        for col, (text, color) in enumerate(cells):
            item = QTableWidgetItem(str(text))
            if color:
                item.setForeground(QColor(color))
            table.setItem(row, col, item)

    @staticmethod
    def _fmt_size(b):
        if not b:
            return "-"
        b = float(b)
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.0f} {unit}" if unit == "B" else f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"

    # ── Export ──────────────────────────────────────────────────────────
    def _export_html(self):
        if not self._result:
            return
        default = str(REPORT_DIR / "copytrace_report.html")
        f, _ = QFileDialog.getSaveFileName(self, "Save HTML report", default, "HTML (*.html)")
        if not f:
            return
        r = self._result
        ce.build_html_report(f, r["root"], r["computer"], r["usb_devices"],
                             r["findings"], r["shellbags"], r["usn_events"],
                             r["setupapi_events"], r["warnings"])
        self._append_log("OK", f"HTML-Report gespeichert: {f}")
        QMessageBox.information(self, "Export", f"HTML-Report gespeichert:\n{f}")

    def _export_json(self):
        if not self._result:
            return
        default = str(REPORT_DIR / "copytrace_report.json")
        f, _ = QFileDialog.getSaveFileName(self, "Save JSON", default, "JSON (*.json)")
        if not f:
            return

        def _ser(o):
            return ce.iso(o) if isinstance(o, datetime.datetime) else o
        with open(f, "w", encoding="utf-8") as fh:
            json.dump(self._result, fh, default=_ser, ensure_ascii=False, indent=2)
        self._append_log("OK", f"JSON gespeichert: {f}")
        QMessageBox.information(self, "Export", f"JSON gespeichert:\n{f}")

    # ── Lifecycle ───────────────────────────────────────────────────────
    def reset(self):
        self._result = None
        for c in (self.card_usb, self.card_find, self.card_high, self.card_usn):
            self._set_card(c, 0)
        for t in (self.tbl_find, self.tbl_usb, self.tbl_shell, self.tbl_usn):
            t.setRowCount(0)
        self.tabs.setTabText(0, "COPY INDICATORS")
        self.tabs.setTabText(1, "USB DEVICES")
        self.tabs.setTabText(2, "SHELLBAGS")
        self.tabs.setTabText(3, "USN JOURNAL")
        self.log_text.clear()
        self.btn_html.setEnabled(False)
        self.btn_json.setEnabled(False)

    def load_result(self, result):
        # CopyTrace is disk-oriented and does not consume run_forensic output;
        # this hook exists for interface symmetry with the other views.
        pass
