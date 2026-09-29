"""
╔══════════════════════════════════════════════════════════════╗
║   THUMBNAILS VIEW — Windows Thumbnail-Cache Forensics        ║
║   Recovers preview images from thumbcache_*.db (deleted-safe) ║
╚══════════════════════════════════════════════════════════════╝

Eigenstaendiger View: extrahiert Vorschaubilder aus den Windows-Thumbnail-
Caches einer gemounteten Platte und zeigt sie als Galerie. Read-only.

Beweiswert: ein Thumbnail belegt, dass ein Bild dem System bekannt war —
oft auch dann noch, wenn die Originaldatei geloescht oder auf einen USB-Stick
verschoben wurde. Pfade sind in Thumbcaches NICHT enthalten (nur Hash-IDs).
"""
import os
import json
import threading
import traceback

from PyQt6.QtCore import Qt, QObject, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QPixmap, QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QMessageBox, QTabWidget, QTableWidget,
    QTableWidgetItem, QPlainTextEdit, QFrame, QHeaderView, QAbstractItemView,
    QProgressBar, QScrollArea
)

from config.settings import T, FONT_MONO, REPORT_DIR, CACHE_DIR
from core.utils import LOG

try:
    from engines.thumbcache_engine import ThumbcacheEngine
    _TE_ERR = None
except Exception as _e:
    ThumbcacheEngine = None
    _TE_ERR = str(_e)


# ── Thread bridge ─────────────────────────────────────────────────────────────
class _TBridge(QObject):
    log    = pyqtSignal(str, str)
    done   = pyqtSignal(dict)
    failed = pyqtSignal(str)


# ── Thumbnail tile ────────────────────────────────────────────────────────────
class _ThumbTile(QFrame):
    def __init__(self, thumb):
        super().__init__()
        self.setObjectName("Card")
        self.setFixedSize(150, 180)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 6, 6, 6)
        lay.setSpacing(4)

        img = QLabel()
        img.setAlignment(Qt.AlignmentFlag.AlignCenter)
        img.setFixedHeight(120)
        img.setStyleSheet(f"background:{T['bg']}; border:1px solid {T['border']};")
        p = thumb.get("saved_path")
        if p and os.path.exists(p):
            pix = QPixmap(p)
            if not pix.isNull():
                img.setPixmap(pix.scaled(
                    QSize(132, 116),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation))
            else:
                img.setText("?")
        else:
            img.setText("—")
        lay.addWidget(img)

        meta = QLabel(f"{thumb.get('source_db','').replace('thumbcache_','').replace('.db','')}"
                      f" · {thumb.get('image_ext','').upper()}")
        meta.setStyleSheet(f"color:{T['cyan']}; font-size:8pt;")
        meta.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(meta)

        idl = QLabel(thumb.get("entry_id", "")[:16])
        idl.setStyleSheet(f"color:{T['text_mute']}; font-size:7pt;")
        idl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(idl)


# ══════════════════════════════════════════════════════════════════════════════
class ThumbnailsView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._result = None
        self._busy = False
        self._out_dir = os.path.join(str(CACHE_DIR), "thumbnails")

        self.bridge = _TBridge()
        self.bridge.log.connect(self._append_log)
        self.bridge.done.connect(self._on_done)
        self.bridge.failed.connect(self._on_failed)

        self._build()

    # ── UI ────────────────────────────────────────────────────────────
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        top = QHBoxLayout()
        title = QLabel("▸  THUMBNAILS  ·  WINDOWS THUMBNAIL-CACHE FORENSICS")
        title.setObjectName("SectionHeader")
        top.addWidget(title)
        top.addStretch(1)
        self.btn_save = QPushButton("EXPORT JSON")
        self.btn_save.clicked.connect(self._export_json)
        self.btn_open_dir = QPushButton("OPEN FOLDER")
        self.btn_open_dir.clicked.connect(self._open_out_dir)
        for b in (self.btn_save, self.btn_open_dir):
            b.setEnabled(False)
            top.addWidget(b)
        root.addLayout(top)

        note = QLabel(
            "ⓘ  Vorschaubilder bleiben oft erhalten, auch wenn die Originaldatei "
            "geloescht oder auf einen USB-Stick verschoben wurde. "
            "Thumbcaches enthalten KEINE Dateipfade — nur Bilddaten + Hash-IDs."
        )
        note.setWordWrap(True)
        note.setStyleSheet(
            f"color:{T['text_dim']}; background:{T['card']}; "
            f"border-left:3px solid {T['cyan']}; border-radius:4px; "
            f"padding:8px 12px; font-size:9pt;"
        )
        root.addWidget(note)

        # Path row
        prow = QHBoxLayout()
        lbl = QLabel("EVIDENCE PATH")
        lbl.setObjectName("CardTitle")
        prow.addWidget(lbl)
        self.root_edit = QLineEdit()
        self.root_edit.setPlaceholderText(
            "Wurzel der Windows-Partition (enthaelt Users\\), z.B. E:\\ oder /mnt/evidence")
        self.root_edit.setStyleSheet(
            f"QLineEdit{{background:{T['card']}; border:1px solid {T['border']};"
            f"border-radius:6px; padding:7px 10px; color:{T['text']};}}"
            f"QLineEdit:focus{{border:1px solid {T['accent']};}}"
        )
        prow.addWidget(self.root_edit, stretch=1)
        b1 = QPushButton("BROWSE")
        b1.setObjectName("NavBtn")
        b1.clicked.connect(self._pick_root)
        prow.addWidget(b1)
        self.btn_run = QPushButton("▶  EXTRACT THUMBNAILS")
        self.btn_run.setObjectName("PrimaryBtn")
        self.btn_run.clicked.connect(self._run)
        prow.addWidget(self.btn_run)
        root.addLayout(prow)

        # Stat cards
        cards = QHBoxLayout()
        cards.setSpacing(10)
        self.card_db    = self._stat_card("CACHE FILES")
        self.card_thumb = self._stat_card("THUMBNAILS")
        for c in (self.card_db, self.card_thumb):
            cards.addWidget(c["frame"])
        self.progress = QProgressBar()
        self.progress.setFixedWidth(200)
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.hide()
        cards.addWidget(self.progress)
        cards.addStretch(1)
        root.addLayout(cards)

        # Tabs: Gallery + Caches table
        self.tabs = QTabWidget()

        # Gallery tab (scrollable grid)
        gal_wrap = QWidget()
        gal_outer = QVBoxLayout(gal_wrap)
        gal_outer.setContentsMargins(0, 0, 0, 0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setStyleSheet(f"background:{T['bg']};")
        self.gallery_host = QWidget()
        self.gallery_grid = QGridLayout(self.gallery_host)
        self.gallery_grid.setContentsMargins(6, 6, 6, 6)
        self.gallery_grid.setSpacing(8)
        self.gallery_grid.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.scroll.setWidget(self.gallery_host)
        gal_outer.addWidget(self.scroll)
        self.tabs.addTab(gal_wrap, "GALLERY")

        # Caches table
        self.tbl_db = QTableWidget(0, 5)
        self.tbl_db.setHorizontalHeaderLabels(
            ["CACHE DB", "USER", "THUMBNAILS", "DB SIZE", "PATH"])
        self._style_table(self.tbl_db)
        self.tabs.addTab(self.tbl_db, "CACHE FILES")

        root.addWidget(self.tabs, stretch=3)

        # Log
        log_hdr = QLabel("▸  ANALYSIS LOG")
        log_hdr.setObjectName("CardTitle")
        root.addWidget(log_hdr)
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont(FONT_MONO, 9))
        self.log_text.setMaximumHeight(130)
        self.log_text.setStyleSheet(
            f"background:{T['bg']}; color:{T['text_dim']}; border:1px solid {T['border']};")
        root.addWidget(self.log_text, stretch=1)

        if ThumbcacheEngine is None:
            self._append_log("ERR", f"Thumbcache-Engine nicht geladen: {_TE_ERR}")
            self.btn_run.setEnabled(False)

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

    def _style_table(self, t):
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.verticalHeader().setVisible(False)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        t.setStyleSheet(
            f"QTableWidget{{background:{T['bg']}; alternate-background-color:{T['bg_alt']};"
            f"gridline-color:{T['grid']}; border:1px solid {T['border']}; color:{T['text']};}}"
            f"QTableWidget::item:selected{{background:{T['border_hot']};}}"
            f"QHeaderView::section{{background:{T['panel']}; color:{T['text_mute']};"
            f"padding:6px 8px; border:none; border-bottom:1px solid {T['border']};}}"
        )

    # ── Dialogs ─────────────────────────────────────────────────────────
    def _pick_root(self):
        d = QFileDialog.getExistingDirectory(self, "Select Windows partition root")
        if d:
            self.root_edit.setText(d)

    def _open_out_dir(self):
        path = self._out_dir
        if not os.path.isdir(path):
            return
        # Plattformneutral oeffnen
        import subprocess, sys
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)            # noqa
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            QMessageBox.information(self, "Folder", path)

    # ── Log ─────────────────────────────────────────────────────────────
    def _append_log(self, level, msg):
        col = {"INFO": T["info"], "OK": T["ok"], "WARN": T["warn"],
               "ERR": T["err"]}.get(level, T["info"])
        tag = {"INFO": "[*]", "OK": "[+]", "WARN": "[!]", "ERR": "[x]"}.get(level, "[ ]")
        self.log_text.appendHtml(
            f"<span style='color:{col};'>{tag}</span> "
            f"<span style='color:{T['text_dim']};'>{self._esc(msg)}</span>")
        try:
            LOG.log(f"[Thumbnails] {msg}",
                    level if level in ("INFO", "OK", "WARN", "ERR") else "INFO")
        except Exception:
            pass

    @staticmethod
    def _esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # ── Run ─────────────────────────────────────────────────────────────
    def _run(self):
        if self._busy or ThumbcacheEngine is None:
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
        self._clear_gallery()
        self.btn_run.setEnabled(False)
        self.btn_save.setEnabled(False)
        self.btn_open_dir.setEnabled(False)
        self.progress.show()

        def emit_log(msg, level="INFO"):
            self.bridge.log.emit(level, msg)

        def worker():
            try:
                eng = ThumbcacheEngine(root, log_fn=emit_log)
                res = eng.run(self._out_dir)
                self.bridge.done.emit(res)
            except Exception as e:
                self.bridge.failed.emit(f"{type(e).__name__}: {e}\n{traceback.format_exc()}")

        threading.Thread(target=worker, daemon=True).start()

    # ── Bridge handlers ─────────────────────────────────────────────────
    def _on_failed(self, msg):
        self._busy = False
        self.progress.hide()
        self.btn_run.setEnabled(True)
        self._append_log("ERR", "FEHLER: " + msg.splitlines()[0])
        QMessageBox.critical(self, "Thumbnail extraction failed", msg[:800])

    def _on_done(self, res):
        self._busy = False
        self._result = res
        self.progress.hide()
        self.btn_run.setEnabled(True)
        self.btn_save.setEnabled(True)
        self.btn_open_dir.setEnabled(True)
        self._populate(res)

    # ── Populate ────────────────────────────────────────────────────────
    def _populate(self, r):
        self._set_card(self.card_db, len(r["databases"]))
        self._set_card(self.card_thumb, r["total"], accent=True)

        # Caches table
        self.tbl_db.setRowCount(0)
        for d in r["databases"]:
            row = self.tbl_db.rowCount()
            self.tbl_db.insertRow(row)
            cells = [
                (d["db"], T["text_hot"]),
                (d["user"], None),
                (str(d["count"]), T["accent"] if d["count"] else T["text_mute"]),
                (d["size_label"], None),
                (d["path"], T["text_mute"]),
            ]
            for c, (txt, col) in enumerate(cells):
                it = QTableWidgetItem(str(txt))
                if col:
                    it.setForeground(QColor(col))
                self.tbl_db.setItem(row, c, it)
        self.tbl_db.resizeColumnsToContents()
        self.tbl_db.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        # Gallery
        self._clear_gallery()
        cols = 6
        for i, t in enumerate(r["thumbnails"]):
            tile = _ThumbTile(t)
            self.gallery_grid.addWidget(tile, i // cols, i % cols)

        self.tabs.setTabText(0, f"GALLERY ({r['total']})")
        self.tabs.setTabText(1, f"CACHE FILES ({len(r['databases'])})")

        if r["total"] == 0:
            self._append_log("WARN", "Keine Thumbnails extrahiert.")

    def _clear_gallery(self):
        while self.gallery_grid.count():
            item = self.gallery_grid.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _set_card(self, card, value, accent=False):
        card["num"].setText(str(value))
        col = T["accent"] if (accent and value) else (T["cyan"] if accent else T["accent"])
        card["num"].setStyleSheet(f"color:{col}; font-size:24pt; font-weight:bold;")

    # ── Export ──────────────────────────────────────────────────────────
    def _export_json(self):
        if not self._result:
            return
        default = str(REPORT_DIR / "thumbnails_report.json")
        f, _ = QFileDialog.getSaveFileName(self, "Save JSON", default, "JSON (*.json)")
        if not f:
            return
        with open(f, "w", encoding="utf-8") as fh:
            json.dump(self._result, fh, ensure_ascii=False, indent=2)
        self._append_log("OK", f"JSON gespeichert: {f}")
        QMessageBox.information(self, "Export",
                                f"JSON gespeichert:\n{f}\n\n"
                                f"Bilder liegen in:\n{self._out_dir}")

    # ── Lifecycle ───────────────────────────────────────────────────────
    def reset(self):
        self._result = None
        self._set_card(self.card_db, 0)
        self._set_card(self.card_thumb, 0)
        self.tbl_db.setRowCount(0)
        self._clear_gallery()
        self.tabs.setTabText(0, "GALLERY")
        self.tabs.setTabText(1, "CACHE FILES")
        self.log_text.clear()
        self.btn_save.setEnabled(False)
        self.btn_open_dir.setEnabled(False)

    def load_result(self, result):
        # disk-oriented; not driven by run_forensic. Interface symmetry only.
        pass
