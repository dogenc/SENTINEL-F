"""
╔══════════════════════════════════════════════════════════════╗
║   WATCH VIEW — Ordner überwachen, neue Dateien sofort prüfen  ║
╚══════════════════════════════════════════════════════════════╝

Neue Dateien in den überwachten Ordnern (Standard: Downloads) werden sofort
im Sandbox-Worker analysiert, im Verlauf (Fall "Watch-Folder") abgelegt und
ab einer wählbaren Stufe per Tray-Benachrichtigung gemeldet.
"""
import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QObject, pyqtSignal, QSettings
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QCheckBox, QComboBox,
    QListWidget, QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QFrame
)

from config.settings import T, SCORE_LEVELS, DATA_DIR
from core.utils import LOG
from core.watcher import FolderWatcher, default_download_dir

LEVEL_COLOR = {label: T.get(key, T["text"]) for _, label, key in SCORE_LEVELS}
LEVEL_RANK = {label: i for i, (_, label, _k) in enumerate(SCORE_LEVELS)}
ALERT_LEVELS = [label for _, label, _k in SCORE_LEVELS[1:]]      # ab LOW RISK
WATCH_CASE = "Watch-Folder"
MAX_FEED = 500

COLUMNS = ["TIME", "FILE", "FOLDER", "SCORE", "LEVEL", "HEADLINE"]


class _Bridge(QObject):
    result = pyqtSignal(str, dict)
    event  = pyqtSignal(str, str)


class WatchView(QWidget):
    openRequested = pyqtSignal(int)        # history analysis_id
    alert         = pyqtSignal(dict)       # Zeile, die die Alarmschwelle erreicht
    stateChanged  = pyqtSignal(bool)

    def __init__(self, parent=None, analyze_fn=None, history=None, settings=None):
        super().__init__(parent)
        self.analyze_fn = analyze_fn
        self.history = history
        self._settings = settings
        self._watcher = None
        self._checked = 0
        self._alerts = 0
        self.bridge = _Bridge()
        self.bridge.result.connect(self._on_result)
        self.bridge.event.connect(self._on_event)
        self._build()
        self._load_settings()

    @property
    def settings(self):
        if self._settings is None:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            self._settings = QSettings(str(DATA_DIR / "watch.ini"), QSettings.Format.IniFormat)
        return self._settings

    # ── UI ────────────────────────────────────────────────────────────
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        top = QHBoxLayout()
        title = QLabel("▸  WATCH  ·  LIVE FOLDER GUARD")
        title.setObjectName("SectionHeader")
        top.addWidget(title)
        top.addStretch(1)
        self.lbl_state = QLabel()
        top.addWidget(self.lbl_state)
        root.addLayout(top)

        body = QHBoxLayout()
        body.setSpacing(12)

        # Linke Spalte: Ordner + Optionen
        left = QFrame()
        left.setObjectName("Card")
        left.setFixedWidth(380)
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 12, 12, 12)
        ll.setSpacing(8)
        lbl = QLabel("WATCHED FOLDERS")
        lbl.setObjectName("CardTitle")
        ll.addWidget(lbl)
        self.lst_folders = QListWidget()
        self.lst_folders.setMinimumHeight(120)
        self.lst_folders.itemSelectionChanged.connect(self._update_buttons)
        ll.addWidget(self.lst_folders)
        row = QHBoxLayout()
        self.btn_add = QPushButton("＋ ADD")
        self.btn_add.setObjectName("NavBtn")
        self.btn_add.clicked.connect(self._add_folder)
        self.btn_dl = QPushButton("＋  ADD MY DOWNLOADS FOLDER")
        self.btn_dl.setObjectName("NavBtn")
        self.btn_dl.clicked.connect(lambda: self.add_folder(default_download_dir()))
        self.btn_remove = QPushButton("REMOVE")
        self.btn_remove.setObjectName("NavBtn")
        self.btn_remove.clicked.connect(self._remove_folder)
        for b in (self.btn_add, self.btn_remove):
            row.addWidget(b)
        ll.addLayout(row)
        ll.addWidget(self.btn_dl)

        ll.addSpacing(6)
        self.chk_recursive = QCheckBox("Include subfolders")
        ll.addWidget(self.chk_recursive)
        self.chk_tray = QCheckBox("Keep watching in the tray when the window is closed")
        self.chk_tray.setChecked(True)
        ll.addWidget(self.chk_tray)
        arow = QHBoxLayout()
        la = QLabel("ALERT FROM")
        la.setObjectName("CardTitle")
        arow.addWidget(la)
        self.cmb_alert = QComboBox()
        self.cmb_alert.addItems(ALERT_LEVELS)
        self.cmb_alert.setCurrentText("ELEVATED")
        arow.addWidget(self.cmb_alert, stretch=1)
        ll.addLayout(arow)
        for w in (self.chk_recursive, self.chk_tray):
            w.toggled.connect(self._save_settings)
        self.cmb_alert.currentTextChanged.connect(self._save_settings)

        ll.addSpacing(6)
        self.btn_toggle = QPushButton()
        self.btn_toggle.setMinimumHeight(40)
        self.btn_toggle.clicked.connect(self.toggle)
        ll.addWidget(self.btn_toggle)

        note = QLabel("Only files that appear AFTER watching starts are checked. Unfinished downloads "
                      "(.crdownload, .part …) are ignored until they are complete. Every file is "
                      "analysed in its own sandbox and saved to the case “Watch-Folder”.")
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{T['text_mute']}; font-size:8pt;")
        ll.addWidget(note)
        ll.addStretch(1)
        body.addWidget(left)

        # Rechte Spalte: Live-Feed
        right = QVBoxLayout()
        lf = QLabel("▸  LIVE FEED")
        lf.setObjectName("CardTitle")
        right.addWidget(lf)
        t = QTableWidget(0, len(COLUMNS))
        t.setHorizontalHeaderLabels(COLUMNS)
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.verticalHeader().setVisible(False)
        t.setWordWrap(False)
        hh = t.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.setStretchLastSection(True)
        for col, w in enumerate((80, 240, 180, 70, 96)):
            t.setColumnWidth(col, w)
        t.setStyleSheet(
            f"QTableWidget{{background:{T['bg']}; alternate-background-color:{T['bg_alt']};"
            f"gridline-color:{T['grid']}; border:1px solid {T['border']}; color:{T['text']};}}"
            f"QTableWidget::item:selected{{background:{T['border_hot']};}}"
            f"QHeaderView::section{{background:{T['panel']}; color:{T['text_mute']};"
            f"padding:6px 8px; border:none; border-bottom:1px solid {T['border']};}}"
        )
        t.doubleClicked.connect(self._open_row)
        self.table = t
        right.addWidget(t, stretch=1)
        body.addLayout(right, stretch=1)
        root.addLayout(body, stretch=1)
        self._render_state()

    # ── Ordner ────────────────────────────────────────────────────────
    def folders(self):
        return [self.lst_folders.item(i).text() for i in range(self.lst_folders.count())]

    def add_folder(self, path):
        path = str(Path(path))
        if path and path not in self.folders() and Path(path).is_dir():
            self.lst_folders.addItem(path)
            self._save_settings()
            if self.watching:            # neue Ordner sofort mit überwachen
                self.stop()
                self.start()
        self._update_buttons()

    def _add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select folder to watch")
        if d:
            self.add_folder(d)

    def _remove_folder(self):
        for it in self.lst_folders.selectedItems():
            self.lst_folders.takeItem(self.lst_folders.row(it))
        self._save_settings()
        if self.watching:
            self.stop()
            if self.folders():
                self.start()
        self._update_buttons()

    def _update_buttons(self):
        self.btn_remove.setEnabled(bool(self.lst_folders.selectedItems()))
        self.btn_toggle.setEnabled(self.watching or bool(self.folders()))

    # ── Einstellungen ─────────────────────────────────────────────────
    def _load_settings(self):
        s = self.settings
        folders = s.value("folders", [], type=list) or []
        self.lst_folders.clear()
        for f in folders:
            if f and Path(f).is_dir():
                self.lst_folders.addItem(f)
        self.chk_recursive.setChecked(s.value("recursive", False, type=bool))
        self.chk_tray.setChecked(s.value("tray", True, type=bool))
        lvl = s.value("alert_level", "ELEVATED", type=str)
        if lvl in ALERT_LEVELS:
            self.cmb_alert.setCurrentText(lvl)
        self._update_buttons()

    def _save_settings(self, *_):
        s = self.settings
        s.setValue("folders", self.folders())
        s.setValue("recursive", self.chk_recursive.isChecked())
        s.setValue("tray", self.chk_tray.isChecked())
        s.setValue("alert_level", self.cmb_alert.currentText())
        s.setValue("active", self.watching)
        s.sync()

    def autostart(self):
        """Überwachung fortsetzen, wenn sie beim letzten Beenden aktiv war."""
        if self.settings.value("active", False, type=bool) and self.folders():
            self.start()

    @property
    def keep_in_tray(self):
        return self.chk_tray.isChecked()

    # ── Steuerung ─────────────────────────────────────────────────────
    @property
    def watching(self):
        return self._watcher is not None

    def toggle(self):
        self.stop() if self.watching else self.start()

    def start(self):
        if self.watching or not self.folders() or not self.analyze_fn:
            return
        self._watcher = FolderWatcher(
            self.folders(), self.analyze_fn, recursive=self.chk_recursive.isChecked(),
            on_result=lambda p, r: self.bridge.result.emit(p, r),
            on_event=lambda k, p: self.bridge.event.emit(k, p),
            log_fn=lambda m, l="INFO": LOG.log(m, "DEBUG" if l in ("INFO", "OK") else l),
        ).start()
        self.chk_recursive.setEnabled(False)
        LOG.log(f"◉ Watching {len(self.folders())} folder(s): {', '.join(self.folders())}", "OK")
        self._after_state_change()

    def stop(self):
        if not self._watcher:
            return
        w, self._watcher = self._watcher, None
        w.stop()
        self.chk_recursive.setEnabled(True)
        LOG.log("◌ Folder watch stopped", "INFO")
        self._after_state_change()

    def _after_state_change(self):
        self._save_settings()
        self._render_state()
        self._update_buttons()
        self.stateChanged.emit(self.watching)

    def _render_state(self):
        if self.watching:
            self.btn_toggle.setText("■  STOP WATCHING")
            self.btn_toggle.setObjectName("DangerBtn")
            self.lbl_state.setText(f"●  WATCHING  ·  {self._checked} CHECKED  ·  {self._alerts} ALERTS")
            self.lbl_state.setStyleSheet(f"color:{T['accent']}; font-weight:bold; letter-spacing:1px;")
        else:
            self.btn_toggle.setText("◉  START WATCHING")
            self.btn_toggle.setObjectName("PrimaryBtn")
            self.lbl_state.setText("○  NOT WATCHING")
            self.lbl_state.setStyleSheet(f"color:{T['text_mute']}; font-weight:bold; letter-spacing:1px;")
        self.btn_toggle.style().unpolish(self.btn_toggle)
        self.btn_toggle.style().polish(self.btn_toggle)

    # ── Ergebnisse ────────────────────────────────────────────────────
    def _on_event(self, kind, path):
        if kind == "queued":
            LOG.log(f"Watch: new file {Path(path).name} → sandbox", "INFO")

    def _watch_case_id(self):
        if not self.history:
            return None
        db = self.history.db
        for c in db.list_cases():
            if c["name"] == WATCH_CASE:
                return c["id"]
        try:
            return db.create_case(WATCH_CASE, "Files checked automatically by the folder watch")
        except ValueError:
            return None

    def _on_result(self, path, res):
        self._checked += 1
        row = {"time": datetime.datetime.now().strftime("%H:%M:%S"), "path": path,
               "name": Path(path).name, "folder": str(Path(path).parent), "id": None,
               "ok": bool(res.get("ok")), "score": None, "level": "ERROR",
               "headline": res.get("error") or ""}
        if row["ok"]:
            sc, th = res.get("score") or {}, res.get("threat") or {}
            row.update(score=int(sc.get("score") or 0), level=sc.get("level") or "",
                       headline=th.get("headline") or "")
            if self.history:
                try:
                    row["id"], _prev = self.history.record(res, case_id=self._watch_case_id(), refresh=False)
                except Exception as e:
                    LOG.log(f"History: could not save {row['name']}: {e}", "WARN")
        self._add_row(row)
        is_alert = row["ok"] and LEVEL_RANK.get(row["level"], 0) >= LEVEL_RANK[self.cmb_alert.currentText()]
        LOG.log(f"Watch: {row['name']} → {row['level']} {row['score'] if row['ok'] else ''}",
                "WARN" if is_alert else "OK")
        if is_alert:
            self._alerts += 1
            self.alert.emit(row)
        self._render_state()

    def _add_row(self, row):
        t = self.table
        t.insertRow(0)
        color = QColor(LEVEL_COLOR.get(row["level"], T["err"]))
        vals = [row["time"], row["name"], row["folder"], "—" if row["score"] is None else str(row["score"]),
                row["level"], row["headline"]]
        for c, v in enumerate(vals):
            it = QTableWidgetItem(v)
            if c == 0:
                it.setData(Qt.ItemDataRole.UserRole, row["id"])
            if c == 1:
                it.setToolTip(row["path"])
            if c in (3, 4):
                it.setForeground(color)
            t.setItem(0, c, it)
        while t.rowCount() > MAX_FEED:
            t.removeRow(t.rowCount() - 1)

    def _open_row(self, index):
        aid = self.table.item(index.row(), 0).data(Qt.ItemDataRole.UserRole)
        if aid is not None:
            self.openRequested.emit(int(aid))
