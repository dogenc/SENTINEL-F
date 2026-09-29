"""
╔══════════════════════════════════════════════════════════════╗
║   HISTORY VIEW — Analyse-Verlauf, Fälle & IOC-Suche          ║
╚══════════════════════════════════════════════════════════════╝

Zeigt alle gespeicherten Analysen (core/history.py). Gespeicherte Ergebnisse
lassen sich ohne erneute Analyse wieder öffnen; die Datei wird dabei nicht
angefasst. Der gewählte Fall ist gleichzeitig der Ablageort für neue Analysen.
"""
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView, QInputDialog,
    QMessageBox, QMenu
)

from config.settings import T, SCORE_LEVELS
from core.utils import LOG

LEVEL_COLOR = {label: T.get(key, T["text"]) for _, label, key in SCORE_LEVELS}

# Einträge der Fall-Auswahl: (Anzeigetext, case_id-Filter)
ALL_CASES, NO_CASE = None, 0

COLUMNS = ["TIME", "FILE", "KIND", "SCORE", "LEVEL", "CASE", "SHA-256", "HEADLINE"]


class HistoryView(QWidget):
    openRequested = pyqtSignal(int)        # analysis_id
    routeOnGlobe = pyqtSignal(dict)        # Bewegungsprofil → Globus

    def __init__(self, parent=None, db=None):
        super().__init__(parent)
        self._db = db
        self._rows = []
        self._case_names = {}
        self._build()
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(250)
        self._search_timer.timeout.connect(self.refresh)
        self.reload_cases()

    @property
    def db(self):
        if self._db is None:
            from core.history import default_db
            self._db = default_db()
        return self._db

    # ── UI ────────────────────────────────────────────────────────────
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        top = QHBoxLayout()
        title = QLabel("▸  HISTORY  ·  CASES  ·  IOC SEARCH")
        title.setObjectName("SectionHeader")
        top.addWidget(title)
        top.addStretch(1)
        self.lbl_stats = QLabel("")
        self.lbl_stats.setStyleSheet(f"color:{T['text_mute']}; font-size:8pt; letter-spacing:1px;")
        top.addWidget(self.lbl_stats)
        root.addLayout(top)

        # Filterzeile
        bar = QHBoxLayout()
        bar.setSpacing(8)
        lbl_case = QLabel("CASE")
        lbl_case.setObjectName("CardTitle")
        bar.addWidget(lbl_case)
        self.cmb_case = QComboBox()
        self.cmb_case.setMinimumWidth(240)
        self.cmb_case.currentIndexChanged.connect(self._on_case_changed)
        bar.addWidget(self.cmb_case)
        self.btn_new_case = QPushButton("＋  NEW CASE")
        self.btn_new_case.setObjectName("NavBtn")
        self.btn_new_case.clicked.connect(self._new_case)
        bar.addWidget(self.btn_new_case)
        self.btn_route = QPushButton("🗺  ROUTE")
        self.btn_route.setObjectName("NavBtn")
        self.btn_route.setToolTip("Movement profile of all geotagged photos in the selected scope")
        self.btn_route.clicked.connect(lambda: self.show_route())
        bar.addWidget(self.btn_route)
        self.btn_case_report = QPushButton("📄  CASE REPORT")
        self.btn_case_report.setObjectName("NavBtn")
        self.btn_case_report.clicked.connect(lambda: self.export_case_report())
        bar.addWidget(self.btn_case_report)
        self.btn_verify = QPushButton("✔  VERIFY REPORT")
        self.btn_verify.setObjectName("NavBtn")
        self.btn_verify.setToolTip("Check the Ed25519 signature (and RFC 3161 time-stamp) of a saved report")
        self.btn_verify.clicked.connect(lambda: self._verify_report())
        bar.addWidget(self.btn_verify)
        self.btn_del_case = QPushButton("DELETE CASE")
        self.btn_del_case.setObjectName("NavBtn")
        self.btn_del_case.clicked.connect(self._delete_case)
        bar.addWidget(self.btn_del_case)

        bar.addStretch(1)
        root.addLayout(bar)
        bar = QHBoxLayout()                  # eigene Zeile für die Suche
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search: file name · path · MD5/SHA prefix · URL / IP / domain / e-mail (IOC)")
        self.search.setClearButtonEnabled(True)
        self.search.setStyleSheet(
            f"QLineEdit{{background:{T['card']}; border:1px solid {T['border']};"
            f"border-radius:6px; padding:7px 10px; color:{T['text']};}}"
            f"QLineEdit:focus{{border:1px solid {T['accent']};}}"
        )
        self.search.textChanged.connect(lambda _: self._search_timer.start())
        bar.addWidget(self.search, stretch=1)
        root.addLayout(bar)

        self.lbl_active = QLabel("")
        self.lbl_active.setWordWrap(True)
        self.lbl_active.setStyleSheet(
            f"color:{T['text_dim']}; background:{T['card']}; border-left:3px solid {T['cyan']};"
            f"border-radius:4px; padding:6px 12px; font-size:9pt;"
        )
        root.addWidget(self.lbl_active)

        # Tabelle
        t = QTableWidget(0, len(COLUMNS))
        t.setHorizontalHeaderLabels(COLUMNS)
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        t.verticalHeader().setVisible(False)
        t.setWordWrap(False)
        t.setSortingEnabled(True)
        hh = t.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.setStretchLastSection(True)
        for col, w in enumerate((140, 220, 90, 76, 90, 150, 150)):
            t.setColumnWidth(col, w)
        t.setStyleSheet(
            f"QTableWidget{{background:{T['bg']}; alternate-background-color:{T['bg_alt']};"
            f"gridline-color:{T['grid']}; border:1px solid {T['border']}; color:{T['text']};}}"
            f"QTableWidget::item:selected{{background:{T['border_hot']};}}"
            f"QHeaderView::section{{background:{T['panel']}; color:{T['text_mute']};"
            f"padding:6px 8px; border:none; border-bottom:1px solid {T['border']};}}"
        )
        t.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        t.doubleClicked.connect(lambda _: self._open_selected())
        t.itemSelectionChanged.connect(self._update_buttons)
        t.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        t.customContextMenuRequested.connect(self._context_menu)
        self.table = t
        root.addWidget(t, stretch=1)

        # Aktionen
        act = QHBoxLayout()
        self.btn_open = QPushButton("▶  OPEN RESULT")
        self.btn_open.setObjectName("PrimaryBtn")
        self.btn_open.clicked.connect(self._open_selected)
        act.addWidget(self.btn_open)
        self.btn_assign = QPushButton("MOVE TO CASE…")
        self.btn_assign.setObjectName("NavBtn")
        self.btn_assign.clicked.connect(self._assign_selected)
        act.addWidget(self.btn_assign)
        self.btn_compare = QPushButton("⇄  COMPARE")
        self.btn_compare.setObjectName("NavBtn")
        self.btn_compare.setToolTip("Select exactly two analyses: before/after comparison")
        self.btn_compare.clicked.connect(lambda: self.compare_selected())
        act.addWidget(self.btn_compare)
        self.btn_delete = QPushButton("DELETE")
        self.btn_delete.setObjectName("DangerBtn")
        self.btn_delete.clicked.connect(self._delete_selected)
        act.addWidget(self.btn_delete)
        act.addStretch(1)
        self.btn_refresh = QPushButton("↻  REFRESH")
        self.btn_refresh.setObjectName("NavBtn")
        self.btn_refresh.clicked.connect(self.refresh)
        act.addWidget(self.btn_refresh)
        root.addLayout(act)
        self._update_buttons()

    # ── Fälle ─────────────────────────────────────────────────────────
    def reload_cases(self, select_id=None):
        keep = self.current_case_filter() if select_id is None else select_id
        self.cmb_case.blockSignals(True)
        self.cmb_case.clear()
        self.cmb_case.addItem("◇  ALL ANALYSES", ALL_CASES)
        self.cmb_case.addItem("◇  UNFILED (no case)", NO_CASE)
        cases = self.db.list_cases()
        self._case_names = {c["id"]: c["name"] for c in cases}
        for c in cases:
            self.cmb_case.addItem(f"▣  {c['name']}  ·  {c['analyses']}", c["id"])
        idx = self.cmb_case.findData(keep)
        self.cmb_case.setCurrentIndex(idx if idx >= 0 else 0)
        self.cmb_case.blockSignals(False)
        self._on_case_changed()

    def current_case_filter(self):
        return self.cmb_case.currentData() if self.cmb_case.count() else ALL_CASES

    def active_case_id(self):
        """Fall, in dem neue Analysen abgelegt werden (None = ohne Fall)."""
        cid = self.current_case_filter()
        return cid if cid else None

    def _on_case_changed(self, *_):
        cid = self.active_case_id()
        self.btn_del_case.setEnabled(cid is not None)
        self.btn_case_report.setEnabled(cid is not None)
        if cid is None:
            self.lbl_active.setText("New analyses are saved to the history without a case. "
                                    "Select or create a case to file them there.")
        else:
            self.lbl_active.setText(f"New analyses are filed into case  ▣ {self._case_names.get(cid, '?')}")
        self.refresh()

    def _new_case(self):
        name, ok = QInputDialog.getText(self, "New case", "Case name (e.g. incident or ticket number):")
        if not ok or not name.strip():
            return
        try:
            cid = self.db.create_case(name)
        except ValueError as e:
            QMessageBox.warning(self, "New case", str(e))
            return
        LOG.log(f"Case created: {name.strip()}", "OK")
        self.reload_cases(select_id=cid)

    def show_route(self, exec_dialog=True):
        from core.geo import route_from_db
        from .route_dialog import RouteDialog
        route = route_from_db(self.db, case_id=self.current_case_filter())
        cid = self.active_case_id()
        dlg = RouteDialog(self, route, self._case_names.get(cid, "all analyses"))
        dlg.showOnGlobe.connect(self.routeOnGlobe.emit)
        if exec_dialog:
            dlg.exec()
        return dlg

    def _verify_report(self, path=None):
        from .report_dialog import verify_dialog
        return verify_dialog(self, path)

    def export_case_report(self):
        cid = self.active_case_id()
        if cid is None:
            return None
        from core.report import case_report_html
        from .report_dialog import save_report
        return save_report(self, lambda ex: case_report_html(self.db, cid, examiner=ex),
                           f"case_{self._case_names.get(cid, cid)}")

    def _delete_case(self):
        cid = self.active_case_id()
        if cid is None:
            return
        name = self._case_names.get(cid, "?")
        if QMessageBox.question(self, "Delete case",
                                f"Delete case '{name}'?\n\nIts analyses stay in the history as unfiled."
                                ) != QMessageBox.StandardButton.Yes:
            return
        self.db.delete_case(cid)
        LOG.log(f"Case deleted: {name}", "INFO")
        self.reload_cases(select_id=ALL_CASES)

    # ── Tabelle ───────────────────────────────────────────────────────
    def refresh(self):
        try:
            self._rows = self.db.list_analyses(case_id=self.current_case_filter(), search=self.search.text())
            st = self.db.stats()
        except Exception as e:
            LOG.log(f"History unavailable: {e}", "ERR")
            self._rows, st = [], None
        t = self.table
        t.setSortingEnabled(False)
        t.setRowCount(len(self._rows))
        for r, row in enumerate(self._rows):
            level = row.get("level") or ""
            vals = [row.get("analyzed_at") or "", row.get("name") or "", row.get("kind") or "",
                    row.get("score"), level, row.get("case_name") or "—",
                    (row.get("sha256") or "")[:16] + "…", row.get("headline") or ""]
            for c, v in enumerate(vals):
                it = QTableWidgetItem()
                if c == 3:
                    it.setData(Qt.ItemDataRole.DisplayRole, int(v) if v is not None else -1)
                else:
                    it.setText(str(v))
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, row["id"])
                if c in (3, 4):
                    it.setForeground(QColor(LEVEL_COLOR.get(level, T["text"])))
                if c == 1:
                    it.setToolTip(row.get("path") or "")
                if c == 6:
                    it.setToolTip(row.get("sha256") or "")
                t.setItem(r, c, it)
        t.setSortingEnabled(True)
        if st:
            self.lbl_stats.setText(
                f"{st['analyses']} ANALYSES  ·  {st['files']} UNIQUE FILES  ·  "
                f"{st['high'] or 0} HIGH/CRIT  ·  {st['cases']} CASES")
        self._update_buttons()

    def _selected_ids(self):
        ids = []
        for idx in self.table.selectionModel().selectedRows(0):
            aid = self.table.item(idx.row(), 0).data(Qt.ItemDataRole.UserRole)
            if aid is not None:
                ids.append(int(aid))
        return ids

    def _update_buttons(self):
        n = len(self._selected_ids()) if self.table.selectionModel() else 0
        self.btn_open.setEnabled(n == 1)
        if hasattr(self, "btn_compare"):
            self.btn_compare.setEnabled(n == 2)
        self.btn_assign.setEnabled(n >= 1)
        self.btn_delete.setEnabled(n >= 1)

    def _open_selected(self):
        ids = self._selected_ids()
        if len(ids) == 1:
            self.openRequested.emit(ids[0])

    def compare_selected(self, exec_dialog=True, diff_fn=None, run_async=True):
        ids = self._selected_ids()
        if len(ids) != 2:
            return None
        from .diff_dialog import DiffDialog
        # ältere Analyse = A (vorher), neuere = B (nachher)
        rows = {r["id"]: r for r in self._rows}
        a, b = sorted(ids, key=lambda i: (rows.get(i, {}).get("analyzed_at", ""), i))
        dlg = DiffDialog(self, self.db.get_result(a), self.db.get_result(b), diff_fn=diff_fn, run_async=run_async)
        if exec_dialog:
            dlg.exec()
        return dlg

    def _assign_selected(self):
        ids = self._selected_ids()
        if not ids:
            return
        cases = self.db.list_cases()
        labels = ["— no case —"] + [c["name"] for c in cases]
        choice, ok = QInputDialog.getItem(self, "Move to case", f"Move {len(ids)} analysis(es) to:",
                                          labels, 0, False)
        if not ok:
            return
        cid = None if choice == labels[0] else cases[labels.index(choice) - 1]["id"]
        self.db.assign(ids, cid)
        self.reload_cases()

    def _delete_selected(self):
        ids = self._selected_ids()
        if not ids:
            return
        if QMessageBox.question(self, "Delete", f"Remove {len(ids)} analysis(es) from the history?\n"
                                "The files themselves are not touched.") != QMessageBox.StandardButton.Yes:
            return
        self.db.delete_analyses(ids)
        self.reload_cases()

    def _context_menu(self, pos):
        ids = self._selected_ids()
        if not ids:
            return
        row = next((r for r in self._rows if r["id"] == ids[0]), None)
        m = QMenu(self)
        if len(ids) == 1:
            m.addAction("Open result", self._open_selected)
            if row:
                from PyQt6.QtWidgets import QApplication
                cb = QApplication.clipboard()
                m.addAction("Copy SHA-256", lambda: cb.setText(row["sha256"]))
                m.addAction("Copy path", lambda: cb.setText(row["path"]))
                m.addAction("Show other analyses of this file",
                            lambda: self._filter_to(row["sha256"]))
                m.addAction("Show IOCs…", lambda: self._show_iocs(row))
            m.addSeparator()
        m.addAction("Move to case…", self._assign_selected)
        m.addAction("Delete", self._delete_selected)
        m.exec(self.table.viewport().mapToGlobal(pos))

    def _filter_to(self, text):
        idx = self.cmb_case.findData(ALL_CASES)
        self.cmb_case.setCurrentIndex(idx)
        self.search.setText(text)
        self.refresh()

    def _show_iocs(self, row):
        iocs = self.db.iocs_for(row["id"])
        if not iocs:
            QMessageBox.information(self, "IOCs", "No IOCs were recorded for this analysis.")
            return
        lines = [f"{i['type']:<8} {i['value']}" for i in iocs]
        box = QMessageBox(self)
        box.setWindowTitle(f"IOCs · {row['name']}")
        box.setText(f"{len(iocs)} IOC(s). Search any value above to find other files containing it.")
        box.setDetailedText("\n".join(lines))
        box.exec()

    # ── Öffentliche API für das Hauptfenster ─────────────────────────
    def record(self, result, case_id=None, refresh=True):
        """
        Speichert eine neue Analyse (Standard: im aktiven Fall). → (id, frühere Analysen)
        refresh=False für Stapel: die Tabelle wird dann erst am Ende einmal neu geladen.
        """
        aid = self.db.record(result, case_id=case_id if case_id is not None else self.active_case_id())
        prev = self.db.previous((result.get("hashes") or {}).get("sha256"), exclude_id=aid)
        if refresh:
            self.reload_cases()
        return aid, prev
