"""
╔══════════════════════════════════════════════════════════════╗
║   BATCH VIEW — Ordner-/Stapelanalyse (Triage)                ║
╚══════════════════════════════════════════════════════════════╝

Scannt einen Ordner (oder mehrere gezogene Dateien) parallel – jede Datei in
ihrem eigenen Sandbox-Worker – und zeigt eine nach Risiko sortierte Liste.
Alle Ergebnisse landen im Verlauf (optional in einem eigenen Fall), ein
Doppelklick öffnet die Detailanalyse.
"""
import csv
import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QObject, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit, QPushButton,
    QCheckBox, QSpinBox, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QFrame, QProgressBar, QMenu
)

from config.settings import T, SCORE_LEVELS, REPORT_DIR
from core.utils import LOG
from core.batch import collect_files, BatchRunner, default_workers, DEFAULT_MAX_FILES

LEVEL_COLOR = {label: T.get(key, T["text"]) for _, label, key in SCORE_LEVELS}
FLAG_MIN_SCORE = 40         # ab ELEVATED gilt eine Datei als auffällig

COLUMNS = ["FILE", "KIND", "SCORE", "LEVEL", "HEADLINE", "NOTE", "SHA-256"]


def _csv_safe(v):
    """Tabellenkalkulationen führen Zellen mit = + - @ als Formel aus – Dateinamen und
    Headlines stammen aus der untersuchten Datei, also neutralisieren (CSV-Injection)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


class _Bridge(QObject):
    result   = pyqtSignal(str, dict)
    finished = pyqtSignal(dict)
    mailbox  = pyqtSignal(dict, str, str)


class _NumItem(QTableWidgetItem):
    """Numerisch sortierbare Zelle."""
    def __init__(self, value, text=None):
        super().__init__(text if text is not None else str(value))
        self._v = value

    def __lt__(self, other):
        return self._v < getattr(other, "_v", 0)


class BatchView(QWidget):
    openRequested = pyqtSignal(int)          # history analysis_id
    busyChanged   = pyqtSignal(bool)

    def __init__(self, parent=None, analyze_fn=None, history=None):
        super().__init__(parent)
        self.analyze_fn = analyze_fn
        self.history = history                # gui.history_view.HistoryView
        self._runner = None
        self._root = None
        self._rows = []
        self._seen_hashes = {}
        self._case_id = None
        self.bridge = _Bridge()
        self.bridge.result.connect(self._on_result)
        self.bridge.finished.connect(self._on_finished)
        self.bridge.mailbox.connect(self._on_mailbox)
        self._build()

    # ── UI ────────────────────────────────────────────────────────────
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        top = QHBoxLayout()
        title = QLabel("▸  BATCH SCAN  ·  FOLDER TRIAGE")
        title.setObjectName("SectionHeader")
        top.addWidget(title)
        top.addStretch(1)
        self.btn_csv = QPushButton("EXPORT CSV")
        self.btn_csv.clicked.connect(self._export_csv)
        self.btn_csv.setEnabled(False)
        top.addWidget(self.btn_csv)
        self.btn_mailbox = QPushButton("📧  SCAN MAILBOX")
        self.btn_mailbox.setObjectName("NavBtn")
        self.btn_mailbox.setToolTip("Outlook PST/OST/MSG, Thunderbird/mbox, EML folder – every mail and attachment "
                                    "is analysed in the sandbox and filed into its own case")
        menu = QMenu(self.btn_mailbox)
        menu.addAction("Mailbox file (PST · OST · mbox · MSG · EML)…", lambda: self._pick_mailbox(folder=False))
        menu.addAction("Mail folder (Thunderbird profile · EML folder)…", lambda: self._pick_mailbox(folder=True))
        self.btn_mailbox.setMenu(menu)
        top.addWidget(self.btn_mailbox)
        root.addLayout(top)

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        lbl = QLabel("TARGET")
        lbl.setObjectName("CardTitle")
        grid.addWidget(lbl, 0, 0)
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Folder to scan, e.g. Downloads or a USB stick · or drop a folder / several files")
        self.path_edit.setStyleSheet(
            f"QLineEdit{{background:{T['card']}; border:1px solid {T['border']};"
            f"border-radius:6px; padding:7px 10px; color:{T['text']};}}"
            f"QLineEdit:focus{{border:1px solid {T['accent']};}}"
        )
        grid.addWidget(self.path_edit, 0, 1)
        b = QPushButton("BROWSE")
        b.setObjectName("NavBtn")
        b.clicked.connect(self._pick_folder)
        grid.addWidget(b, 0, 2)
        grid.setColumnStretch(1, 1)
        root.addLayout(grid)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.chk_recursive = QCheckBox("Include subfolders")
        self.chk_recursive.setChecked(True)
        opts.addWidget(self.chk_recursive)
        self.chk_new_case = QCheckBox("File results into a new case for this scan")
        self.chk_new_case.setChecked(True)
        opts.addWidget(self.chk_new_case)
        self.chk_flagged = QCheckBox(f"Show only flagged (score ≥ {FLAG_MIN_SCORE})")
        self.chk_flagged.toggled.connect(self._apply_filter)
        opts.addWidget(self.chk_flagged)
        opts.addStretch(1)
        lw = QLabel("PARALLEL SANDBOXES")
        lw.setObjectName("CardTitle")
        opts.addWidget(lw)
        self.spin_workers = QSpinBox()
        self.spin_workers.setRange(1, 8)
        self.spin_workers.setValue(default_workers())
        self.spin_workers.setMinimumWidth(64)
        self.spin_workers.setStyleSheet(
            f"QSpinBox{{background:{T['card']}; border:1px solid {T['border']}; border-radius:6px;"
            f"padding:5px 8px; color:{T['text_hot']}; font-weight:bold;}}"
            f"QSpinBox:focus{{border:1px solid {T['accent']};}}"
        )
        opts.addWidget(self.spin_workers)
        root.addLayout(opts)

        act = QHBoxLayout()
        self.btn_start = QPushButton("▶  START SCAN")
        self.btn_start.setObjectName("PrimaryBtn")
        self.btn_start.clicked.connect(lambda: self.start_scan([self.path_edit.text().strip()]))
        act.addWidget(self.btn_start)
        self.btn_stop = QPushButton("■  STOP")
        self.btn_stop.setObjectName("DangerBtn")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        act.addWidget(self.btn_stop)
        act.addSpacing(12)
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setFormat("%v / %m")
        self.progress.setValue(0)
        act.addWidget(self.progress, stretch=1)
        root.addLayout(act)

        cards = QHBoxLayout()
        cards.setSpacing(10)
        self.cards = {}
        for key, label, color in (("files", "FILES", T["cyan"]), ("done", "ANALYSED", T["accent"]),
                                  ("flagged", "FLAGGED", T["warn"]), ("critical", "HIGH / CRITICAL", T["crit"]),
                                  ("dupes", "DUPLICATES", T["text_dim"]), ("known", "SEEN BEFORE", T["info"]),
                                  ("errors", "ERRORS", T["err"])):
            cards.addWidget(self._stat_card(key, label, color))
        cards.addStretch(1)
        root.addLayout(cards)

        t = QTableWidget(0, len(COLUMNS))
        t.setHorizontalHeaderLabels(COLUMNS)
        t.setAlternatingRowColors(True)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.verticalHeader().setVisible(False)
        t.setWordWrap(False)
        hh = t.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for col, w in enumerate((320, 90, 76, 96, 380, 150)):
            t.setColumnWidth(col, w)
        hh.setStretchLastSection(True)
        t.setStyleSheet(
            f"QTableWidget{{background:{T['bg']}; alternate-background-color:{T['bg_alt']};"
            f"gridline-color:{T['grid']}; border:1px solid {T['border']}; color:{T['text']};}}"
            f"QTableWidget::item:selected{{background:{T['border_hot']};}}"
            f"QHeaderView::section{{background:{T['panel']}; color:{T['text_mute']};"
            f"padding:6px 8px; border:none; border-bottom:1px solid {T['border']};}}"
        )
        t.doubleClicked.connect(self._open_row)
        self.table = t
        root.addWidget(t, stretch=1)

        self.lbl_hint = QLabel("Every file is analysed in its own sandbox worker. "
                               "Double-click a row to open the full analysis.")
        self.lbl_hint.setStyleSheet(f"color:{T['text_mute']}; font-size:8pt;")
        root.addWidget(self.lbl_hint)

    def _stat_card(self, key, label, color):
        frame = QFrame()
        frame.setObjectName("Card")
        frame.setMinimumWidth(118)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(12, 8, 12, 8)
        num = QLabel("0")
        num.setStyleSheet(f"color:{color}; font-size:20pt; font-weight:bold;")
        lbl = QLabel(label)
        lbl.setStyleSheet(f"color:{T['text_mute']}; font-size:8pt; letter-spacing:1px;")
        lay.addWidget(num)
        lay.addWidget(lbl)
        self.cards[key] = num
        return frame

    def _set_card(self, key, value):
        self.cards[key].setText(str(value))

    def _pick_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select folder to scan")
        if d:
            self.path_edit.setText(d)

    # ── Scan ──────────────────────────────────────────────────────────
    @property
    def busy(self):
        return self._runner is not None

    def _pick_mailbox(self, folder):
        if folder:
            p = QFileDialog.getExistingDirectory(self, "Select mail folder (Thunderbird profile, EML folder)")
        else:
            p, _ = QFileDialog.getOpenFileName(self, "Select mailbox", "",
                                               "Mailboxes (*.pst *.ost *.mbox *.mbx *.msg *.eml);;All files (*)")
        if p:
            self.scan_mailbox(p)

    def scan_mailbox(self, path, run_async=True, split_fn=None):
        """Postfach in der Sandbox zerlegen, dann alle Mails wie einen Ordner scannen (eigener Fall)."""
        if self.busy:
            return
        from config.settings import DATA_DIR
        fn = split_fn
        if fn is None:
            from core.sandbox import mailbox_isolated as fn
        self.btn_start.setEnabled(False)
        self.btn_mailbox.setEnabled(False)
        self.lbl_hint.setText(f"Splitting mailbox {Path(path).name} inside the sandbox …")
        LOG.log(f"▶ Mailbox: splitting {path}", "INFO")

        def work():
            try:
                res, folder = fn(path, DATA_DIR / "mailboxes")
            except Exception as e:
                res, folder = {"messages": [], "errors": [f"{type(e).__name__}: {e}"]}, None
            try:
                self.bridge.mailbox.emit(res, folder or "", str(path))
            except RuntimeError:
                pass
        if run_async:
            import threading
            threading.Thread(target=work, daemon=True).start()
        else:
            work()

    def _on_mailbox(self, res, folder, source):
        self.btn_start.setEnabled(True)
        self.btn_mailbox.setEnabled(True)
        for e in res.get("errors") or []:
            LOG.log(f"Mailbox: {e}", "WARN")
        mails = [str(Path(folder) / m["file"]) for m in res.get("messages", []) if m.get("file")] if folder else []
        if not mails:
            msg = "No messages found." + ("\n\n" + "\n".join(res.get("errors") or []) if res.get("errors") else "")
            self.lbl_hint.setText("Mailbox: " + msg.replace("\n", " "))
            # nicht blockierend: der Scan läuft oft im Hintergrund, der Hinweis darf nichts anhalten
            self._mailbox_box = QMessageBox(QMessageBox.Icon.Information, "Mailbox", msg, parent=self)
            self._mailbox_box.open()
            return
        LOG.log(f"Mailbox: {len(mails)} message(s) extracted from {Path(source).name}"
                + (" (limit reached)" if res.get("truncated") else ""), "OK")
        self.chk_new_case.setChecked(True)
        self.start_scan(mails, case_name=f"Mailbox · {Path(source).name}")

    def start_scan(self, paths, case_name=None):
        paths = [p for p in paths if p]
        if self.busy or not paths:
            return
        missing = [p for p in paths if not Path(p).exists()]
        if missing:
            QMessageBox.warning(self, "Batch scan", f"Path not found:\n{missing[0]}")
            return
        files, truncated = collect_files(paths, recursive=self.chk_recursive.isChecked())
        if not files:
            QMessageBox.information(self, "Batch scan", "No files found.")
            return
        if truncated:
            LOG.log(f"Batch: limit reached – only the first {DEFAULT_MAX_FILES} files are scanned", "WARN")

        self._root = Path(paths[0]) if len(paths) == 1 and Path(paths[0]).is_dir() else None
        parents = {str(Path(p).resolve().parent) for p in paths}
        if self._root is None and len(parents) == 1:          # z. B. Mails aus einem Postfach
            self._root = Path(parents.pop())
        if len(paths) == 1:
            self.path_edit.setText(paths[0])
        self._reset_results()
        self._case_id = self._make_case(paths, len(files), case_name)

        self._set_card("files", len(files))
        self.progress.setRange(0, len(files))
        self.progress.setValue(0)
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_csv.setEnabled(False)
        LOG.log(f"▶ Batch scan: {len(files)} files · {self.spin_workers.value()} parallel sandboxes", "INFO")
        self._started = datetime.datetime.now()
        self._runner = BatchRunner(
            files, self.analyze_fn, workers=self.spin_workers.value(),
            on_result=lambda p, r: self.bridge.result.emit(p, r),
            on_finished=lambda s: self.bridge.finished.emit(s),
            log_fn=lambda m, l="INFO": LOG.log(m, "DEBUG" if l in ("INFO", "OK") else l),
        ).start()
        self.busyChanged.emit(True)

    def stop_scan(self):
        if self._runner:
            self._runner.cancel()
            self.btn_stop.setEnabled(False)
            LOG.log("Batch: stopping – running sandboxes finish their current file", "WARN")

    def _make_case(self, paths, n, case_name=None):
        if not (self.chk_new_case.isChecked() and self.history):
            return None
        base = (Path(paths[0]).name or str(paths[0])) if len(paths) == 1 else f"{len(paths)} items"
        name = f"{case_name or 'Scan · ' + base} · {datetime.datetime.now():%Y-%m-%d %H:%M:%S}"
        try:
            cid = self.history.db.create_case(name, description=f"Batch scan of {n} files: {paths[0]}")
        except ValueError:
            return None
        self.history.reload_cases(select_id=cid)
        return cid

    def _reset_results(self):
        self._rows = []
        self._seen_hashes = {}
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for k in self.cards:
            self._set_card(k, 0)

    # ── Ergebnisse ────────────────────────────────────────────────────
    def _rel(self, path):
        if self._root:
            try:
                return str(Path(path).relative_to(self._root.resolve()))
            except ValueError:
                pass
        return str(path)

    def _on_result(self, path, res):
        row = {"path": path, "id": None, "ok": bool(res.get("ok")), "kind": res.get("kind") or "",
               "score": -1, "level": "ERROR", "headline": res.get("error") or "", "note": "",
               "sha256": ((res.get("hashes") or {}).get("sha256") or "").lower()}
        if row["ok"]:
            sc, th = res.get("score") or {}, res.get("threat") or {}
            row.update(score=int(sc.get("score") or 0), level=sc.get("level") or "",
                       headline=th.get("headline") or "")
            notes = []
            if row["sha256"] in self._seen_hashes:
                notes.append(f"duplicate of {Path(self._seen_hashes[row['sha256']]).name}")
            else:
                self._seen_hashes[row["sha256"]] = path
            if self.history:
                try:
                    row["id"], prev = self.history.record(res, case_id=self._case_id, refresh=False)
                    prev = [p for p in prev if p.get("case_id") != self._case_id or self._case_id is None]
                    if prev and not notes:
                        notes.append(f"seen before ({prev[0]['level']})")
                    if not notes:
                        sim = self.history.db.similar(row["id"], limit=1, use_prnu=False)
                        if sim and sim[0].get("distance") is not None and sim[0]["distance"] <= 30:
                            notes.append(f"variant of {sim[0]['name']} (TLSH {sim[0]['distance']})")
                except Exception as e:
                    LOG.log(f"History: could not save {Path(path).name}: {e}", "WARN")
            row["note"] = " · ".join(notes)
        self._rows.append(row)
        self._add_row(row)
        self._update_cards()
        self.progress.setValue(len(self._rows))

    def _add_row(self, row):
        t = self.table
        sorting = t.isSortingEnabled()
        t.setSortingEnabled(False)
        r = t.rowCount()
        t.insertRow(r)
        color = QColor(LEVEL_COLOR.get(row["level"], T["err"] if not row["ok"] else T["text"]))
        vals = [self._rel(row["path"]), row["kind"], None, row["level"], row["headline"], row["note"],
                row["sha256"][:16] + ("…" if row["sha256"] else "")]
        for c, v in enumerate(vals):
            it = _NumItem(row["score"], "—" if row["score"] < 0 else str(row["score"])) if c == 2 \
                else QTableWidgetItem(str(v))
            if c == 0:
                it.setData(Qt.ItemDataRole.UserRole, row["id"])
                it.setToolTip(row["path"])
            if c in (2, 3):
                it.setForeground(color)
            if c == 6:
                it.setToolTip(row["sha256"])
            t.setItem(r, c, it)
        t.setRowHidden(r, self._hidden(row))
        t.setSortingEnabled(sorting)

    def _hidden(self, row):
        return self.chk_flagged.isChecked() and row["ok"] and row["score"] < FLAG_MIN_SCORE

    def _apply_filter(self):
        by_path = {r["path"]: r for r in self._rows}
        for i in range(self.table.rowCount()):
            row = by_path.get(self.table.item(i, 0).toolTip())
            if row:
                self.table.setRowHidden(i, self._hidden(row))

    def _update_cards(self):
        ok = [r for r in self._rows if r["ok"]]
        self._set_card("done", len(self._rows))
        self._set_card("flagged", sum(1 for r in ok if r["score"] >= FLAG_MIN_SCORE))
        self._set_card("critical", sum(1 for r in ok if r["level"] in ("HIGH RISK", "CRITICAL")))
        self._set_card("dupes", sum(1 for r in ok if r["note"].startswith("duplicate")))
        self._set_card("known", sum(1 for r in ok if "seen before" in r["note"]))
        self._set_card("errors", len(self._rows) - len(ok))

    def _on_finished(self, stats):
        self._runner = None
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_csv.setEnabled(bool(self._rows))
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(2, Qt.SortOrder.DescendingOrder)
        secs = (datetime.datetime.now() - self._started).total_seconds()
        flagged = sum(1 for r in self._rows if r["ok"] and r["score"] >= FLAG_MIN_SCORE)
        state = "stopped" if stats.get("cancelled") else "complete"
        LOG.log(f"✓ Batch scan {state}: {stats['done']}/{stats['total']} files in {secs:.0f}s · "
                f"{flagged} flagged · {stats['errors']} errors", "WARN" if flagged else "OK")
        self.lbl_hint.setText(f"Scan {state}: {stats['done']}/{stats['total']} files in {secs:.0f}s. "
                              "Double-click a row to open the full analysis.")
        if self.history:
            self.history.reload_cases()
        self.busyChanged.emit(False)

    def _open_row(self, index):
        aid = self.table.item(index.row(), 0).data(Qt.ItemDataRole.UserRole)
        if aid is not None:
            self.openRequested.emit(int(aid))

    def _export_csv(self):
        default = str(REPORT_DIR / f"batch_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv")
        f, _ = QFileDialog.getSaveFileName(self, "Export batch results", default, "CSV (*.csv)")
        if f:
            self.export_csv(f)
            LOG.log(f"Batch results exported: {f}", "OK")

    def export_csv(self, path):
        rows = sorted(self._rows, key=lambda r: -r["score"])
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh, delimiter=";")
            w.writerow(["path", "kind", "score", "level", "headline", "note", "sha256", "history_id"])
            for r in rows:
                w.writerow([_csv_safe(v) for v in (r["path"], r["kind"], r["score"] if r["ok"] else "",
                            r["level"], r["headline"], r["note"], r["sha256"], r["id"] or "")])
