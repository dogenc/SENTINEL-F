"""
╔══════════════════════════════════════════════════════════════╗
║          MAIN WINDOW — DGKN@Labs-FileForensic                ║
║     Frameless · Sidebar · Dashboard · Analysis · AI Panel    ║
╚══════════════════════════════════════════════════════════════╝
"""
import threading

from PyQt6.QtCore import Qt, QObject, pyqtSignal
from PyQt6.QtGui import QIcon, QColor, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QStackedWidget, QFileDialog, QMessageBox, QProgressBar, QApplication, QButtonGroup
)

from config.settings import (
    T, APP_NAME, APP_VERSION, APP_CODENAME, FONT_MONO
)
from core.utils import LOG
from engines import run_forensic
from core.sandbox import analyze_isolated
from config.settings import SANDBOX_ENABLED

from .titlebar   import TitleBar
from .dashboard  import DashboardView
from .analysis_view import AnalysisView
from .ai_panel    import AIPanel
from .copytrace_view import CopyTraceView
from .thumbnails_view import ThumbnailsView
from .history_view import HistoryView
from .batch_view import BatchView
from .watch_view import WatchView
from .graph_view import GraphView
from .widgets    import DropZone


# ── Thread bridge ─────────────────────────────────────────────────────────────
class _AnalysisBridge(QObject):
    progress  = pyqtSignal(str, int)
    logLine   = pyqtSignal(dict)
    done      = pyqtSignal(dict)
    failed    = pyqtSignal(str)


# ══════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setMinimumSize(1400, 860)
        self.resize(1520, 920)

        self._current_path   = None
        self._current_result = None
        self._analyzing      = False

        # Bridge — engine threads -> UI
        self.bridge = _AnalysisBridge()
        self.bridge.progress.connect(self._on_progress)
        self.bridge.logLine.connect(self._on_log_line)
        self.bridge.done.connect(self._on_analysis_done)
        self.bridge.failed.connect(self._on_analysis_failed)

        LOG.subscribe(lambda line: self.bridge.logLine.emit(line))

        self._build()
        self._wire_shortcuts()
        self._tray = None
        self._last_alert_id = None
        self._last_history_id = None

    # ══════════════════════════════════════════════════════════════════
    # UI construction
    # ══════════════════════════════════════════════════════════════════
    def _build(self):
        root = QWidget()
        root.setObjectName("RootFrame")
        rlay = QVBoxLayout(root)
        rlay.setContentsMargins(0, 0, 0, 0)
        rlay.setSpacing(0)

        # ── Title bar ─────────────────────────────────────────────
        self.titlebar = TitleBar(self, self)
        rlay.addWidget(self.titlebar)

        # ── Body: sidebar + stacked views ─────────────────────────
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        body.addWidget(self._build_sidebar())

        # Main content stack
        self.stack = QStackedWidget()
        self.stack.setObjectName("ContentStack")

        self.dashboard = DashboardView(self)
        self.analysis  = AnalysisView(self)
        self.ai_panel  = AIPanel(self)
        self.copytrace = CopyTraceView(self)
        self.thumbnails = ThumbnailsView(self)
        self.log_view  = self._build_log_view()
        self.history   = HistoryView(self)
        self.history.openRequested.connect(self._open_from_history)
        self.history.routeOnGlobe.connect(self._show_route_on_globe)
        self.batch     = BatchView(self, analyze_fn=analyze_isolated if SANDBOX_ENABLED else run_forensic,
                                   history=self.history)
        self.batch.openRequested.connect(self._open_from_history)
        self.watch     = WatchView(self, analyze_fn=analyze_isolated if SANDBOX_ENABLED else run_forensic,
                                   history=self.history)
        self.watch.openRequested.connect(self._open_from_history)
        self.watch.alert.connect(self._on_watch_alert)
        self.watch.stateChanged.connect(self._on_watch_state)
        self.analysis.similar.openRequested.connect(self._open_from_history)
        self.analysis.lineage.openRequested.connect(self._open_from_history)
        self.analysis.intel.intelChanged.connect(self._on_intel)
        self.graph     = GraphView(self, history=self.history)
        self.graph.openRequested.connect(self._open_from_history)

        self.stack.addWidget(self.dashboard)   # idx 0
        self.stack.addWidget(self.analysis)    # idx 1
        self.stack.addWidget(self.ai_panel)    # idx 2
        self.stack.addWidget(self.copytrace)   # idx 3
        self.stack.addWidget(self.thumbnails)  # idx 4
        self.stack.addWidget(self.log_view)    # idx 5
        self.stack.addWidget(self.history)     # idx 6
        self.stack.addWidget(self.batch)       # idx 7
        self.stack.addWidget(self.watch)       # idx 8
        self.stack.addWidget(self.graph)       # idx 9

        body.addWidget(self.stack, stretch=1)

        body_w = QWidget()
        body_w.setLayout(body)
        rlay.addWidget(body_w, stretch=1)

        # ── Status bar ────────────────────────────────────────────
        rlay.addWidget(self._build_statusbar())

        # Drop-zone overlay on the dashboard — wire the signal
        self._wire_drop()

        self.setCentralWidget(root)

    def _build_sidebar(self):
        side = QWidget()
        side.setObjectName("Sidebar")
        side.setFixedWidth(240)

        lay = QVBoxLayout(side)
        lay.setContentsMargins(0, 10, 0, 10)
        lay.setSpacing(0)

        # Nav section label
        lbl1 = QLabel("◉  OPERATIONS")
        lbl1.setObjectName("SidebarSection")
        lay.addWidget(lbl1)

        self.btn_group = QButtonGroup(self)
        self.btn_group.setExclusive(True)

        self.btn_dashboard = self._nav_button("▸  DASHBOARD", 0, checked=True)
        self.btn_analysis  = self._nav_button("▸  ANALYSIS",  1)
        self.btn_batch     = self._nav_button("▸  BATCH SCAN", 7)
        self.btn_watch     = self._nav_button("▸  WATCH",      8)
        self.btn_ai        = self._nav_button("▸  AI ANALYST",2)
        self.btn_copytrace = self._nav_button("▸  COPYTRACE",  3)
        self.btn_thumbs    = self._nav_button("▸  THUMBNAILS", 4)
        self.btn_log       = self._nav_button("▸  TELEMETRY", 5)
        self.btn_history   = self._nav_button("▸  HISTORY",   6)
        self.btn_graph     = self._nav_button("▸  IOC GRAPH", 9)

        for b in (self.btn_dashboard, self.btn_analysis, self.btn_batch, self.btn_watch, self.btn_ai,
                  self.btn_copytrace, self.btn_thumbs, self.btn_log, self.btn_history, self.btn_graph):
            lay.addWidget(b)

        lay.addSpacing(10)
        lbl2 = QLabel("◉  INPUT")
        lbl2.setObjectName("SidebarSection")
        lay.addWidget(lbl2)

        self.btn_open = QPushButton("⟰  OPEN FILE")
        self.btn_open.setObjectName("NavBtn")
        self.btn_open.clicked.connect(self._browse_file)
        lay.addWidget(self.btn_open)

        self.btn_scan = QPushButton("⟰  SCAN FOLDER")
        self.btn_scan.setObjectName("NavBtn")
        self.btn_scan.clicked.connect(self._browse_folder)
        lay.addWidget(self.btn_scan)

        self.btn_run  = QPushButton("▶  RUN ANALYSIS")
        self.btn_run.setObjectName("NavBtn")
        self.btn_run.clicked.connect(self._run_current)
        self.btn_run.setEnabled(False)
        lay.addWidget(self.btn_run)

        self.btn_reset = QPushButton("↺  RESET")
        self.btn_reset.setObjectName("NavBtn")
        self.btn_reset.clicked.connect(self._reset_all)
        lay.addWidget(self.btn_reset)

        lay.addStretch(1)

        # Drop zone at bottom of sidebar
        self.drop_zone = DropZone()
        dzwrap = QVBoxLayout()
        dzwrap.setContentsMargins(12, 6, 12, 6)
        dzwrap.addWidget(self.drop_zone)
        dz_w = QWidget()
        dz_w.setLayout(dzwrap)
        lay.addWidget(dz_w)

        # Brand footer
        # Brand footer – Namensnennung (NOTICE, GPL §7(b)); Klick öffnet „Über“
        brand = QPushButton(f"© DGKN@Labs · v{APP_VERSION}\n{APP_CODENAME}  ·  GPL-3.0  ·  ⓘ")
        brand.setObjectName("BrandBtn")
        brand.setFlat(True)
        brand.setCursor(Qt.CursorShape.PointingHandCursor)
        brand.setToolTip("About SENTINEL-F · license · credits")
        brand.setStyleSheet(
            f"QPushButton#BrandBtn {{ color:{T['text_mute']}; font-size:8pt; letter-spacing:2px; padding:8px;"
            f"border:none; border-top:1px solid {T['border']}; background:transparent; }}"
            f"QPushButton#BrandBtn:hover {{ color:{T['accent']}; }}"
        )
        from gui.about import show_about
        brand.clicked.connect(lambda: show_about(self))
        lay.addWidget(brand)

        return side

    def _nav_button(self, label, idx, checked=False):
        b = QPushButton(label)
        b.setObjectName("NavBtn")
        b.setCheckable(True)
        b.setChecked(checked)
        b.clicked.connect(lambda _, i=idx: self._goto(i))
        self.btn_group.addButton(b, idx)
        return b

    def _goto(self, idx):
        self.stack.setCurrentIndex(idx)
        if idx == 9:                       # Graph: Fälle aktualisieren und bei Bedarf aufbauen
            self.graph.reload_scopes()
            if self.graph.graph is None:
                self.graph.rebuild()

    def _wire_drop(self):
        self.drop_zone.fileDropped.connect(self._load_file)
        self.drop_zone.pathsDropped.connect(self._scan_paths)

    def _build_log_view(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(14, 14, 14, 14)

        hdr = QLabel("▸  TELEMETRY  ·  EVENT LOG")
        hdr.setObjectName("SectionHeader")
        lay.addWidget(hdr)

        from PyQt6.QtWidgets import QPlainTextEdit
        from PyQt6.QtGui import QFont
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont(FONT_MONO, 9))
        lay.addWidget(self.log_text, stretch=1)
        return w

    def _build_statusbar(self):
        bar = QWidget()
        bar.setObjectName("StatusBar")
        bar.setFixedHeight(26)
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 0, 12, 0)
        lay.setSpacing(14)

        self.status_left = QLabel("SYSTEM READY")
        self.status_left.setObjectName("StatusOK")
        lay.addWidget(self.status_left)

        sep = QLabel("│"); sep.setStyleSheet(f"color:{T['border_hot']};")
        lay.addWidget(sep)

        self.status_op = QLabel("idle")
        self.status_op.setObjectName("StatusText")
        lay.addWidget(self.status_op)

        lay.addStretch(1)

        self.progress = QProgressBar()
        self.progress.setFixedWidth(260)
        self.progress.setMaximum(100)
        self.progress.setTextVisible(False)
        lay.addWidget(self.progress)

        self.status_right = QLabel("  SENTINEL-F · READY")
        self.status_right.setObjectName("StatusText")
        lay.addWidget(self.status_right)

        return bar

    # ══════════════════════════════════════════════════════════════════
    # Shortcuts
    # ══════════════════════════════════════════════════════════════════
    def _wire_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+O"), self, activated=self._browse_file)
        QShortcut(QKeySequence("Ctrl+R"), self, activated=self._run_current)
        QShortcut(QKeySequence("Ctrl+E"), self, activated=lambda: self.analysis._export_json())
        QShortcut(QKeySequence("Ctrl+P"), self, activated=lambda: self.analysis.export_report())
        QShortcut(QKeySequence("F5"),     self, activated=self._run_current)
        QShortcut(QKeySequence("1"),      self, activated=lambda: (self._goto(0), self.btn_dashboard.setChecked(True)))
        QShortcut(QKeySequence("2"),      self, activated=lambda: (self._goto(1), self.btn_analysis.setChecked(True)))
        QShortcut(QKeySequence("3"),      self, activated=lambda: (self._goto(2), self.btn_ai.setChecked(True)))
        QShortcut(QKeySequence("4"),      self, activated=lambda: (self._goto(5), self.btn_log.setChecked(True)))
        QShortcut(QKeySequence("5"),      self, activated=lambda: (self._goto(3), self.btn_copytrace.setChecked(True)))
        QShortcut(QKeySequence("6"),      self, activated=lambda: (self._goto(4), self.btn_thumbs.setChecked(True)))
        QShortcut(QKeySequence("7"),      self, activated=lambda: (self._goto(6), self.btn_history.setChecked(True)))
        QShortcut(QKeySequence("8"),      self, activated=lambda: (self._goto(7), self.btn_batch.setChecked(True)))
        QShortcut(QKeySequence("9"),      self, activated=lambda: (self._goto(8), self.btn_watch.setChecked(True)))
        QShortcut(QKeySequence("0"),      self, activated=lambda: (self._goto(9), self.btn_graph.setChecked(True)))
        QShortcut(QKeySequence("Ctrl+Shift+O"), self, activated=self._browse_folder)

    # ══════════════════════════════════════════════════════════════════
    # File loading
    # ══════════════════════════════════════════════════════════════════
    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File for Forensic Analysis", "",
            "All Files (*.*);;"
            "Images (*.jpg *.jpeg *.png *.gif *.bmp *.tif *.tiff *.webp *.heic *.ico *.psd);;"
            "PDF (*.pdf);;"
            "Documents (*.docx *.xlsx *.pptx *.doc *.xls *.ppt *.rtf *.odt *.one);;"
            "Programs (*.exe *.dll *.sys *.scr *.msi *.elf *.so *.apk *.jar);;"
            "Archives (*.zip *.7z *.rar *.gz *.tgz *.bz2 *.xz *.tar *.cab *.iso *.img);;"
            "Scripts (*.ps1 *.vbs *.js *.bat *.cmd *.hta *.wsf *.py *.sh *.php);;"
            "Web & Mail (*.html *.htm *.svg *.eml *.msg *.lnk *.url);;"
            "Databases (*.db *.sqlite *.sqlite3)"
        )
        if path:
            self._load_file(path)

    def _browse_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Select folder for batch scan")
        if d:
            self._scan_paths([d])

    def _scan_paths(self, paths):
        """Ordner / mehrere Dateien → BATCH SCAN."""
        self._goto(7)
        self.btn_batch.setChecked(True)
        if self.batch.busy:
            QMessageBox.information(self, "Batch scan", "A batch scan is already running.")
            return
        self.batch.start_scan(paths)

    def _load_file(self, path):
        from pathlib import Path as _P
        p = _P(path)
        if not p.exists():
            QMessageBox.critical(self, "Error", f"File does not exist:\n{path}")
            return
        if p.is_dir():
            self._scan_paths([str(p)])
            return
        self._current_path = str(p.resolve())
        self.btn_run.setEnabled(True)
        self.status_op.setText(f"loaded: {p.name}")
        LOG.log(f"Loaded: {p.name} ({p.stat().st_size:,} bytes)", "OK")
        # Immediately run analysis for a smooth UX
        self._run_current()

    def _run_current(self):
        if not self._current_path:
            QMessageBox.information(self, "No file", "Load a file first.")
            return
        if self._analyzing:
            return

        self._analyzing = True
        self.btn_run.setEnabled(False)
        self.btn_open.setEnabled(False)
        self.progress.setValue(0)
        self.status_op.setText("analysis running…")
        self.status_left.setText("ANALYZING")
        self.status_left.setObjectName("StatusText")
        self.status_left.setStyleSheet(f"color:{T['warn']}; font-weight:bold;")

        LOG.log(f"▶ Running analysis: {self._current_path}", "INFO")

        path = self._current_path

        def progress_fn(label, value):
            self.bridge.progress.emit(label, int(value))

        def log_fn(msg, level="INFO"):
            LOG.log(msg, level)

        def worker():
            try:
                if SANDBOX_ENABLED:
                    # Datei wird nur im abgeschotteten Worker geparst (core/sandbox.py)
                    result = analyze_isolated(path, progress_fn=progress_fn, log_fn=log_fn)
                else:
                    result = run_forensic(path, progress_fn=progress_fn, log_fn=log_fn)
                self.bridge.done.emit(result)
            except Exception as e:
                import traceback
                self.bridge.failed.emit(f"{e}\n{traceback.format_exc()}")

        threading.Thread(target=worker, daemon=True).start()

    def _reset_all(self):
        self._current_path = None
        self._current_result = None
        self.btn_run.setEnabled(False)
        self.progress.setValue(0)
        self.status_op.setText("idle")
        self.dashboard.reset()
        self.analysis.reset()
        self.ai_panel.reset()
        self.copytrace.reset()
        self.thumbnails.reset()
        LOG.log("Reset", "INFO")

    # ══════════════════════════════════════════════════════════════════
    # Bridge handlers
    # ══════════════════════════════════════════════════════════════════
    def _on_progress(self, label, value):
        self.progress.setValue(value)
        self.status_op.setText(label.lower())

    def _on_log_line(self, line):
        ts    = line.get("ts", "")
        level = line.get("level", "INFO")
        msg   = line.get("msg", "")
        color_map = {
            "INFO": T['info'], "OK": T['ok'], "WARN": T['warn'],
            "ERR":  T['err'],  "CRIT":T['crit'],"DEBUG":T['text_mute'],
        }
        col = color_map.get(level, T['info'])
        prefix = f"[{ts}] [{level:<4}]"
        # render to log_text with color
        # msg kann Dateinamen/Strings aus der analysierten Datei enthalten → escapen
        import html as _html
        self.log_text.appendHtml(
            f"<span style='color:{T['text_mute']};'>{prefix}</span> "
            f"<span style='color:{col};'>{_html.escape(str(msg))}</span>"
        )

    def _on_analysis_done(self, result):
        self._analyzing = False
        self._current_result = result
        self.btn_run.setEnabled(True)
        self.btn_open.setEnabled(True)
        self.progress.setValue(100)

        if not result.get("ok"):
            err = result.get("error", "unknown error")
            self.status_left.setText("FAILED")
            self.status_left.setStyleSheet(f"color:{T['err']}; font-weight:bold;")
            self.status_op.setText("error")
            LOG.log(f"✗ Analysis failed: {err}", "ERR")
            QMessageBox.critical(self, "Analysis Failed", err)
            return

        score = result.get("score") or {}
        LOG.log(
            f"✓ Analysis done — kind={result.get('kind', '?')}, "
            f"score={score.get('score', 0)}/100 ({score.get('level', '?')}), "
            f"signals={score.get('total_signals', 0)}",
            "OK"
        )
        seen_before = self._record_history(result)
        self._show_result(result)
        self._show_similar(self._last_history_id)
        if seen_before:
            self.status_op.setText(f"complete — {result.get('file',{}).get('name','?')}  ·  {seen_before}")

    def _show_result(self, result):
        # propagate to dashboards
        self.dashboard.load_result(result)
        self.analysis.load_result(result)
        self.ai_panel.load_result(result)

        score = result.get("score") or {}
        self.status_left.setText(
            f"READY  ·  SCORE {score.get('score', 0)}/100  ·  {score.get('level','?')}"
        )
        self.status_left.setStyleSheet(
            f"color:{score.get('color', T['ok'])}; font-weight:bold;"
        )
        self.status_op.setText(f"complete — {result.get('file',{}).get('name','?')}")

        # Auto-jump to analysis tab the first time
        self._goto(1)
        self.btn_dashboard.setChecked(False)
        self.btn_analysis.setChecked(True)

        # Pin GPS if available
        self._try_pin_gps(result)

    # ══════════════════════════════════════════════════════════════════
    # Watch-Folder · Tray
    # ══════════════════════════════════════════════════════════════════
    def _ensure_tray(self):
        from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
        if self._tray is not None or not QSystemTrayIcon.isSystemTrayAvailable():
            return self._tray
        tray = QSystemTrayIcon(self._tray_icon(), self)
        tray.setToolTip(f"{APP_CODENAME} · folder watch")
        menu = QMenu(self)
        menu.addAction("Show SENTINEL-F", self._show_from_tray)
        menu.addAction("Stop watching", self.watch.stop)
        menu.addSeparator()
        menu.addAction("Quit", self._quit_from_tray)
        tray.setContextMenu(menu)
        tray.activated.connect(lambda reason: self._show_from_tray()
                               if reason == QSystemTrayIcon.ActivationReason.Trigger else None)
        tray.messageClicked.connect(self._open_last_alert)
        self._tray_menu = menu
        self._tray = tray
        return tray

    @staticmethod
    def _tray_icon():
        from PyQt6.QtGui import QPixmap, QPainter, QPen, QBrush
        pm = QPixmap(64, 64)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(QPen(QColor(T['accent']), 6))
        p.setBrush(QBrush(QColor(T['bg'])))
        p.drawEllipse(6, 6, 52, 52)
        p.setBrush(QBrush(QColor(T['accent'])))
        p.drawEllipse(24, 24, 16, 16)
        p.end()
        return QIcon(pm)

    def _on_watch_state(self, active):
        tray = self._ensure_tray() if active else self._tray
        if tray is not None:
            tray.setVisible(active)
        self.status_right.setText("  ◉ WATCHING" if active else "  SENTINEL-F · READY")
        self.status_right.setStyleSheet(f"color:{T['accent']}; font-weight:bold;" if active else "")

    def _on_watch_alert(self, row):
        self._last_alert_id = row.get("id")
        text = f"{row['name']}\n{row['level']} · {row['score']}/100 — {row['headline']}"[:250]
        if self._tray is not None and self._tray.isVisible():
            from PyQt6.QtWidgets import QSystemTrayIcon
            self._tray.showMessage(f"⚠ {APP_CODENAME}: suspicious file", text,
                                   QSystemTrayIcon.MessageIcon.Warning, 10000)
        elif self.isVisible():
            QApplication.alert(self)

    def _open_last_alert(self):
        self._show_from_tray()
        if self._last_alert_id is not None:
            self._open_from_history(self._last_alert_id)

    def _show_from_tray(self):
        QApplication.instance().setQuitOnLastWindowClosed(True)
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _quit_from_tray(self):
        self.watch.stop()
        QApplication.instance().quit()

    def closeEvent(self, e):
        if self.watch.watching and self.watch.keep_in_tray and self._ensure_tray() is not None:
            # Weiter im Hintergrund wachen – erst "Quit" im Tray-Menü beendet die App
            QApplication.instance().setQuitOnLastWindowClosed(False)
            e.ignore()
            self.hide()
            from PyQt6.QtWidgets import QSystemTrayIcon
            self._tray.showMessage(APP_CODENAME, "Still watching your folders in the background.",
                                   QSystemTrayIcon.MessageIcon.Information, 4000)
            return
        self.watch.stop()
        if self.batch.busy:
            self.batch.stop_scan()
        super().closeEvent(e)

    # ══════════════════════════════════════════════════════════════════
    # History
    # ══════════════════════════════════════════════════════════════════
    def _record_history(self, result):
        """Analyse speichern; liefert einen Hinweis, falls die Datei schon bekannt ist."""
        self._last_history_id = None
        try:
            aid, prev = self.history.record(result)
        except Exception as e:
            LOG.log(f"History: analysis could not be saved ({e})", "WARN")
            return ""
        LOG.log(f"History: saved as #{aid}", "DEBUG")
        self._last_history_id = aid
        if not prev:
            return ""
        self.ai_panel.set_context(previous=prev)
        last = prev[0]
        levels = sorted({p["level"] for p in prev if p.get("level")})
        LOG.log(
            f"▸ Known file: SHA-256 analysed {len(prev)}× before — last {last['analyzed_at']} "
            f"as {last['name']} ({last['level']} {last['score']}/100)"
            + (f", case {last['case_name']}" if last.get("case_name") else "")
            + (f"; verdicts seen: {', '.join(levels)}" if len(levels) > 1 else ""),
            "WARN" if last["name"] != (result.get("file") or {}).get("name") else "INFO",
        )
        return f"seen {len(prev)}× before"

    def _on_intel(self, intel):
        from core.threatintel import summary
        v = summary({k: x for k, x in intel.items() if not k.startswith("_")})
        LOG.log(f"▸ Hash lookup: {v.upper()}", "WARN" if v in ("malicious", "suspicious") else "INFO")
        hid = (self._current_result or {}).get("history", {}).get("id") or self._last_history_id
        if hid:
            try:
                self.history.db.update_result(hid, self._current_result)
            except Exception as e:
                LOG.log(f"History: could not store intel ({e})", "WARN")

    def _show_similar(self, analysis_id, log=True):
        if analysis_id is None:
            self.analysis.set_similar([], {})
            self.analysis.set_lineage([])
            return
        try:
            db = self.history.db
            rows = db.similar(analysis_id)
            fp = db.fingerprints_for(analysis_id)
        except Exception as e:
            LOG.log(f"Similarity search failed: {e}", "WARN")
            return
        self.analysis.set_similar(rows, fp)
        try:
            from core.lineage import relatives
            fam = relatives(db, analysis_id)
            self.analysis.set_lineage(fam)
            if fam and log:
                LOG.log(f"▸ Document lineage: {len(fam)} related version(s) in the history "
                        f"({', '.join(sorted({r['relation'] for r in fam}))})", "INFO")
        except Exception as e:
            LOG.log(f"Lineage lookup failed: {e}", "WARN")
        self.ai_panel.set_context(similar=rows)
        if rows and log:
            top = rows[0]
            how = f"TLSH distance {top['distance']}" if top.get("distance") is not None else ", ".join(top["match"])
            bad = [r for r in rows if (r.get("score") or 0) >= 60]
            LOG.log(f"▸ Similar to {len(rows)} earlier file(s) — closest: {top['name']} ({how}, "
                    f"{top['level']} {top['score']}/100)", "WARN" if bad else "INFO")

    def _open_from_history(self, analysis_id):
        if self._analyzing:
            return
        try:
            result = self.history.db.get_result(analysis_id)
        except Exception as e:
            QMessageBox.critical(self, "History", f"Could not load analysis #{analysis_id}:\n{e}")
            return
        if not result:
            return
        self._current_result = result
        self._current_path = None      # Neu analysieren nur über OPEN FILE – die Datei kann sich geändert haben
        self.btn_run.setEnabled(False)
        LOG.log(f"History: opened analysis #{analysis_id} from {result['history']['analyzed_at']}", "INFO")
        self._show_result(result)
        self._show_similar(analysis_id, log=False)
        self.status_op.setText(f"history #{analysis_id} — {(result.get('file') or {}).get('name', '?')}"
                               f"  ·  analysed {result['history']['analyzed_at']}")

    def _on_analysis_failed(self, err):
        self._analyzing = False
        self.btn_run.setEnabled(True)
        self.btn_open.setEnabled(True)
        self.status_left.setText("FAILED")
        self.status_left.setStyleSheet(f"color:{T['err']}; font-weight:bold;")
        LOG.log(f"✗ {err}", "ERR")
        QMessageBox.critical(self, "Analysis Failed", err[:800])

    # ══════════════════════════════════════════════════════════════════
    # Helpers
    # ══════════════════════════════════════════════════════════════════
    def _try_pin_gps(self, result):
        """If the file has GPS EXIF, pin it on the 3D globe."""
        from core.geo import gps_from_result
        g = gps_from_result(result)
        if not g:
            return
        lat, lon = g
        label = (result.get("file") or {}).get("name", "TARGET")[:20]
        try:
            self.dashboard.pin_file_location(lon, lat, label)
            LOG.log(f"▸ GPS pinned on globe: {lat:.4f}, {lon:.4f}", "INFO")
        except Exception:
            pass

    def _show_route_on_globe(self, route):
        if self.dashboard.show_route(route):
            self._goto(0)
            self.btn_dashboard.setChecked(True)
        else:
            QMessageBox.information(self, "Globe", "The 3-D globe is not available (PyQt6-WebEngine missing).")
