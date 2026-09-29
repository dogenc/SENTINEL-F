"""
╔══════════════════════════════════════════════════════════════╗
║          OLLAMA AI PANEL — local second-opinion analyst      ║
╚══════════════════════════════════════════════════════════════╝
"""
import datetime
import threading

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPlainTextEdit, QLineEdit,
    QPushButton, QFrame, QComboBox, QMessageBox
)

from config.settings import T, FONT_MONO, OLLAMA_MODEL
from engines.ollama_client import OllamaClient
from engines import detective


# ── Qt signal bridge so Ollama threads can safely update the UI ───────────────
class _Bridge(QObject):
    token   = pyqtSignal(str)
    done    = pyqtSignal()
    failed  = pyqtSignal(str)
    status  = pyqtSignal(bool, str)
    models  = pyqtSignal(list)


class AIPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.client = OllamaClient()
        self.bridge = _Bridge()
        self._last_result = None
        self._busy = False
        self._online = False
        self._context = {}           # similar / previous / case_rows für die Beweisliste
        self._verify_ev = None       # aktive Beweisliste, gegen die die Antwort geprüft wird
        self._answer_start = 0

        self.bridge.token.connect(self._append_token)
        self.bridge.done.connect(self._on_done)
        self.bridge.failed.connect(self._on_failed)
        self.bridge.status.connect(self._on_status)
        self.bridge.models.connect(self._on_models)

        self._build()
        # probe on startup
        threading.Thread(target=self._probe_worker, daemon=True).start()

    # ─── UI ──────────────────────────────────────────────────────────
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        # Header bar
        hdr_row = QHBoxLayout()
        title = QLabel("▸  SENTINEL-F · AI ANALYST (OLLAMA · LOCAL)")
        title.setObjectName("SectionHeader")
        hdr_row.addWidget(title)
        hdr_row.addStretch(1)

        # Status dot
        self.lbl_status = QLabel("◉  probing…")
        self.lbl_status.setStyleSheet(
            f"color:{T['text_mute']}; font-size:9pt; letter-spacing:1.5px;"
            f"font-family:'{FONT_MONO}',monospace;"
        )
        hdr_row.addWidget(self.lbl_status)
        root.addLayout(hdr_row)

        # Config strip
        cfg_frame = QFrame()
        cfg_frame.setObjectName("Card")
        cfg_lay = QHBoxLayout(cfg_frame)
        cfg_lay.setContentsMargins(10, 8, 10, 8)
        cfg_lay.setSpacing(10)

        lbl_model = QLabel("MODEL")
        lbl_model.setStyleSheet(f"color:{T['text_dim']}; font-size:9pt; letter-spacing:2px;")
        cfg_lay.addWidget(lbl_model)

        self.cb_model = QComboBox()
        self.cb_model.setEditable(True)
        self.cb_model.addItem(OLLAMA_MODEL)
        self.cb_model.setMinimumWidth(320)
        cfg_lay.addWidget(self.cb_model)

        self.btn_probe = QPushButton("PROBE")
        self.btn_probe.clicked.connect(
            lambda: threading.Thread(target=self._probe_worker, daemon=True).start()
        )
        cfg_lay.addWidget(self.btn_probe)

        cfg_lay.addStretch(1)

        self.btn_detective = QPushButton("🕵  DETECTIVE")
        self.btn_detective.setObjectName("PrimaryBtn")
        self.btn_detective.setToolTip("Evidence-linked incident narrative – every statement cites a finding.\n"
                                      "Works offline (rule-based) and with the local model (verified).")
        self.btn_detective.clicked.connect(self.run_detective)
        self.btn_detective.setEnabled(False)
        cfg_lay.addWidget(self.btn_detective)

        self.btn_analyze = QPushButton("RUN SECOND-OPINION")
        self.btn_analyze.setObjectName("PrimaryBtn")
        self.btn_analyze.clicked.connect(self._run_analysis)
        self.btn_analyze.setEnabled(False)
        cfg_lay.addWidget(self.btn_analyze)

        self.btn_clear = QPushButton("CLEAR")
        self.btn_clear.clicked.connect(self._clear_output)
        cfg_lay.addWidget(self.btn_clear)

        root.addWidget(cfg_frame)

        # Output transcript
        self.txt = QPlainTextEdit()
        self.txt.setReadOnly(True)
        self.txt.setFont(QFont(FONT_MONO, 10))
        self.txt.setPlaceholderText(
            "  SENTINEL-F standing by.\n"
            "  ▸  Load a file & run a forensic analysis, then press "
            "'RUN SECOND-OPINION' to have the local AI review the findings.\n"
            "  ▸  Or use the chat box below for freeform forensic questions."
        )
        root.addWidget(self.txt, stretch=1)

        # Chat input
        input_frame = QFrame()
        input_frame.setObjectName("Card")
        il = QHBoxLayout(input_frame)
        il.setContentsMargins(8, 6, 8, 6)
        il.setSpacing(6)

        prompt_label = QLabel("▸")
        prompt_label.setStyleSheet(
            f"color:{T['accent']}; font-size:12pt; font-weight:bold;"
        )
        il.addWidget(prompt_label)

        self.input = QLineEdit()
        self.input.setPlaceholderText("Ask SENTINEL-F anything about the current file or forensics …")
        self.input.returnPressed.connect(self._send_chat)
        il.addWidget(self.input, stretch=1)

        self.btn_send = QPushButton("SEND")
        self.btn_send.setObjectName("PrimaryBtn")
        self.btn_send.clicked.connect(self._send_chat)
        il.addWidget(self.btn_send)

        root.addWidget(input_frame)

    # ─── Probe ───────────────────────────────────────────────────────
    def _probe_worker(self):
        try:
            self.bridge.status.emit(False, "probing…")
            ok, info = self.client.probe(timeout=3)
            self.bridge.status.emit(ok, info)
            if ok:
                self.bridge.models.emit(self.client.list_models())
        except RuntimeError:          # Fenster wurde inzwischen geschlossen
            pass

    def _on_status(self, ok, info):
        self._online = ok and "NOT installed" not in info
        if ok:
            self.lbl_status.setText(f"◉  ONLINE  ·  {info}")
            self.lbl_status.setStyleSheet(
                f"color:{T['ok']}; font-size:9pt; letter-spacing:1.5px; font-weight:bold;"
                f"font-family:'{FONT_MONO}',monospace;"
            )
        else:
            self.lbl_status.setText(f"◉  OFFLINE  ·  {info}")
            self.lbl_status.setStyleSheet(
                f"color:{T['err']}; font-size:9pt; letter-spacing:1.5px; font-weight:bold;"
                f"font-family:'{FONT_MONO}',monospace;"
            )
        # find parent main window to update dashboard card
        self._bubble_status(ok, info)

    def _bubble_status(self, ok, info):
        # find DashboardView through parent chain
        parent = self.parent()
        while parent is not None:
            if hasattr(parent, "dashboard"):
                try:
                    parent.dashboard.set_ollama_status(ok, info)
                except Exception:
                    pass
                break
            parent = parent.parent()

    def _on_models(self, models):
        current = self.cb_model.currentText()
        self.cb_model.clear()
        if models:
            self.cb_model.addItems(models)
        if current and current not in models:
            self.cb_model.addItem(current)
            self.cb_model.setCurrentText(current)

    # ─── Result ingestion ────────────────────────────────────────────
    def load_result(self, result):
        self._last_result = result
        self._context = {}
        self.btn_analyze.setEnabled(bool(result and result.get("ok")))
        self.btn_detective.setEnabled(bool(result and result.get("ok")))

    def set_context(self, similar=None, previous=None, case_rows=None):
        """Vom Hauptfenster: ähnliche/frühere Dateien und Fall-Geschwister als zusätzliche Belege."""
        self._context.update({k: v for k, v in (("similar", similar), ("previous", previous),
                                                ("case_rows", case_rows)) if v is not None})

    def evidence(self):
        return detective.build_evidence(self._last_result or {}, **self._context)

    def reset(self):
        self._last_result = None
        self._context = {}
        self.btn_analyze.setEnabled(False)
        self.btn_detective.setEnabled(False)

    # ─── Detektiv ────────────────────────────────────────────────────
    def run_detective(self):
        if self._busy or not (self._last_result and self._last_result.get("ok")):
            return
        ev = self.evidence()
        name = (self._last_result.get("file") or {}).get("name", "?")
        self._write_system(f"─── 🕵 DETECTIVE  ·  {name}  ·  {len(ev)} evidence items  ·  "
                           f"{datetime.datetime.now().strftime('%H:%M:%S')}  ────────")
        self._write_evidence(ev)
        if not self._online:
            text = detective.narrative(ev, lang="de")
            annotated, summary, _v = detective.annotate(text, ev)
            self.txt.appendPlainText("NARRATIVE (offline · rule-based · deterministic):\n")
            self.txt.appendPlainText(annotated)
            self.txt.appendPlainText(f"\n✔ {summary}\n")
            return
        self._stream_llm(detective.llm_prompt(ev), ev, header="NARRATIVE (local model · verified):\n")

    def _write_evidence(self, ev):
        self.txt.appendPlainText("EVIDENCE:")
        for e in ev:
            self.txt.appendPlainText(f"  [{e['id']}] {e['kind']:<8} {e['text']}")
        self.txt.appendPlainText("")

    def _stream_llm(self, prompt, ev, header=""):
        model = self.cb_model.currentText().strip() or OLLAMA_MODEL
        self.client.model = model
        if header:
            self.txt.appendPlainText(header)
        self._verify_ev = ev
        self.txt.moveCursor(QTextCursor.MoveOperation.End)
        self._answer_start = len(self.txt.toPlainText())
        self._busy = True
        for b in (self.btn_analyze, self.btn_send, self.btn_detective):
            b.setEnabled(False)

        def worker():
            try:
                self.client._generate_stream(prompt, system=detective.SYSTEM,
                                             on_token=lambda t: self.bridge.token.emit(t))
                self.bridge.done.emit()
            except Exception as e:
                self.bridge.failed.emit(str(e))
        threading.Thread(target=worker, daemon=True).start()

    # ─── Actions ─────────────────────────────────────────────────────
    def _run_analysis(self):
        if self._busy:
            return
        if not self._last_result or not self._last_result.get("ok"):
            QMessageBox.information(self, "AI Analysis",
                "Run a forensic analysis first.")
            return
        model = self.cb_model.currentText().strip() or OLLAMA_MODEL
        self.client.model = model

        self._write_system(
            f"─── SENTINEL-F SECOND-OPINION  ·  {model}  "
            f"·  {datetime.datetime.now().strftime('%H:%M:%S')}  ────────"
        )
        self._busy = True
        self.btn_analyze.setEnabled(False)
        self.btn_send.setEnabled(False)

        def worker():
            try:
                self.client.analyze_report(
                    file_kind = self._last_result.get("kind", "unknown"),
                    file_info = self._last_result.get("file", {}),
                    heuristic_result = self._last_result.get("score", {}),
                    on_token  = lambda t: self.bridge.token.emit(t),
                )
                self.bridge.done.emit()
            except Exception as e:
                self.bridge.failed.emit(str(e))

        threading.Thread(target=worker, daemon=True).start()

    def _send_chat(self):
        if self._busy:
            return
        text = self.input.text().strip()
        if not text:
            return
        self.input.clear()
        model = self.cb_model.currentText().strip() or OLLAMA_MODEL
        self.client.model = model

        self._write_user(text)
        self._write_system_inline("▸ SENTINEL-F: ")

        # Mit geladenem Befund: Frage wird gegen die Beweisliste beantwortet und geprüft
        if self._last_result and self._last_result.get("ok"):
            ev = self.evidence()
            self._stream_llm(detective.llm_prompt(ev, question=text), ev)
            return
        context = ""
        if self._last_result and self._last_result.get("ok"):
            fi = self._last_result.get("file", {})
            sc = self._last_result.get("score", {})
            th = self._last_result.get("threat") or {}
            context = (
                f"[context: current file = {fi.get('name','?')}, "
                f"kind={self._last_result.get('kind','?')}, "
                f"heuristic_score={sc.get('score','?')}/100 ({sc.get('level','?')}), "
                f"threat_areas={', '.join(th.get('families') or []) or 'none'}, "
                f"top_signal={th.get('headline','-')}]\n\n"
            )
        full_prompt = context + text

        self._busy = True
        self.btn_analyze.setEnabled(False)
        self.btn_send.setEnabled(False)

        def worker():
            try:
                self.client.chat(full_prompt, on_token=lambda t: self.bridge.token.emit(t))
                self.bridge.done.emit()
            except Exception as e:
                self.bridge.failed.emit(str(e))
        threading.Thread(target=worker, daemon=True).start()

    def _clear_output(self):
        self.txt.clear()

    # ─── Output helpers ──────────────────────────────────────────────
    def _append_token(self, text):
        self.txt.moveCursor(QTextCursor.MoveOperation.End)
        self.txt.insertPlainText(text)
        self.txt.moveCursor(QTextCursor.MoveOperation.End)

    def _write_system(self, text):
        self.txt.appendPlainText("")
        self.txt.appendPlainText(text)
        self.txt.appendPlainText("")

    def _write_system_inline(self, text):
        self.txt.appendPlainText("")
        self.txt.moveCursor(QTextCursor.MoveOperation.End)
        self.txt.insertPlainText(text)

    def _write_user(self, text):
        self.txt.appendPlainText("")
        self.txt.appendPlainText(
            f"▸ YOU: {text}"
        )

    def _on_done(self):
        self._busy = False
        self.btn_analyze.setEnabled(bool(self._last_result and self._last_result.get("ok")))
        self.btn_detective.setEnabled(bool(self._last_result and self._last_result.get("ok")))
        self.btn_send.setEnabled(True)
        if self._verify_ev is not None:
            answer = self.txt.toPlainText()[self._answer_start:]
            annotated, summary, v = detective.annotate(answer, self._verify_ev)
            self._verify_ev = None
            if any(not ok for _s, ok, _i in v["sentences"]):
                self.txt.appendPlainText("\nVERIFIED VIEW (⚠ = statement without valid evidence):")
                self.txt.appendPlainText(annotated)
            self.txt.appendPlainText(f"\n✔ {summary}")
        self.txt.appendPlainText("")
        self.txt.appendPlainText("─── END ───────────────────────────────────────────────")
        self.txt.appendPlainText("")

    def _on_failed(self, err):
        self._busy = False
        self._verify_ev = None
        self.btn_detective.setEnabled(bool(self._last_result and self._last_result.get("ok")))
        self.btn_analyze.setEnabled(bool(self._last_result and self._last_result.get("ok")))
        self.btn_send.setEnabled(True)
        self.txt.appendPlainText(f"\n[ERROR] {err}\n")
