"""Tab INTEL: Hash-Abfrage bei CIRCL / VirusTotal / MalwareBazaar (opt-in, nur Hashes)."""
import threading

from PyQt6.QtCore import Qt, QObject, pyqtSignal, QUrl
from PyQt6.QtGui import QColor, QDesktopServices
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QAbstractItemView
)

from config.settings import T
from core import threatintel

STATUS_COLOR = {"malicious": T["crit"], "suspicious": T["warn"], "clean": T["ok"], "known_good": T["ok"],
                "unknown": T["text_dim"], "skipped": T["text_mute"], "error": T["err"]}
NAMES = {"circl": "CIRCL hashlookup", "virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar"}


class _Bridge(QObject):
    done = pyqtSignal(dict)


class IntelView(QWidget):
    intelChanged = pyqtSignal(dict)

    def __init__(self, parent=None, db_fn=None, lookup_fn=None):
        super().__init__(parent)
        self.db_fn = db_fn
        self.lookup_fn = lookup_fn
        self.result = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        top = QHBoxLayout()
        self.lbl = QLabel()
        self.lbl.setWordWrap(True)
        self.lbl.setTextFormat(Qt.TextFormat.RichText)
        self.lbl.setStyleSheet(f"color:{T['text_dim']}; font-size:10pt; padding:8px;"
                               f"border:1px solid {T['border']}; background:{T['card']};")
        top.addWidget(self.lbl, stretch=1)
        self.btn = QPushButton("☁  LOOK UP HASHES")
        self.btn.setObjectName("PrimaryBtn")
        self.btn.clicked.connect(lambda: self.run_lookup())
        top.addWidget(self.btn)
        lay.addLayout(top)
        t = QTableWidget(0, 4)
        t.setHorizontalHeaderLabels(["SERVICE", "RESULT", "DETAIL", "LINK"])
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.verticalHeader().setVisible(False)
        t.horizontalHeader().setStretchLastSection(True)
        for c, w in enumerate((170, 110, 640)):
            t.setColumnWidth(c, w)
        t.cellDoubleClicked.connect(self._open_link)
        self.table = t
        lay.addWidget(t, stretch=1)
        note = QLabel("Only the SHA-256 is sent – the file itself never leaves this computer. "
                      "Enable with HASH_LOOKUP_ENABLED (or env DGKN_HASH_LOOKUP=1); VirusTotal/MalwareBazaar need "
                      "your own keys (VT_API_KEY / MB_AUTH_KEY in config/local_secrets.py).")
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{T['text_mute']}; font-size:8pt;")
        lay.addWidget(note)
        self.bridge = _Bridge()
        self.bridge.done.connect(self._show)
        self.set_result(None)

    def set_result(self, result):
        self.result = result
        cfg = threatintel.settings()
        self.table.setRowCount(0)
        if not result:
            self.lbl.setText("&nbsp; —&nbsp; no file analyzed")
            self.btn.setEnabled(False)
            return
        self.btn.setEnabled(cfg["enabled"])
        if result.get("intel"):
            self._show(result["intel"], emit=False)
        elif not cfg["enabled"]:
            self.lbl.setText("&nbsp; Hash lookup is <b>off</b> (privacy default). Nothing has been sent anywhere.")
        else:
            self.lbl.setText("&nbsp; Press <b>LOOK UP HASHES</b> to ask the configured services about this SHA-256.")

    def run_lookup(self, run_async=True, force=False):
        if not self.result:
            return
        sha = (self.result.get("hashes") or {}).get("sha256")
        self.btn.setEnabled(False)
        self.lbl.setText("&nbsp; Querying … (only the hash is sent)")

        def work():
            try:
                if self.lookup_fn:
                    data = self.lookup_fn(sha)
                else:
                    db = self.db_fn() if self.db_fn else None
                    data = threatintel.cached_lookup(db, sha, force=force) if db else threatintel.lookup(sha)
            except Exception as e:
                data = {"_error": f"{type(e).__name__}: {e}"}
            try:
                self.bridge.done.emit(data)
            except RuntimeError:
                pass
        if run_async:
            threading.Thread(target=work, daemon=True).start()
        else:
            work()

    def _show(self, data, emit=True):
        rows = [(k, v) for k, v in data.items() if not k.startswith("_")]
        self.table.setRowCount(len(rows))
        for i, (prov, r) in enumerate(rows):
            vals = [NAMES.get(prov, prov), (r.get("status") or "").upper().replace("_", " "), r.get("detail") or "",
                    r.get("link") or ""]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(str(v))
                if c == 1:
                    it.setForeground(QColor(STATUS_COLOR.get(r.get("status"), T["text"])))
                self.table.setItem(i, c, it)
        verdict = threatintel.summary({k: v for k, v in rows})
        col = STATUS_COLOR.get(verdict, T["text"])
        when = " · cached" if data.get("_cached") else (f" · {data['_fetched']}" if data.get("_fetched") else "")
        err = f" · <span style='color:{T['err']}'>{data['_error']}</span>" if data.get("_error") else ""
        self.lbl.setText(f"&nbsp; Threat-intel verdict: <b style='color:{col}'>{verdict.upper().replace('_', ' ')}"
                         f"</b>{when}{err}")
        self.btn.setEnabled(threatintel.settings()["enabled"])
        if self.result is not None and rows:
            self.result["intel"] = {k: v for k, v in data.items()}
            if emit:
                self.intelChanged.emit(self.result["intel"])

    def _open_link(self, row, col):
        it = self.table.item(row, 3)
        if it and it.text().startswith("https://"):
            QDesktopServices.openUrl(QUrl(it.text()))
