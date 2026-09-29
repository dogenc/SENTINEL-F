"""Dialog: generierte YARA-Regel prüfen, bearbeiten, gegen den Verlauf testen und aktivieren."""
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QFileDialog, QMessageBox
)

from config.settings import T, FONT_MONO, REPORT_DIR
from core import intel
from core.utils import LOG


class RuleDialog(QDialog):
    def __init__(self, parent, db, rule):
        super().__init__(parent)
        self.db, self.rule = db, rule
        self.setWindowTitle(f"Generated YARA rule · {rule['name']}")
        self.resize(900, 640)
        self.setStyleSheet(f"QDialog{{background:{T['bg_alt']};}} QLabel{{color:{T['text']};}}")
        lay = QVBoxLayout(self)
        self.lbl = QLabel()
        self.lbl.setWordWrap(True)
        self.lbl.setStyleSheet(f"padding:8px; background:{T['card']}; border:1px solid {T['border']};")
        lay.addWidget(self.lbl)
        self.edit = QPlainTextEdit(rule["text"])
        self.edit.setFont(QFont(FONT_MONO, 9))
        lay.addWidget(self.edit, stretch=1)
        row = QHBoxLayout()
        self.btn_test = QPushButton("↻  RE-TEST")
        self.btn_test.clicked.connect(self.run_test)
        self.btn_save = QPushButton("SAVE AS…")
        self.btn_save.clicked.connect(self.save_as)
        self.btn_activate = QPushButton("◉  ACTIVATE FOR ALL FUTURE SCANS")
        self.btn_activate.setObjectName("PrimaryBtn")
        self.btn_activate.clicked.connect(self.activate)
        close = QPushButton("CLOSE")
        close.clicked.connect(self.reject)
        for b in (self.btn_test, self.btn_save):
            row.addWidget(b)
        row.addStretch(1)
        row.addWidget(self.btn_activate)
        row.addWidget(close)
        lay.addLayout(row)
        self.activated_path = None
        self.run_test()

    def run_test(self):
        self.rule["text"] = self.edit.toPlainText()
        err = intel.compile_check(self.rule["text"])
        bt = intel.backtest(self.db, self.rule)
        n_in, n_out = len(bt["inside"]), len(bt["outside"])
        outside = ", ".join(r["name"] for r in bt["outside"][:6])
        col = T["ok"] if not n_out and not err else T["warn"]
        self.lbl.setText(
            f"<b>Back-test against the whole history</b> (simulated on stored IOCs/imphash): "
            f"<span style='color:{T['ok']}'>{n_in}/{bt['cluster_size']} cluster files matched</span> · "
            f"<span style='color:{col}'>{n_out} other file(s) matched</span>"
            + (f" – {outside}" if outside else " – no collateral hits")
            + (f"<br><span style='color:{T['err']}'>YARA compile error: {err}</span>" if err else
               "<br>Rule compiles. Activating stores it in data/yara_generated – every new analysis, "
               "batch scan and the folder watch will use it."))
        self.btn_activate.setEnabled(not err)

    def save_as(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save YARA rule", str(REPORT_DIR / f"{self.rule['name']}.yar"),
                                              "YARA (*.yar)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.edit.toPlainText())

    def activate(self):
        self.rule["text"] = self.edit.toPlainText()
        if intel.compile_check(self.rule["text"]):
            return
        self.activated_path = intel.activate(self.rule)
        LOG.log(f"YARA rule activated: {self.activated_path.name}", "OK")
        QMessageBox.information(self, "Activated", f"Rule active for all future scans:\n{self.activated_path}")
        self.accept()
