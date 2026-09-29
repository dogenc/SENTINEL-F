"""
ATT&CK-Matrix: eine Spalte je Taktik (Kill-Chain-Reihenfolge), darin die
getroffenen Techniken. Farbe = höchster Schweregrad der auslösenden Signale.
Ein Klick auf eine Technik öffnet die offizielle MITRE-Seite.
"""
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QScrollArea, QSizePolicy
)

from config.settings import T
from engines.attack import TACTIC_NAMES, map_result

SEV_COLOR = {"CRIT": T["crit"], "WARN": T["warn"], "INFO": T["text_mute"]}


class _Chip(QLabel):
    def __init__(self, tech):
        short = tech["name"].split(": ", 1)[-1]
        super().__init__(f"<b>{tech['id']}</b><br>{short}")
        col = SEV_COLOR.get(tech["severity"], T["text_dim"])
        self.setWordWrap(True)
        self.setTextFormat(Qt.TextFormat.RichText)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(f"{tech['id']} · {tech['name']}\nSignals: {', '.join(tech['codes'])}\n"
                        f"Click: open MITRE ATT&CK page")
        self.setStyleSheet(
            f"QLabel{{color:{T['text_hot'] if tech['severity'] != 'INFO' else T['text_dim']};"
            f"background:{T['card']}; border:1px solid {col}; border-left:4px solid {col};"
            f"border-radius:4px; padding:5px 6px; font-size:8pt;}}"
        )
        self._url = tech["url"]

    def mousePressEvent(self, e):
        QDesktopServices.openUrl(QUrl(self._url))


class AttackMatrix(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        self.lbl_summary = QLabel("  —  no file analyzed")
        self.lbl_summary.setWordWrap(True)
        self.lbl_summary.setStyleSheet(
            f"color:{T['text_dim']}; font-size:10pt; letter-spacing:1px; padding:8px;"
            f"border:1px solid {T['border']}; background:{T['card']};")
        root.addWidget(self.lbl_summary)

        self._inner = QWidget()
        self._inner.setObjectName("AttackInner")
        self._inner.setStyleSheet(f"QWidget#AttackInner{{background:{T['bg']};}}")
        self._cols = QHBoxLayout(self._inner)
        self._cols.setContentsMargins(0, 0, 0, 0)
        self._cols.setSpacing(6)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(f"QScrollArea{{background:{T['bg']}; border:none;}}")
        scroll.setWidget(self._inner)
        root.addWidget(scroll, stretch=1)

        legend = QLabel(
            f"<span style='color:{T['crit']}'>■</span> critical signal &nbsp; "
            f"<span style='color:{T['warn']}'>■</span> warning &nbsp; "
            f"<span style='color:{T['text_mute']}'>■</span> context only (not counted) &nbsp;·&nbsp; "
            "MITRE ATT&amp;CK® Enterprise · static indicators, not observed behaviour")
        legend.setStyleSheet(f"color:{T['text_mute']}; font-size:8pt;")
        root.addWidget(legend)
        self.data = None
        self.set_result(None)

    def _clear(self):
        while self._cols.count():
            it = self._cols.takeAt(0)
            w = it.widget()
            if w:
                w.hide()                 # sofort weg, nicht erst beim nächsten Event-Loop-Durchlauf
                w.setParent(None)
                w.deleteLater()

    def set_result(self, result):
        self._clear()
        self.data = map_result(result) if result else {"techniques": [], "tactics": {n: 0 for n in TACTIC_NAMES}}
        techs = self.data["techniques"]
        hot = [t for t in techs if t["severity"] != "INFO"]
        if result is None:
            self.lbl_summary.setText("  —  no file analyzed")
        elif not techs:
            self.lbl_summary.setText("  No signal maps to an ATT&CK technique.")
        else:
            active = [n for n, c in self.data["tactics"].items() if c]
            self.lbl_summary.setText(
                f"  {len(hot)} TECHNIQUE(S) across {len(active)} TACTIC(S)"
                + (f"  ·  {' → '.join(active)}" if active else "")
                + (f"  ·  +{len(techs) - len(hot)} context" if len(techs) > len(hot) else ""))
        peak = max(self.data["tactics"].values() or [0]) or 1
        for tactic in TACTIC_NAMES:
            col = QFrame()
            col.setMinimumWidth(96)
            col.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
            lay = QVBoxLayout(col)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.setSpacing(4)
            n = self.data["tactics"][tactic]
            # Kopf: Deckkraft wächst mit der Zahl der Techniken (Heatmap)
            alpha = 0.0 if not n else 0.14 + 0.36 * n / peak
            head = QLabel(f"{tactic}<br><span style='font-size:13pt'>{n}</span>")
            head.setTextFormat(Qt.TextFormat.RichText)
            head.setAlignment(Qt.AlignmentFlag.AlignCenter)
            head.setWordWrap(True)
            head.setFixedHeight(58)
            head.setStyleSheet(
                f"QLabel{{color:{T['text_hot'] if n else T['text_mute']}; font-size:8pt; font-weight:bold;"
                f"letter-spacing:0px; padding:4px 3px; border-radius:4px;"
                f"border:1px solid {T['crit'] if n else T['border']};"
                f"background:rgba(255,42,63,{alpha:.2f});}}")
            lay.addWidget(head)
            for t in techs:
                if t["tactics"][0] == tactic or (tactic in t["tactics"] and t["severity"] != "INFO"):
                    lay.addWidget(_Chip(t))
            lay.addStretch(1)
            self._cols.addWidget(col)
