"""
Tab SIMILAR: Dateien aus dem Verlauf, die der aktuellen ähneln, aber nicht
identisch sind – per TLSH-Fuzzy-Hash, Imphash oder Rich-Header.
Doppelklick öffnet die gespeicherte Analyse.
"""
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QAbstractItemView
)

from config.settings import T, SCORE_LEVELS
from engines.similarity import label as tlsh_label

LEVEL_COLOR = {lab: T.get(key, T["text"]) for _, lab, key in SCORE_LEVELS}
REASON = {"tlsh": "fuzzy hash (TLSH)", "imphash": "same imports (imphash)", "rich": "same build env (Rich)",
          "prnu": "same camera sensor (PRNU)"}


class SimilarView(QWidget):
    openRequested = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        self.lbl = QLabel()
        self.lbl.setWordWrap(True)
        self.lbl.setStyleSheet(f"color:{T['text_dim']}; font-size:10pt; padding:8px;"
                               f"border:1px solid {T['border']}; background:{T['card']};")
        root.addWidget(self.lbl)
        t = QTableWidget(0, 7)
        t.setHorizontalHeaderLabels(["FILE", "SIMILARITY", "MATCHED BY", "LEVEL", "SCORE", "CASE", "ANALYSED"])
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        for c, w in enumerate((240, 170, 300, 90, 60, 170)):
            t.setColumnWidth(c, w)
        t.horizontalHeader().setStretchLastSection(True)
        t.doubleClicked.connect(self._open)
        self.table = t
        root.addWidget(t, stretch=1)
        self.fp = {}
        self.set_matches(None)

    def set_fingerprints(self, fp):
        self.fp = fp or {}

    def set_matches(self, rows):
        fp_txt = "  ·  ".join(f"{k.upper()} {v[:24]}…" if len(v) > 24 else f"{k.upper()} {v}"
                              for k, v in self.fp.items() if k != "prnu")
        if self.fp.get("prnu"):
            fp_txt += f"  ·  CAMERA NOISE {self.fp['prnu'].split(':', 1)[0]}"
        if rows is None:
            self.lbl.setText("  —  no file analyzed")
        elif not rows:
            self.lbl.setText(f"  No similar file in the history yet.\n  {fp_txt or 'no comparable fingerprint'}")
        else:
            worst = max((r.get("score") or 0) for r in rows)
            self.lbl.setText(f"  {len(rows)} similar file(s) in the history"
                             + (f"  ·  ⚠ one of them scored {worst}/100" if worst >= 60 else "")
                             + f"\n  {fp_txt}")
        rows = rows or []
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            d = row.get("distance")
            sim = (f"TLSH {d} · {tlsh_label(d)}" if d is not None else
                   f"sensor noise r={row['ncc']}" if row.get("ncc") is not None else "exact fingerprint")
            vals = [row.get("name") or "", sim, ", ".join(REASON.get(m, m) for m in row["match"]),
                    row.get("level") or "", str(row.get("score") if row.get("score") is not None else "—"),
                    row.get("case_name") or "—", row.get("analyzed_at") or ""]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setData(Qt.ItemDataRole.UserRole, row["id"])
                    it.setToolTip(row.get("path") or "")
                if c in (3, 4):
                    it.setForeground(QColor(LEVEL_COLOR.get(row.get("level"), T["text"])))
                self.table.setItem(r, c, it)

    def _open(self, index):
        aid = self.table.item(index.row(), 0).data(Qt.ItemDataRole.UserRole)
        if aid is not None:
            self.openRequested.emit(int(aid))
