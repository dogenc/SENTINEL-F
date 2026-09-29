"""Tab LINEAGE: Stammbaum des Dokuments – frühere Fassungen, Zweige, spätere Ableitungen."""
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTreeWidget, QTreeWidgetItem

from config.settings import T, SCORE_LEVELS

LEVEL_COLOR = {lab: T.get(key, T["text"]) for _, lab, key in SCORE_LEVELS}
GROUPS = (("ancestor", "▲  EARLIER VERSIONS / SOURCES"), ("sibling", "◆  SAME ORIGIN, EDITED SEPARATELY"),
          ("descendant", "▼  LATER VERSIONS / DERIVED FILES"))


class LineageView(QWidget):
    openRequested = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        self.lbl = QLabel()
        self.lbl.setWordWrap(True)
        self.lbl.setStyleSheet(f"color:{T['text_dim']}; font-size:10pt; padding:8px;"
                               f"border:1px solid {T['border']}; background:{T['card']};")
        lay.addWidget(self.lbl)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["DOCUMENT", "EVIDENCE", "VERDICT", "CASE", "ANALYSED"])
        for c, w in enumerate((300, 520, 110, 160)):
            self.tree.setColumnWidth(c, w)
        self.tree.itemDoubleClicked.connect(self._open)
        lay.addWidget(self.tree, stretch=1)
        self.count = 0
        self.set_data(None, None)

    def set_data(self, result, rows, ids=None):
        self.tree.clear()
        rows = rows or []
        self.count = len(rows)
        if result is None:
            self.lbl.setText("  —  no file analyzed")
            return
        lin = (((result.get("report") or {}).get("analyzers") or {}).get("lineage") or {})
        keys = [k for k in ("pdf_id0", "xmp_orig", "xmp_doc", "rsid_root") if lin.get(k)]
        info = ", ".join(f"{k}={str(lin[k])[:14]}…" for k in keys) or "no provenance IDs in this file"
        extra = f" · {lin['pdf_saves']} PDF save states" if lin.get("pdf_saves", 1) > 1 else ""
        self.lbl.setText(f"  {len(rows)} related document(s) in the history  ·  {info}{extra}")
        me = (result.get("file") or {}).get("name", "this file")
        for rel, title in GROUPS:
            group = [r for r in rows if r["relation"] == rel]
            if not group and rel != "sibling":
                continue
            head = QTreeWidgetItem(self.tree, [title, "", "", "", ""])
            head.setForeground(0, QColor(T["cyan"]))
            for r in group:
                it = QTreeWidgetItem(head, [r["name"], r["evidence"], f"{r['level']} {r['score']}",
                                            r.get("case_name") or "—", r["analyzed_at"]])
                it.setData(0, Qt.ItemDataRole.UserRole, r["id"])
                it.setToolTip(0, r.get("path") or "")
                it.setForeground(2, QColor(LEVEL_COLOR.get(r["level"], T["text"])))
            if rel == "sibling":
                cur = QTreeWidgetItem(self.tree, [f"●  THIS FILE: {me}", "", "", "", ""])
                cur.setForeground(0, QColor(T["accent"]))
        self.tree.expandAll()

    def _open(self, item, _col):
        aid = item.data(0, Qt.ItemDataRole.UserRole)
        if aid is not None:
            self.openRequested.emit(int(aid))
