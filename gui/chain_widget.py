"""
Tab CHAIN: die Payload-Kette als Baum – welche versteckte Stufe steckt worin,
wie gefährlich ist jede einzelne, und wo liegt die eigentliche Ursache.
"""
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTreeWidget, QTreeWidgetItem

from config.settings import T, SCORE_LEVELS, FONT_MONO
from core.utils import human_size

LEVEL_COLOR = {lab: T.get(key, T["text"]) for _, lab, key in SCORE_LEVELS}


class ChainView(QWidget):
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
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["STAGE", "FOUND AS", "TRUE TYPE", "VERDICT", "SIZE", "SHA-256", "CAUSE"])
        self.tree.setAlternatingRowColors(True)
        for c, w in enumerate((260, 170, 150, 110, 70, 130)):
            self.tree.setColumnWidth(c, w)
        root.addWidget(self.tree, stretch=1)
        note = QLabel("Every stage is extracted in memory, analysed with the full pipeline (inside the sandbox) "
                      "and never executed. Danger is inherited upwards.")
        note.setStyleSheet(f"color:{T['text_mute']}; font-size:8pt;")
        root.addWidget(note)
        self.count = 0
        self.set_result(None)

    def _item(self, parent, n):
        vals = [n.get("name") or "", n.get("source") or "", n.get("true_type") or n.get("kind") or "",
                f"{n.get('level') or 'ERROR'} {n.get('score') if n.get('score') is not None else ''}",
                human_size(n.get("size") or 0), (n.get("sha256") or "")[:16] + "…",
                n.get("cause") or n.get("error") or ""]
        it = QTreeWidgetItem(parent, vals)
        col = QColor(LEVEL_COLOR.get(n.get("level"), T["err"]))
        it.setForeground(3, col)
        if n.get("level") in ("HIGH RISK", "CRITICAL"):
            it.setForeground(0, col)
        it.setToolTip(5, n.get("sha256") or "")
        it.setToolTip(6, "\n".join(f"[{f['severity']}] {f['desc']}" for f in n.get("findings") or []))
        it.setFont(5, QFont(FONT_MONO, 8))
        self.count += 1
        for c in n.get("children") or []:
            self._item(it, c)
        return it

    def set_result(self, result):
        self.tree.clear()
        self.count = 0
        if not result:
            self.lbl.setText("  —  no file analyzed")
            return
        tree = result.get("payloads") or []
        fi, sc = result.get("file") or {}, result.get("score") or {}
        top = QTreeWidgetItem(self.tree, [fi.get("name") or "file", "analysed file",
                                          (result.get("filetype") or {}).get("description") or "",
                                          f"{sc.get('level')} {sc.get('score')}", human_size(fi.get("size") or 0),
                                          ((result.get("hashes") or {}).get("sha256") or "")[:16] + "…", ""])
        top.setForeground(3, QColor(LEVEL_COLOR.get(sc.get("level"), T["text"])))
        for n in tree:
            self._item(top, n)
        self.tree.expandAll()
        if not tree:
            self.lbl.setText("  No hidden stages found (archives, attachments, macros, encoded commands, "
                             "Base64 blobs, embedded programs, appended data).")
        else:
            bad = [n for n in _walk(tree) if n.get("level") in ("HIGH RISK", "CRITICAL")]
            self.lbl.setText(f"  {self.count} hidden stage(s) extracted and analysed"
                             + (f"  ·  ⚠ {len(bad)} dangerous" if bad else "  ·  none dangerous"))


def _walk(tree):
    for n in tree or []:
        yield n
        yield from _walk(n.get("children"))
