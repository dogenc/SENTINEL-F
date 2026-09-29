"""
Zeitleisten-Tab: Widersprüche oben, darunter eine Achse aller Zeitstempel
(gleichmäßige Abstände, Lücken beschriftet – sonst würden 1998 und 2026 auf
einer linearen Achse alles zusammenquetschen) und die vollständige Tabelle.
"""
import datetime

from PyQt6.QtCore import Qt, QRectF, QPointF
from PyQt6.QtGui import QPainter, QColor, QPen, QFont, QBrush
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QAbstractItemView,
    QScrollArea, QFrame
)

from config.settings import T, FONT_MONO
from engines.timeline import build_timeline

SOURCE_COLOR = {
    "File system": T["text_dim"], "EXIF": T["cyan"], "XMP": T["cyan"], "PDF": "#b48cff",
    "Office": "#5aa0ff", "PE header": T["warn"], "E-mail": "#ff8ad8", "SENTINEL-F": T["accent"],
}


def _fmt_gap(a, b):
    d = (datetime.datetime.fromisoformat(b) - datetime.datetime.fromisoformat(a)).total_seconds()
    if d < 86400:
        return None
    days = d / 86400
    if days >= 730:
        return f"{days / 365.25:.0f} years"
    if days >= 60:
        return f"{days / 30.4:.0f} months"
    return f"{days:.0f} days"


class _Axis(QWidget):
    STEP = 150

    def __init__(self):
        super().__init__()
        self.groups = []            # [(ts, [events])]
        self.flagged = set()
        self.setMinimumHeight(190)

    def set_events(self, events, flagged):
        groups = []
        for e in events:
            if groups and groups[-1][0] == e["ts"]:
                groups[-1][1].append(e)
            else:
                groups.append((e["ts"], [e]))
        self.groups = groups
        self.flagged = flagged
        self.setMinimumWidth(max(600, 80 + self.STEP * max(1, len(groups))))
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(T["bg"]))
        if not self.groups:
            p.setPen(QColor(T["text_mute"]))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "no timestamps")
            return
        y = 64
        x0 = 60
        xs = [x0 + i * self.STEP for i in range(len(self.groups))]
        p.setPen(QPen(QColor(T["border_hot"]), 2))
        p.drawLine(QPointF(x0 - 30, y), QPointF(xs[-1] + 30, y))
        small = QFont(FONT_MONO, 7)
        norm = QFont(FONT_MONO, 8)
        for i, (ts, evs) in enumerate(self.groups):
            x = xs[i]
            if i:
                gap = _fmt_gap(self.groups[i - 1][0], ts)
                if gap:
                    p.setFont(small)
                    p.setPen(QColor(T["text_mute"]))
                    p.drawText(QRectF(xs[i - 1], y - 26, self.STEP, 14), Qt.AlignmentFlag.AlignCenter, f"⋯ {gap} ⋯")
            hot = any(e["label"] in self.flagged for e in evs)
            col = QColor(T["crit"] if hot else SOURCE_COLOR.get(evs[0]["source"], T["text"]))
            p.setPen(QPen(col, 2))
            p.setBrush(QBrush(QColor(T["bg"]) if not hot else col))
            p.drawEllipse(QPointF(x, y), 7, 7)
            p.setFont(norm)
            p.setPen(QColor(T["text_hot"]))
            p.drawText(QRectF(x - self.STEP / 2, y - 50, self.STEP, 16), Qt.AlignmentFlag.AlignCenter, ts[:10])
            p.setPen(QColor(T["text_dim"]))
            p.drawText(QRectF(x - self.STEP / 2, y + 12, self.STEP, 14), Qt.AlignmentFlag.AlignCenter, ts[11:])
            for j, e in enumerate(evs[:5]):
                ecol = QColor(T["crit"] if e["label"] in self.flagged else SOURCE_COLOR.get(e["source"], T["text"]))
                p.setPen(ecol)
                p.setFont(small)
                p.drawText(QRectF(x - self.STEP / 2 + 4, y + 30 + j * 26, self.STEP - 8, 26),
                           Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop | Qt.TextFlag.TextWordWrap,
                           e["label"])
            if len(evs) > 5:
                p.setPen(QColor(T["text_mute"]))
                p.drawText(QRectF(x - 40, y + 160, 80, 14), Qt.AlignmentFlag.AlignCenter, f"+{len(evs) - 5}")


class TimelineView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)
        self.lbl_summary = QLabel()
        self.lbl_summary.setWordWrap(True)
        self.lbl_summary.setTextFormat(Qt.TextFormat.RichText)
        self.lbl_summary.setStyleSheet(
            f"color:{T['text_dim']}; font-size:10pt; padding:8px;"
            f"border:1px solid {T['border']}; background:{T['card']};")
        root.addWidget(self.lbl_summary)

        self.axis = _Axis()
        scroll = QScrollArea()
        scroll.setWidget(self.axis)
        scroll.setWidgetResizable(True)
        scroll.setFixedHeight(214)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet(f"QScrollArea{{background:{T['bg']}; border:1px solid {T['border']};}}")
        root.addWidget(scroll)

        t = QTableWidget(0, 5)
        t.setHorizontalHeaderLabels(["TIME (local)", "SOURCE", "EVENT", "ZONE", "RAW VALUE"])
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        for c, w in enumerate((160, 110, 260, 70)):
            t.setColumnWidth(c, w)
        t.horizontalHeader().setStretchLastSection(True)
        self.table = t
        root.addWidget(t, stretch=1)
        self.data = None
        self.set_result(None)

    def set_result(self, result):
        if not result:
            self.data = {"events": [], "anomalies": [], "span": None}
        else:
            try:
                self.data = result.get("timeline") or build_timeline(result)
            except Exception as e:
                self.data = {"events": [], "anomalies": [], "span": None, "error": str(e)}
        ev, an = self.data["events"], self.data["anomalies"]
        flagged = {lbl for a in an if a["severity"] == "WARN" for lbl in a["events"]}
        if result is None:
            self.lbl_summary.setText("&nbsp; —&nbsp; no file analyzed")
        else:
            head = (f"<b>{len(ev)}</b> timestamps"
                    + (f" · {self.data['span'][0][:10]} → {self.data['span'][1][:10]}" if self.data.get("span") else ""))
            if an:
                items = "".join(
                    f"<div style='color:{T['crit'] if a['severity'] == 'WARN' else T['text_dim']}'>"
                    f"{'⚠' if a['severity'] == 'WARN' else 'ℹ'} {_esc(a['desc'])}</div>" for a in an)
                self.lbl_summary.setText(f"{head} · <b style='color:{T['warn']}'>{len(an)} contradiction(s)</b>{items}")
            else:
                self.lbl_summary.setText(f"{head} · <span style='color:{T['ok']}'>no contradictions found</span>")
        self.axis.set_events(ev, flagged)
        self.table.setRowCount(len(ev))
        for r, e in enumerate(ev):
            vals = [e["ts"], e["source"], e["label"], "known" if e["tz_known"] else "local?", e["raw"]]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if e["label"] in flagged:
                    it.setForeground(QColor(T["crit"]))
                elif c == 1:
                    it.setForeground(QColor(SOURCE_COLOR.get(e["source"], T["text"])))
                self.table.setItem(r, c, it)


def _esc(s):
    import html
    return html.escape(str(s))
