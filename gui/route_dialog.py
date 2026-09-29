"""Bewegungsprofil eines Falls: 2D-Karte (ohne Schlüssel/Internet), Etappen, Unmöglichkeiten."""
import math

from PyQt6.QtCore import Qt, QPointF, pyqtSignal
from PyQt6.QtGui import QColor, QPen, QBrush, QPainter, QFont
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QGraphicsView, QGraphicsScene, QGraphicsSimpleTextItem, QAbstractItemView, QSplitter
)

from config.settings import T, FONT_MONO

FLAG_COLOR = {"impossible": T["crit"], "flight": T["warn"], None: T["cyan"]}


class RouteDialog(QDialog):
    showOnGlobe = pyqtSignal(dict)
    openRequested = pyqtSignal(int)

    def __init__(self, parent, route, title):
        super().__init__(parent)
        self.route = route
        self.setWindowTitle(f"Movement profile · {title}")
        self.resize(1200, 720)
        self.setStyleSheet(f"QDialog{{background:{T['bg_alt']};}} QLabel{{color:{T['text']};}}")
        lay = QVBoxLayout(self)
        self.lbl = QLabel()
        self.lbl.setWordWrap(True)
        self.lbl.setTextFormat(Qt.TextFormat.RichText)
        self.lbl.setStyleSheet(f"padding:8px; background:{T['card']}; border:1px solid {T['border']};")
        lay.addWidget(self.lbl)
        split = QSplitter()
        self.scene = QGraphicsScene()
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setBackgroundBrush(QBrush(QColor(T["bg"])))
        split.addWidget(self.view)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["FROM → TO", "DISTANCE", "TIME", "SPEED", "CHECK"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        for c, w in enumerate((250, 90, 70, 90)):
            self.table.setColumnWidth(c, w)
        split.addWidget(self.table)
        split.setSizes([640, 620])
        lay.addWidget(split, stretch=1)
        row = QHBoxLayout()
        row.addStretch(1)
        self.btn_globe = QPushButton("🌍  SHOW ON 3-D GLOBE")
        self.btn_globe.setObjectName("PrimaryBtn")
        self.btn_globe.clicked.connect(lambda: (self.showOnGlobe.emit(self.route), self.accept()))
        row.addWidget(self.btn_globe)
        close = QPushButton("CLOSE")
        close.clicked.connect(self.reject)
        row.addWidget(close)
        lay.addLayout(row)
        self._render()

    def _render(self):
        r = self.route
        pts, legs = r["points"], r["legs"]
        txt = (f"<b>{len(pts)}</b> geotagged photo(s) in time order · {r['total_km']:,.1f} km total"
               + (f" · {len(r['undated'])} without capture time (not in route)" if r["undated"] else ""))
        for a in r["anomalies"]:
            col = T["crit"] if a["severity"] == "WARN" else T["warn"]
            txt += f"<br><span style='color:{col}'>{'⚠' if a['severity'] == 'WARN' else 'ℹ'} {_esc(a['desc'])}</span>"
        if pts and not r["anomalies"]:
            txt += f"<br><span style='color:{T['ok']}'>All legs physically plausible.</span>"
        self.lbl.setText(txt)
        self.btn_globe.setEnabled(bool(pts))
        self.table.setRowCount(len(legs))
        for i, l in enumerate(legs):
            vals = [f"{l['from']} → {l['to']}", f"{l['km']:,.1f} km", _dur(l["hours"]),
                    "∞" if l["speed_kmh"] is None else f"{l['speed_kmh']:,.0f} km/h",
                    {"impossible": "IMPOSSIBLE", "flight": "plane only"}.get(l["flag"], "ok")]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 4 or l["flag"] == "impossible":
                    it.setForeground(QColor(FLAG_COLOR.get(l["flag"], T["ok"]) if l["flag"] else T["ok"]))
                self.table.setItem(i, c, it)
        self._draw(pts, legs)

    def _draw(self, pts, legs):
        self.scene.clear()
        if not pts:
            t = self.scene.addText("No geotagged photos with capture time in this scope.")
            t.setDefaultTextColor(QColor(T["text_mute"]))
            return
        lat0 = sum(p["lat"] for p in pts) / len(pts)
        kx = math.cos(math.radians(lat0))
        xs = [p["lon"] * kx for p in pts]
        ys = [-p["lat"] for p in pts]
        span = max(max(xs) - min(xs), max(ys) - min(ys), 1e-4)
        sc = 600 / span
        pos = [QPointF((x - min(xs)) * sc, (y - min(ys)) * sc) for x, y in zip(xs, ys)]
        flags = {l["to_id"]: l["flag"] for l in legs}
        z = {"impossible": 3, "flight": 2}
        for i in range(1, len(pos)):
            f = flags.get(pts[i]["id"])
            pen = QPen(QColor(FLAG_COLOR.get(f, T["cyan"])), 4 if f == "impossible" else 3 if f else 2)
            if f == "flight":
                pen.setStyle(Qt.PenStyle.DashLine)
            line = self.scene.addLine(pos[i - 1].x(), pos[i - 1].y(), pos[i].x(), pos[i].y(), pen)
            line.setZValue(z.get(f, 1))                    # auffällige Etappen liegen oben
        # nahe beieinander liegende Punkte teilen sich eine Beschriftung
        groups = []
        for i, q in enumerate(pos):
            for g in groups:
                if abs(pos[g[0]].x() - q.x()) < 40 and abs(pos[g[0]].y() - q.y()) < 40:
                    g.append(i)
                    break
            else:
                groups.append([i])
        font = QFont(FONT_MONO, 8)
        for i, (p, q) in enumerate(zip(pts, pos)):
            dot = self.scene.addEllipse(q.x() - 6, q.y() - 6, 12, 12, QPen(QColor(T["bg"]), 2),
                                        QBrush(QColor(T["accent"])))
            dot.setZValue(5)
            dot.setToolTip(f"{i + 1} · {p['name']}\n{p['ts']}\n{p['lat']:.5f}, {p['lon']:.5f}")
        for g in groups:
            q = pos[g[0]]
            nums = ", ".join(str(i + 1) for i in g)
            names = pts[g[0]]["name"][:20] + (f" +{len(g) - 1}" if len(g) > 1 else "")
            when = pts[g[0]]["ts"][:16] + (f" … {pts[g[-1]]['ts'][11:16]}" if len(g) > 1 else "")
            lab = QGraphicsSimpleTextItem(f"{nums} · {names}\n    {when}")
            lab.setFont(font)
            lab.setBrush(QBrush(QColor(T["text_hot"])))
            lab.setPos(q.x() + 9, q.y() - 6)
            lab.setZValue(6)
            lab.setFlag(lab.GraphicsItemFlag.ItemIgnoresTransformations)
            self.scene.addItem(lab)
        # Maßstab
        km_per_px = 111.32 / sc
        nice = next((v for v in (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000) if v / km_per_px >= 80), 5000)
        bx, by = 0, max(q.y() for q in pos) + 40
        self.scene.addLine(bx, by, bx + nice / km_per_px, by, QPen(QColor(T["text_dim"]), 2))
        sb = self.scene.addSimpleText(f"{nice} km", font)
        sb.setBrush(QBrush(QColor(T["text_dim"])))
        sb.setPos(bx, by + 4)
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-40, -40, 160, 40))
        self.view.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def showEvent(self, e):
        super().showEvent(e)
        self.view.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)


def _dur(h):
    return f"{h * 60:.0f} min" if h < 1 else f"{h:.1f} h"


def _esc(s):
    import html
    return html.escape(str(s))
