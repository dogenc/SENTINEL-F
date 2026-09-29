"""
╔══════════════════════════════════════════════════════════════╗
║   IOC GRAPH — welche Dateien teilen sich Infrastruktur?       ║
╚══════════════════════════════════════════════════════════════╝

Kreise = Dateien (Farbe = Risiko), Rauten = IOCs (Farbe = Typ), gestrichelte
Linien = Ähnlichkeit (TLSH/Imphash/Rich). Links: erkannte Cluster (mögliche
Kampagnen). Mausrad zoomt, Ziehen verschiebt, Doppelklick öffnet eine Datei.
"""
from PyQt6.QtCore import Qt, pyqtSignal, QPointF, QRectF
from PyQt6.QtGui import QColor, QPen, QBrush, QPainter, QPolygonF, QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QCheckBox,
    QListWidget, QListWidgetItem, QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsPolygonItem, QGraphicsLineItem, QGraphicsSimpleTextItem, QFrame
)

from PyQt6.QtWidgets import QFileDialog, QMessageBox

from config.settings import T, SCORE_LEVELS, FONT_MONO, REPORT_DIR, APP_CODENAME
from .report_dialog import safe_name
from core.utils import LOG
from core.iocgraph import graph_from_db, layout

LEVEL_COLOR = {lab: T.get(key, T["text"]) for _, lab, key in SCORE_LEVELS}
IOC_COLOR = {"domain": T["cyan"], "ipv4": T["warn"], "email": "#ff8ad8", "onion": "#b48cff",
             "btc": "#ffd84d", "xmr": "#ffd84d", "unc_path": "#5aa0ff"}
IOC_LABEL = {"domain": "domain", "ipv4": "IP", "email": "e-mail", "onion": "Tor", "btc": "BTC wallet",
             "xmr": "XMR wallet", "unc_path": "UNC path"}
SCALE = 420


class _FileNode(QGraphicsEllipseItem):
    def __init__(self, view, sha, info, r=13):
        super().__init__(-r, -r, 2 * r, 2 * r)
        self.view, self.sha, self.info = view, sha, info
        col = QColor(LEVEL_COLOR.get(info.get("level"), T["text_dim"]))
        self.setBrush(QBrush(col))
        self.setPen(QPen(QColor(T["bg"]), 2))
        self.setZValue(3)
        self.setToolTip(f"{info.get('name')}\n{info.get('level')} {info.get('score')}/100\n"
                        f"case: {info.get('case_name') or '—'}\nSHA-256 {info.get('sha256')}\n"
                        "double-click: open analysis")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mouseDoubleClickEvent(self, e):
        self.view.openRequested.emit(int(self.info["id"]))


class _IocNode(QGraphicsPolygonItem):
    def __init__(self, ioc, r=8):
        poly = QPolygonF([QPointF(0, -r), QPointF(r, 0), QPointF(0, r), QPointF(-r, 0)])
        super().__init__(poly)
        self.ioc = ioc
        col = QColor(IOC_COLOR.get(ioc["type"], T["text"]))
        self.setBrush(QBrush(QColor(T["bg"])))
        self.setPen(QPen(col, 2))
        self.setZValue(2)
        self.setToolTip(f"{IOC_LABEL.get(ioc['type'], ioc['type'])}: {ioc['value']}\n"
                        f"shared by {len(ioc['files'])} files")


class _View(QGraphicsView):
    def __init__(self, scene):
        super().__init__(scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setBackgroundBrush(QBrush(QColor(T["bg"])))
        self.setStyleSheet(f"border:1px solid {T['border']};")

    def wheelEvent(self, e):
        f = 1.15 if e.angleDelta().y() > 0 else 1 / 1.15
        self.scale(f, f)


class GraphView(QWidget):
    openRequested = pyqtSignal(int)

    def __init__(self, parent=None, history=None):
        super().__init__(parent)
        self.history = history
        self.graph = None
        self._file_items, self._ioc_items, self._edges = {}, {}, []
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)
        top = QHBoxLayout()
        title = QLabel("▸  IOC GRAPH  ·  SHARED INFRASTRUCTURE")
        title.setObjectName("SectionHeader")
        top.addWidget(title)
        top.addStretch(1)
        lc = QLabel("SCOPE")
        lc.setObjectName("CardTitle")
        top.addWidget(lc)
        self.cmb_scope = QComboBox()
        self.cmb_scope.setMinimumWidth(240)
        top.addWidget(self.cmb_scope)
        self.chk_similar = QCheckBox("Similarity links")
        self.chk_similar.setChecked(True)
        top.addWidget(self.chk_similar)
        self.btn_rule = QPushButton("🧬  YARA RULE")
        self.btn_rule.setObjectName("NavBtn")
        self.btn_rule.setToolTip("Generate a YARA rule from the selected cluster")
        self.btn_rule.clicked.connect(lambda: self.generate_rule())
        self.btn_rule.setEnabled(False)
        top.addWidget(self.btn_rule)
        self.btn_export = QPushButton("⇪  EXPORT IOCs")
        self.btn_export.setObjectName("NavBtn")
        self.btn_export.setToolTip("STIX 2.1 / MISP / CSV – selected cluster, otherwise the whole scope")
        self.btn_export.clicked.connect(lambda: self.export_iocs())
        top.addWidget(self.btn_export)
        self.btn_build = QPushButton("▶  BUILD GRAPH")
        self.btn_build.setObjectName("PrimaryBtn")
        self.btn_build.clicked.connect(self.rebuild)
        top.addWidget(self.btn_build)
        root.addLayout(top)

        body = QHBoxLayout()
        left = QFrame()
        left.setObjectName("Card")
        left.setFixedWidth(330)
        ll = QVBoxLayout(left)
        ll.setContentsMargins(10, 10, 10, 10)
        lbl = QLabel("CLUSTERS  ·  possible campaigns")
        lbl.setObjectName("CardTitle")
        ll.addWidget(lbl)
        self.lst_clusters = QListWidget()
        self.lst_clusters.currentRowChanged.connect(self._highlight_cluster)
        ll.addWidget(self.lst_clusters, stretch=2)
        lbl2 = QLabel("SHARED IOCs")
        lbl2.setObjectName("CardTitle")
        ll.addWidget(lbl2)
        self.lst_iocs = QListWidget()
        ll.addWidget(self.lst_iocs, stretch=3)
        body.addWidget(left)

        right = QVBoxLayout()
        self.scene = QGraphicsScene()
        self.canvas = _View(self.scene)
        right.addWidget(self.canvas, stretch=1)
        legend = " &nbsp; ".join(f"<span style='color:{c}'>◆</span> {IOC_LABEL[t]}"
                                 for t, c in IOC_COLOR.items() if t != "xmr")
        self.lbl_legend = QLabel(f"● file (colour = risk) &nbsp; {legend} &nbsp; ┅ similar code")
        self.lbl_legend.setStyleSheet(f"color:{T['text_mute']}; font-size:8pt;")
        right.addWidget(self.lbl_legend)
        body.addLayout(right, stretch=1)
        root.addLayout(body, stretch=1)
        self.reload_scopes()

    # ── Daten ─────────────────────────────────────────────────────────
    def reload_scopes(self):
        keep = self.cmb_scope.currentData() if self.cmb_scope.count() else None
        self.cmb_scope.clear()
        self.cmb_scope.addItem("◇  ALL ANALYSES", None)
        if self.history:
            for c in self.history.db.list_cases():
                self.cmb_scope.addItem(f"▣  {c['name']}", c["id"])
        i = self.cmb_scope.findData(keep)
        self.cmb_scope.setCurrentIndex(max(i, 0))

    def rebuild(self):
        if not self.history:
            return
        try:
            self.graph = graph_from_db(self.history.db, case_id=self.cmb_scope.currentData(),
                                       include_similar=self.chk_similar.isChecked())
        except Exception as e:
            LOG.log(f"IOC graph failed: {e}", "ERR")
            return
        self._render()
        g = self.graph
        LOG.log(f"IOC graph: {len(g['files'])} linked files · {len(g['iocs'])} shared IOCs · "
                f"{len(g['clusters'])} cluster(s)", "INFO")

    def _render(self):
        g = self.graph
        self.scene.clear()
        self._file_items, self._ioc_items, self._edges = {}, {}, []
        self.lst_clusters.clear()
        self.lst_iocs.clear()
        if not g["files"]:
            t = self.scene.addText("No files share IOCs or code yet.\n"
                                   "Analyse more files (e.g. a batch scan) and rebuild.")
            t.setDefaultTextColor(QColor(T["text_mute"]))
            return
        pos = layout(g)
        p = lambda k: QPointF(pos[k][0] * SCALE, pos[k][1] * SCALE)
        for i in g["iocs"]:
            for s in i["files"]:
                line = QGraphicsLineItem(p(f"file:{s}").x(), p(f"file:{s}").y(), p(i["key"]).x(), p(i["key"]).y())
                line.setPen(QPen(QColor(T["border_hot"]), 1.2))
                line.setZValue(1)
                self.scene.addItem(line)
                self._edges.append((line, {s}, i["key"]))
        for a, b, reason in g["similar"]:
            pa, pb = p(f"file:{a}"), p(f"file:{b}")
            line = QGraphicsLineItem(pa.x(), pa.y(), pb.x(), pb.y())
            pen = QPen(QColor(T["accent"]), 1.6, Qt.PenStyle.DashLine)
            line.setPen(pen)
            line.setToolTip(f"similar code: {reason}")
            line.setZValue(1)
            self.scene.addItem(line)
            self._edges.append((line, {a, b}, None))
        font = QFont(FONT_MONO, 8)
        for i in g["iocs"]:
            node = _IocNode(i)
            node.setPos(p(i["key"]))
            self.scene.addItem(node)
            lab = QGraphicsSimpleTextItem(i["value"][:28], node)
            lab.setFont(font)
            lab.setBrush(QBrush(QColor(IOC_COLOR.get(i["type"], T["text"]))))
            lab.setPos(10, -6)
            lab.setFlag(lab.GraphicsItemFlag.ItemIgnoresTransformations)   # bei jedem Zoom lesbar
            self._ioc_items[i["key"]] = node
            it = QListWidgetItem(f"{IOC_LABEL.get(i['type'], i['type']):<9} {i['value']}  ·  {len(i['files'])} files")
            it.setForeground(QColor(IOC_COLOR.get(i["type"], T["text"])))
            self.lst_iocs.addItem(it)
        for sha, info in g["files"].items():
            node = _FileNode(self, sha, info)
            node.setPos(p(f"file:{sha}"))
            self.scene.addItem(node)
            lab = QGraphicsSimpleTextItem(info.get("name", "")[:26], node)
            lab.setFont(font)
            lab.setBrush(QBrush(QColor(T["text_hot"])))
            lab.setPos(15, 2)
            lab.setFlag(lab.GraphicsItemFlag.ItemIgnoresTransformations)
            self._file_items[sha] = node
        for c in g["clusters"]:
            names = ", ".join(g["files"][s]["name"] for s in c["files"][:3])
            it = QListWidgetItem(f"{c['name']} · {len(c['files'])} files · {len(c['iocs'])} IOCs · "
                                 f"max {c['max_score']}\n   {names}{' …' if len(c['files']) > 3 else ''}")
            it.setForeground(QColor(T["crit"] if c["max_score"] >= 60 else T["text"]))
            self.lst_clusters.addItem(it)
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-80, -60, 160, 60))
        self.canvas.resetTransform()
        self.canvas.fitInView(self.scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def _selected_cluster(self):
        row = self.lst_clusters.currentRow()
        if self.graph and 0 <= row < len(self.graph["clusters"]):
            return self.graph["clusters"][row]
        return None

    def generate_rule(self):
        from core import intel
        from .intel_dialog import RuleDialog
        c = self._selected_cluster()
        if not c:
            return None
        rule = intel.cluster_rule(self.history.db, self.graph, c)
        if not rule:
            QMessageBox.information(self, "YARA rule", "This cluster shares no IOC or imphash that a rule "
                                                        "could be built on (it is linked by fuzzy hash only).")
            return None
        dlg = RuleDialog(self, self.history.db, rule)
        dlg.exec()
        return dlg

    def export_iocs(self, path=None):
        from core import intel
        c = self._selected_cluster()
        scope = c["name"] if c else self.cmb_scope.currentText().strip("◇▣ ")
        title = f"{APP_CODENAME} · {scope}"
        if path is None:
            path, _ = QFileDialog.getSaveFileName(
                self, "Export IOCs", str(REPORT_DIR / f"iocs_{safe_name(scope)}.stix.json"),
                "STIX 2.1 (*.stix.json);;MISP event (*.misp.json);;CSV (*.csv)")
            if not path:
                return None
        data = intel.collect(self.history.db, case_id=self.cmb_scope.currentData(),
                             graph=self.graph if c else None, cluster=c)
        intel.write_export(data, path, title)
        LOG.log(f"IOC export: {len(data['iocs'])} IOCs, {len(data['files'])} files → {path}", "OK")
        return path

    def _highlight_cluster(self, row):
        self.btn_rule.setEnabled(row >= 0)
        g = self.graph
        if not g or row < 0 or row >= len(g["clusters"]):
            members, keys = None, None
        else:
            c = g["clusters"][row]
            members, keys = set(c["files"]), set(c["iocs"])
        for sha, it in self._file_items.items():
            it.setOpacity(1.0 if members is None or sha in members else 0.15)
        for key, it in self._ioc_items.items():
            it.setOpacity(1.0 if keys is None or key in keys else 0.15)
        for line, shas, key in self._edges:
            on = members is None or (shas <= members if key is None else (key in keys))
            line.setOpacity(1.0 if on else 0.08)
        if members:
            rect = QRectF()
            for sha in members:
                it = self._file_items[sha]
                rect = rect.united(it.sceneBoundingRect())
            self.canvas.fitInView(rect.adjusted(-120, -80, 200, 80), Qt.AspectRatioMode.KeepAspectRatio)
