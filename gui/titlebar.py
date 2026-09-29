"""
╔══════════════════════════════════════════════════════════════╗
║          CUSTOM FRAMELESS TITLE BAR                          ║
╚══════════════════════════════════════════════════════════════╝
"""
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPainter, QColor, QPen
from PyQt6.QtWidgets import (
    QWidget, QLabel, QHBoxLayout, QPushButton
)

from config.settings import (
    T, APP_NAME, APP_VERSION, APP_CODENAME, APP_BUILD, FONT_MONO
)


class BrandGlyph(QWidget):
    """Animated scanning reticle — pure SVG/QPainter."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(26, 26)
        self._angle = 0
        self._t = QTimer(self)
        self._t.timeout.connect(self._tick)
        self._t.start(40)

    def _tick(self):
        self._angle = (self._angle + 4) % 360
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        r = min(w, h) / 2 - 3

        # outer ring
        p.setPen(QPen(QColor(T['accent_dim']), 1))
        p.drawEllipse(int(cx - r), int(cy - r), int(r * 2), int(r * 2))

        # inner ring
        p.setPen(QPen(QColor(T['accent_dim']), 1))
        p.drawEllipse(int(cx - r * 0.55), int(cy - r * 0.55),
                      int(r * 1.1), int(r * 1.1))

        # crosshair
        p.setPen(QPen(QColor(T['accent']), 1))
        p.drawLine(int(cx - r), int(cy), int(cx - r * 0.6), int(cy))
        p.drawLine(int(cx + r * 0.6), int(cy), int(cx + r), int(cy))
        p.drawLine(int(cx), int(cy - r), int(cx), int(cy - r * 0.6))
        p.drawLine(int(cx), int(cy + r * 0.6), int(cx), int(cy + r))

        # rotating dot
        import math
        rad = math.radians(self._angle)
        px = cx + r * 0.78 * math.cos(rad)
        py = cy + r * 0.78 * math.sin(rad)
        p.setBrush(QColor(T['accent']))
        p.setPen(QPen(QColor(T['accent']), 0))
        p.drawEllipse(int(px - 2), int(py - 2), 4, 4)

        # core dot
        p.setBrush(QColor(T['cyan']))
        p.drawEllipse(int(cx - 2), int(cy - 2), 4, 4)
        p.end()


class TitleBar(QWidget):
    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.setObjectName("TitleBar")
        self.setFixedHeight(40)
        self._win = window
        self._drag_pos = None

        lay = QHBoxLayout(self)
        lay.setContentsMargins(6, 0, 0, 0)
        lay.setSpacing(0)

        # Brand glyph
        self._glyph = BrandGlyph(self)
        lay.addSpacing(8)
        lay.addWidget(self._glyph)

        # App name
        self.lbl_title = QLabel(APP_NAME.upper())
        self.lbl_title.setObjectName("TitleText")
        lay.addWidget(self.lbl_title)

        # Version/codename tag
        self.lbl_ver = QLabel(f"v{APP_VERSION}  ·  {APP_CODENAME}  ·  BUILD {APP_BUILD}")
        self.lbl_ver.setObjectName("TitleVersion")
        lay.addWidget(self.lbl_ver)

        lay.addStretch(1)

        # Classification banner (purely aesthetic)
        self.lbl_class = QLabel("◈  CLASSIFIED · OPERATOR ONLY  ◈")
        self.lbl_class.setStyleSheet(
            f"color:{T['accent']}; font-size:8pt; letter-spacing:3px; font-weight:bold;"
            f"font-family:'{FONT_MONO}',monospace;"
            f"border:1px solid {T['accent_dim']}; padding:2px 10px;"
        )
        lay.addWidget(self.lbl_class)
        lay.addSpacing(12)

        # Min/Max/Close
        self.btn_min = QPushButton("—", self)
        self.btn_max = QPushButton("▢", self)
        self.btn_cls = QPushButton("✕", self)
        for b in (self.btn_min, self.btn_max, self.btn_cls):
            b.setObjectName("WinBtn")
            b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_cls.setObjectName("WinBtnClose")
        self.btn_cls.setStyleSheet("")  # inherits via objectName
        self.btn_min.clicked.connect(self._win.showMinimized)
        self.btn_max.clicked.connect(self._toggle_max)
        self.btn_cls.clicked.connect(self._win.close)
        lay.addWidget(self.btn_min)
        lay.addWidget(self.btn_max)
        lay.addWidget(self.btn_cls)

    def _toggle_max(self):
        if self._win.isMaximized():
            self._win.showNormal()
        else:
            self._win.showMaximized()

    # Drag-move the window
    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag_pos = e.globalPosition().toPoint() - self._win.frameGeometry().topLeft()

    def mouseMoveEvent(self, e):
        if self._drag_pos and (e.buttons() & Qt.MouseButton.LeftButton):
            if self._win.isMaximized():
                self._win.showNormal()
            self._win.move(e.globalPosition().toPoint() - self._drag_pos)

    def mouseReleaseEvent(self, e):
        self._drag_pos = None

    def mouseDoubleClickEvent(self, e):
        self._toggle_max()
