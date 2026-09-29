"""
╔══════════════════════════════════════════════════════════════╗
║          REUSABLE GUI COMPONENTS                             ║
║     LiveClock · ScoreGauge · StatCard · MiniBar · Severity   ║
╚══════════════════════════════════════════════════════════════╝
"""
import datetime
import math
import os

from PyQt6.QtCore import Qt, QTimer, QRectF, QPointF, pyqtSignal
from PyQt6.QtGui import (
    QPainter, QColor, QPen, QFont
)
from PyQt6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout, QFrame, QSizePolicy
)

from config.settings import T, FONT_MONO, FONT_MONO_ALT


# ═══════════════════════════════════════════════════════════════════════════════
# Live Clock — UTC + Local
# ═══════════════════════════════════════════════════════════════════════════════
class LiveClock(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(54)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 6, 12, 6)
        root.setSpacing(0)

        self.lbl_title = QLabel("MISSION CLOCK")
        self.lbl_title.setObjectName("CardTitle")

        row = QHBoxLayout()
        row.setSpacing(18)

        self.lbl_utc = QLabel("00:00:00 UTC")
        self.lbl_utc.setStyleSheet(
            f"color:{T['accent']}; font-size:16pt; font-weight:bold; letter-spacing:2px;"
            f"font-family:'{FONT_MONO}','{FONT_MONO_ALT}',monospace;"
        )

        self.lbl_local = QLabel("00:00:00")
        self.lbl_local.setStyleSheet(
            f"color:{T['cyan']}; font-size:12pt; letter-spacing:2px;"
            f"font-family:'{FONT_MONO}','{FONT_MONO_ALT}',monospace;"
        )

        row.addWidget(self.lbl_utc)
        row.addStretch(1)
        row.addWidget(self.lbl_local)

        self.lbl_date = QLabel("")
        self.lbl_date.setStyleSheet(
            f"color:{T['text_mute']}; font-size:8pt; letter-spacing:2px;"
        )

        root.addWidget(self.lbl_title)
        root.addLayout(row)
        root.addWidget(self.lbl_date)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        self._tick()

    def _tick(self):
        now_utc   = datetime.datetime.utcnow()
        now_local = datetime.datetime.now()
        self.lbl_utc.setText(now_utc.strftime("%H:%M:%S  UTC"))
        self.lbl_local.setText(now_local.strftime("%H:%M:%S  LOCAL"))
        self.lbl_date.setText(now_utc.strftime("%Y-%m-%d · DAY %j · WEEK %V · ZULU"))


# ═══════════════════════════════════════════════════════════════════════════════
# Score Gauge — 0-100 circular meter with color-coded risk
# ═══════════════════════════════════════════════════════════════════════════════
class ScoreGauge(QWidget):
    """Circular 0-100 gauge with risk-level label."""
    def __init__(self, parent=None, size=230):
        super().__init__(parent)
        self.setMinimumSize(size, size)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        self._score = 0
        self._display = 0.0    # animated value
        self._level = "—"
        self._color = T['text_mute']

        self._anim = QTimer(self)
        self._anim.timeout.connect(self._step)
        self._anim.start(20)

    def set_score(self, score, level, color):
        self._score = max(0, min(100, int(score)))
        self._level = (level or "—").upper()
        self._color = color or T['text_mute']

    def reset(self):
        self._score = 0
        self._display = 0.0
        self._level = "—"
        self._color = T['text_mute']
        self.update()

    def _step(self):
        diff = self._score - self._display
        if abs(diff) < 0.3:
            if self._display != self._score:
                self._display = float(self._score)
                self.update()
            return
        self._display += diff * 0.10
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        side = min(w, h) - 16
        rect = QRectF((w - side) / 2, (h - side) / 2, side, side)

        # Background ring
        p.setPen(QPen(QColor(T['border']), 10))
        p.drawArc(rect, 0, 360 * 16)

        # Grid ticks
        p.setPen(QPen(QColor(T['border_hot']), 1))
        cx, cy = rect.center().x(), rect.center().y()
        r_outer = side / 2
        for i in range(0, 101, 10):
            ang = math.radians(-90 + i * 3.6)
            x1 = cx + (r_outer - 14) * math.cos(ang)
            y1 = cy + (r_outer - 14) * math.sin(ang)
            x2 = cx + (r_outer - 6)  * math.cos(ang)
            y2 = cy + (r_outer - 6)  * math.sin(ang)
            p.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        # Active arc
        pct = self._display / 100.0
        span = int(-360 * 16 * pct)
        pen = QPen(QColor(self._color), 10, Qt.PenStyle.SolidLine,
                   Qt.PenCapStyle.FlatCap)
        p.setPen(pen)
        p.drawArc(rect, 90 * 16, span)

        # Glow effect — softer outer arc
        glow = QColor(self._color)
        glow.setAlpha(55)
        p.setPen(QPen(glow, 18, Qt.PenStyle.SolidLine, Qt.PenCapStyle.FlatCap))
        p.drawArc(rect, 90 * 16, span)

        # Center value
        p.setPen(QPen(QColor(self._color)))
        f = QFont(FONT_MONO, 36, QFont.Weight.Bold)
        p.setFont(f)
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter,
                   f"{int(round(self._display))}")

        # "/100" suffix
        p.setPen(QPen(QColor(T['text_mute'])))
        p.setFont(QFont(FONT_MONO, 10))
        sub_rect = QRectF(rect.x(), rect.y() + rect.height() * 0.62,
                          rect.width(), 24)
        p.drawText(sub_rect, Qt.AlignmentFlag.AlignCenter, "/ 100")

        # Level label below
        p.setPen(QPen(QColor(self._color)))
        p.setFont(QFont(FONT_MONO, 10, QFont.Weight.Bold))
        lvl_rect = QRectF(rect.x(), rect.y() + rect.height() * 0.75,
                          rect.width(), 20)
        p.drawText(lvl_rect, Qt.AlignmentFlag.AlignCenter, self._level)

        # Top marker — "MANIPULATION INDEX"
        p.setPen(QPen(QColor(T['cyan'])))
        p.setFont(QFont(FONT_MONO, 7, QFont.Weight.Bold))
        title_rect = QRectF(rect.x(), rect.y() + 14, rect.width(), 14)
        p.drawText(title_rect, Qt.AlignmentFlag.AlignCenter, "MANIPULATION INDEX")

        p.end()


# ═══════════════════════════════════════════════════════════════════════════════
# Stat Card — small dashboard tile
# ═══════════════════════════════════════════════════════════════════════════════
class StatCard(QFrame):
    def __init__(self, title, value="—", sub="", color=None, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(92)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(4)

        self.lbl_title = QLabel(title.upper())
        self.lbl_title.setObjectName("CardTitle")

        self.lbl_value = QLabel(str(value))
        self.lbl_value.setObjectName("CardValue")
        if color:
            self.lbl_value.setStyleSheet(
                f"color:{color}; font-size:18pt; font-weight:bold;"
                f"font-family:'{FONT_MONO}','{FONT_MONO_ALT}',monospace;"
            )

        self.lbl_sub = QLabel(sub)
        self.lbl_sub.setObjectName("CardSub")

        lay.addWidget(self.lbl_title)
        lay.addWidget(self.lbl_value)
        lay.addWidget(self.lbl_sub)

    def set_value(self, value, sub=None, color=None):
        self.lbl_value.setText(str(value))
        if sub is not None:
            self.lbl_sub.setText(sub)
        if color:
            self.lbl_value.setStyleSheet(
                f"color:{color}; font-size:18pt; font-weight:bold;"
                f"font-family:'{FONT_MONO}','{FONT_MONO_ALT}',monospace;"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# Severity Pill
# ═══════════════════════════════════════════════════════════════════════════════
class SeverityPill(QLabel):
    def __init__(self, severity="INFO", parent=None):
        super().__init__(severity, parent)
        self.set_severity(severity)

    def set_severity(self, severity):
        severity = (severity or "INFO").upper()
        self.setText(severity)
        mapping = {
            "INFO": T['info'],
            "OK":   T['ok'],
            "WARN": T['warn'],
            "ERR":  T['err'],
            "CRIT": T['crit'],
        }
        c = mapping.get(severity, T['info'])
        self.setStyleSheet(
            f"background:{T['bg']}; color:{c}; border:1px solid {c};"
            f"padding:1px 8px; font-size:8pt; font-weight:bold; letter-spacing:1.5px;"
            f"font-family:'{FONT_MONO}',monospace;"
        )
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMaximumWidth(70)


# ═══════════════════════════════════════════════════════════════════════════════
# Mini horizontal bar — for sub-signals in score breakdown
# ═══════════════════════════════════════════════════════════════════════════════
class MiniBar(QWidget):
    def __init__(self, value=0.0, maximum=20.0, color=T['accent'], parent=None):
        super().__init__(parent)
        self._val = value
        self._max = maximum
        self._col = color
        self.setFixedHeight(6)
        self.setMinimumWidth(60)

    def set_value(self, value, maximum=None, color=None):
        self._val = value
        if maximum is not None:
            self._max = maximum
        if color is not None:
            self._col = color
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(T['bg']))
        if self._max <= 0:
            return
        pct = max(0.0, min(1.0, self._val / self._max))
        w = int(self.width() * pct)
        p.fillRect(0, 0, w, self.height(), QColor(self._col))
        # border
        p.setPen(QPen(QColor(T['border']), 1))
        p.drawRect(0, 0, self.width() - 1, self.height() - 1)


# ═══════════════════════════════════════════════════════════════════════════════
# Drop Zone — accepts file drag & drop
# ═══════════════════════════════════════════════════════════════════════════════
class DropZone(QFrame):
    fileDropped  = pyqtSignal(str)
    pathsDropped = pyqtSignal(list)      # Ordner oder mehrere Dateien → Stapelanalyse

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setAcceptDrops(True)
        self.setMinimumHeight(110)
        self._hover = False
        self._build()

    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(4)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

        icon = QLabel("⧉")
        icon.setStyleSheet(
            f"color:{T['accent']}; font-size:28pt; font-weight:bold;"
        )
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl = QLabel("DROP  ·  DOUBLE-CLICK")   # passt in die schmale Seitenleiste
        lbl.setStyleSheet(
            f"color:{T['text_dim']}; font-size:9pt; letter-spacing:1px; font-weight:bold;"
            f"font-family:'{FONT_MONO}',monospace;"
        )
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        sub = QLabel("FILE · FOLDER · SANDBOXED")
        sub.setStyleSheet(
            f"color:{T['text_mute']}; font-size:7pt; letter-spacing:1.5px;"
        )
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lay.addWidget(icon)
        lay.addWidget(lbl)
        lay.addWidget(sub)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._hover = True
            self.setStyleSheet(
                f"QFrame#Card {{ border: 1px solid {T['accent']}; "
                f"background: {T['card_hover']}; }}"
            )

    def dragLeaveEvent(self, _):
        self._hover = False
        self.setStyleSheet("")

    def dropEvent(self, e):
        self._hover = False
        self.setStyleSheet("")
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.toLocalFile()]
        if len(paths) == 1 and not os.path.isdir(paths[0]):
            self.fileDropped.emit(paths[0])
        elif paths:
            self.pathsDropped.emit(paths)

    def mouseDoubleClickEvent(self, _):
        from PyQt6.QtWidgets import QFileDialog
        path, _f = QFileDialog.getOpenFileName(
            self, "Select File for Forensic Analysis", "", "All Files (*.*)"
        )
        if path:
            self.fileDropped.emit(path)
