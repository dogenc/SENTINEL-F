"""
╔══════════════════════════════════════════════════════════════╗
║          SPLASH SCREEN                                       ║
╚══════════════════════════════════════════════════════════════╝
"""
import math
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QPainter, QColor, QPen, QFont, QLinearGradient
from PyQt6.QtWidgets import QWidget, QLabel, QVBoxLayout, QProgressBar

from config.settings import (
    T, APP_VERSION, APP_BUILD, FONT_MONO, FONT_MONO_ALT
)


class SplashScreen(QWidget):
    """Animated, frameless boot splash."""
    finishedLoading = pyqtSignal()

    BOOT_LINES = [
        ("CRYPTO CORE",            "initializing cryptographic digest pipeline"),
        ("MAGIC SIGNATURES",       "loading binary signature database"),
        ("IMAGE FORENSIC ENGINE",  "verifying PIL / numpy / piexif / scipy"),
        ("PDF FORENSIC ENGINE",    "verifying pikepdf / pdf2image / tesseract"),
        ("DOCUMENT FORENSIC ENGINE","verifying python-docx / openpyxl / oletools"),
        ("SCORE ENGINE",           "loading heuristic weight matrix"),
        ("SENTINEL GLOBE",         "initializing Cesium 3D geospatial layer"),
        ("OLLAMA BRIDGE",          "probing local AI endpoint 127.0.0.1:11434"),
        ("TELEMETRY",              "subscribing log channels"),
        ("INTERFACE",              "loading operator console"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.SplashScreen
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        self.setFixedSize(560, 360)
        self._step = 0
        self._angle = 0
        self._current_line = ""
        self._messages = []
        self._build()

        self._spin = QTimer(self)
        self._spin.timeout.connect(self._tick_spin)
        self._spin.start(50)

        self._advance = QTimer(self)
        self._advance.timeout.connect(self._tick_advance)
        self._advance.start(240)

    # ─── UI ──────────────────────────────────────────────────────────
    def _build(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(40, 30, 40, 22)
        lay.setSpacing(10)

        # Title
        title = QLabel("DGKN@Labs")
        title.setStyleSheet(
            f"color:{T['accent']}; font-size:14pt; font-weight:bold; letter-spacing:6px;"
            f"font-family:'{FONT_MONO}','{FONT_MONO_ALT}',monospace;"
        )
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(title)

        product = QLabel("FILE-FORENSIC")
        product.setStyleSheet(
            f"color:{T['cyan']}; font-size:20pt; font-weight:bold; letter-spacing:3px;"
            f"font-family:'{FONT_MONO}','{FONT_MONO_ALT}',monospace;"
        )
        product.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(product)

        codename = QLabel("▸  SENTINEL-F  ◂")
        codename.setStyleSheet(
            f"color:{T['accent']}; font-size:11pt; font-weight:bold; letter-spacing:8px;"
            f"font-family:'{FONT_MONO}','{FONT_MONO_ALT}',monospace;"
        )
        codename.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(codename)

        sub = QLabel(f"v{APP_VERSION}  ·  BUILD {APP_BUILD}  ·  OPERATOR-TIER")
        sub.setStyleSheet(
            f"color:{T['text_mute']}; font-size:9pt; letter-spacing:3px;"
        )
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(sub)

        lay.addStretch(1)

        # Current boot line
        self.lbl_line = QLabel("booting core…")
        self.lbl_line.setStyleSheet(
            f"color:{T['accent']}; font-size:9pt; letter-spacing:2px;"
            f"font-family:'{FONT_MONO}',monospace;"
        )
        self.lbl_line.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.lbl_line)

        # Progress bar
        self.bar = QProgressBar()
        self.bar.setMaximum(len(self.BOOT_LINES))
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(4)
        self.bar.setStyleSheet(
            f"QProgressBar {{ background:{T['bg']}; border:1px solid {T['border']}; }}"
            f"QProgressBar::chunk {{ background:{T['accent']}; }}"
        )
        lay.addWidget(self.bar)

        footer = QLabel("◈  CLASSIFIED  ·  OPERATOR ONLY  ·  DGKN@Labs 2026  ◈")
        footer.setStyleSheet(
            f"color:{T['text_mute']}; font-size:8pt; letter-spacing:3px;"
        )
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(footer)

    # ─── Animation ───────────────────────────────────────────────────
    def _tick_spin(self):
        self._angle = (self._angle + 6) % 360
        self.update()

    def _tick_advance(self):
        if self._step >= len(self.BOOT_LINES):
            self._spin.stop()
            self._advance.stop()
            self.finishedLoading.emit()
            return
        code, desc = self.BOOT_LINES[self._step]
        self.lbl_line.setText(f"▸  [{code}]  {desc}")
        self.bar.setValue(self._step + 1)
        self._step += 1

    # ─── Paint backdrop ──────────────────────────────────────────────
    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Base fill
        p.fillRect(self.rect(), QColor(T['bg']))

        # Top gradient strip
        grad = QLinearGradient(0, 0, 0, 4)
        grad.setColorAt(0, QColor(T['accent']))
        grad.setColorAt(1, QColor(T['accent_dim']))
        p.fillRect(0, 0, self.width(), 2, grad)
        p.fillRect(0, self.height()-2, self.width(), 2, QColor(T['accent_dim']))

        # Border
        p.setPen(QPen(QColor(T['border']), 1))
        p.drawRect(0, 0, self.width()-1, self.height()-1)

        # Subtle grid
        p.setPen(QPen(QColor(T['grid']), 1))
        for x in range(0, self.width(), 20):
            p.drawLine(x, 0, x, self.height())
        for y in range(0, self.height(), 20):
            p.drawLine(0, y, self.width(), y)

        # Rotating reticle right side
        cx, cy = self.width() - 55, 50
        r = 22
        p.setPen(QPen(QColor(T['accent_dim']), 1))
        p.drawEllipse(cx - r, cy - r, r * 2, r * 2)
        p.drawEllipse(cx - r//2, cy - r//2, r, r)
        ang = math.radians(self._angle)
        dot_x = cx + r * math.cos(ang)
        dot_y = cy + r * math.sin(ang)
        p.setBrush(QColor(T['accent']))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(int(dot_x - 3), int(dot_y - 3), 6, 6)

        # Left side code block
        p.setPen(QPen(QColor(T['text_mute']), 1))
        p.setFont(QFont(FONT_MONO, 7))
        codes = [
            "0x48 0x44 0x47 0x4B",
            "JWT.CSM ────── OK",
            "MAPTILER ───── OK",
            "OLLAMA ─── PROBE",
            f"BUILD {APP_BUILD}",
        ]
        for i, c in enumerate(codes):
            p.drawText(28, 40 + i * 12, c)

        p.end()
