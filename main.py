"""
╔══════════════════════════════════════════════════════════════╗
║          DGKN@Labs-FileForensic  ·  Entry Point              ║
║          v1.0.0  ·  SENTINEL-F  ·  2026                      ║
╚══════════════════════════════════════════════════════════════╝
"""
import sys
import os
from pathlib import Path

# Ensure project root on path when run as script or as frozen exe
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Sandbox-Worker-Modus: Analyse in isoliertem Prozess (core/sandbox.py).
# Muss VOR allen Qt-Imports stehen – der Worker braucht keine Oberfläche.
if len(sys.argv) > 1 and sys.argv[1] in ("--sentinel-worker", "--sentinel-selftest", "--sentinel-diff",
                                          "--sentinel-mailbox"):
    from engines.sandbox_worker import main as _worker_main
    sys.exit(_worker_main(sys.argv[1:]))

# Qt platform tweaks (Windows friendliness)
os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFontDatabase, QFont, QIcon
from PyQt6.QtWidgets import QApplication

from config.settings import APP_NAME, APP_VERSION, FONT_MONO, RESOURCE_DIR
from gui.styles       import qss_main
from gui.splash       import SplashScreen
from gui.main_window  import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("DGKN@Labs")
    icon = RESOURCE_DIR / "sentinel.ico"
    if icon.exists():
        app.setWindowIcon(QIcon(str(icon)))

    # Global stylesheet
    app.setStyleSheet(qss_main())

    # Default font — fall back gracefully if JetBrains Mono isn't installed
    available = set(QFontDatabase.families())
    if FONT_MONO in available:
        default = QFont(FONT_MONO, 10)
    elif "Consolas" in available:
        default = QFont("Consolas", 10)
    elif "Courier New" in available:
        default = QFont("Courier New", 10)
    else:
        default = QFont("monospace", 10)
    app.setFont(default)

    # Splash → Main
    splash = SplashScreen()
    # Center on screen
    try:
        screen = app.primaryScreen().availableGeometry()
        splash.move(
            (screen.width()  - splash.width())  // 2,
            (screen.height() - splash.height()) // 2,
        )
    except Exception:
        pass
    splash.show()

    main_window = {"win": None}

    def _launch():
        w = MainWindow()
        # center main window
        try:
            screen = app.primaryScreen().availableGeometry()
            w.move(
                (screen.width()  - w.width())  // 2,
                (screen.height() - w.height()) // 2,
            )
        except Exception:
            pass
        w.show()
        w.watch.autostart()          # Watch-Folder fortsetzen, falls beim Beenden aktiv
        main_window["win"] = w
        splash.close()
        # Pfade von der Kommandozeile / "Mit SENTINEL-F analysieren" im Explorer
        paths = [a for a in sys.argv[1:] if not a.startswith("-") and Path(a).exists()]
        if len(paths) == 1:
            QTimer.singleShot(200, lambda: w._load_file(paths[0]))
        elif paths:
            QTimer.singleShot(200, lambda: w._scan_paths(paths))

    splash.finishedLoading.connect(_launch)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
