"""
Erzeugt README-Screenshots der echten App (inkl. 3D-Globus via WebGL).

    python scripts/capture_screenshots.py [ausgabeordner]

Legt harmlose Demo-Dateien unter C:\\Users\\Public\\SENTINEL-Demo an (neutraler Pfad,
kein Benutzername im Bild), startet das Hauptfenster sichtbar, analysiert nacheinander
und fotografiert den Bildschirmbereich des Fensters (WebGL lässt sich nur so erfassen).
Das Fenster ist währenddessen „immer im Vordergrund“ – bitte nicht verdecken.
"""
import io
import os
import random
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEMO = Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "SENTINEL-Demo"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "screenshots"


def make_demo_files():
    import piexif
    from PIL import Image, ImageDraw, ImageFilter
    DEMO.mkdir(parents=True, exist_ok=True)
    rnd = random.Random(7)

    # 1) „Nachtaufnahme“ mit GPS (Brandenburger Tor) – rein synthetisch
    w, h = 1600, 1000
    img = Image.new("RGB", (w, h))
    d = ImageDraw.Draw(img)
    for y in range(h):
        t = y / h
        d.line([(0, y), (w, y)], fill=(int(8 + 30 * t), int(12 + 20 * t), int(40 + 50 * (1 - t))))
    for _ in range(260):
        x, y = rnd.randrange(w), rnd.randrange(int(h * 0.55))
        d.point((x, y), fill=(230, 230, 255))
    x = 0
    while x < w:
        bw, bh = rnd.randint(60, 160), rnd.randint(180, 620)
        d.rectangle([x, h - bh, x + bw, h], fill=(10, 14, 22))
        for wy in range(h - bh + 12, h - 10, 18):
            for wx in range(x + 8, x + bw - 8, 14):
                if rnd.random() < 0.35:
                    d.rectangle([wx, wy, wx + 6, wy + 9], fill=(255, rnd.randint(170, 220), 90))
        x += bw + rnd.randint(4, 20)
    img = img.filter(ImageFilter.GaussianBlur(0.6))
    # Sensorrauschen wie bei einer echten Kamera (sonst gelten identische Fensterblöcke als Klon)
    import numpy as np
    arr = np.asarray(img).astype(np.int16)
    arr += np.random.default_rng(7).normal(0, 6, arr.shape).astype(np.int16)
    img = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))
    photo = DEMO / "IMG_2026-09-14_Berlin.jpg"
    img.save(photo, "JPEG", quality=92)
    gps = {piexif.GPSIFD.GPSLatitudeRef: b"N", piexif.GPSIFD.GPSLatitude: ((52, 1), (30, 1), (5870, 100)),
           piexif.GPSIFD.GPSLongitudeRef: b"E", piexif.GPSIFD.GPSLongitude: ((13, 1), (22, 1), (3970, 100))}
    zeroth = {piexif.ImageIFD.Make: b"DGKN", piexif.ImageIFD.Model: b"Demo-Cam",
              piexif.ImageIFD.Software: b"Adobe Photoshop 25.0"}
    exif = {piexif.ExifIFD.DateTimeOriginal: b"2026:09:14 21:37:00"}
    piexif.insert(piexif.dump({"0th": zeroth, "Exif": exif, "GPS": gps}), str(photo))

    # 2) Rekursive Zipbomb (42.zip-Stil) – 21 KB auf der Platte
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_BZIP2) as z:
        z.writestr("payload.bin", b"\x00" * (60 << 20))
    data = inner.getvalue()
    for lvl in range(3):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            for i in range(4):
                z.writestr(f"lvl{lvl}_{i}.zip", data)
        data = b.getvalue()
    bomb = DEMO / "Bewerbungsunterlagen.zip"
    bomb.write_bytes(data)

    # 3) Programm, getarnt als PDF (Kopie des signierten python.exe – harmlos)
    fake = DEMO / "Rechnung_2026-09.pdf"
    shutil.copy(sys.executable, fake)
    return photo, bomb, fake


def main():
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtGui import QFont, QFontDatabase
    from PyQt6.QtWidgets import QApplication
    from config.settings import FONT_MONO
    from gui.styles import qss_main
    # WebEngine (3D-Globus) muss VOR der QApplication importiert werden – wie in main.py
    from gui.main_window import MainWindow

    photo, bomb, fake = make_demo_files()
    OUT.mkdir(parents=True, exist_ok=True)

    app = QApplication(sys.argv)
    app.setStyleSheet(qss_main())
    fams = set(QFontDatabase.families())
    app.setFont(QFont(FONT_MONO if FONT_MONO in fams else "Consolas", 10))

    w = MainWindow()
    w.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
    avail = app.primaryScreen().availableGeometry()
    ww, wh = min(1680, avail.width() - 40), min(1000, avail.height() - 40)
    w.resize(ww, wh)
    w.move(avail.x() + (avail.width() - ww) // 2, avail.y() + (avail.height() - wh) // 2)
    w.show()
    w.raise_()
    w.activateWindow()

    def shot(name):
        """Fenster per Qt-grab(); die WebGL-Fläche (Globus) wird separat gegrabbt und
        eingesetzt – Bildschirmaufnahmen per GDI liefern dort nur Schwarz."""
        from PyQt6.QtGui import QPainter
        app.processEvents()
        pix = w.grab()
        web = getattr(w.dashboard, "web", None)
        if web is not None and web.isVisible():
            globe = web.grab()
            pos = web.mapTo(w, web.rect().topLeft())
            p = QPainter(pix)
            p.drawPixmap(pos, globe)
            p.end()
        pix.save(str(OUT / name))
        print("gespeichert:", OUT / name, pix.width(), "x", pix.height(), flush=True)

    def goto(idx, tab=None):
        w._goto(idx)
        (w.btn_dashboard, w.btn_analysis, w.btn_ai)[idx].setChecked(True)
        if tab is not None:
            w.analysis.tabs.setCurrentIndex(tab)

    steps = [
        (14000, lambda: w._load_file(str(bomb))),                  # Globus laden lassen
        (15000, lambda: (goto(0), shot("01-dashboard-zipbomb.png"))),
        (1500, lambda: (goto(1, 2), shot("02-threats-zipbomb.png"))),
        (500, lambda: w._load_file(str(fake))),
        (9000, lambda: (goto(1, 1), shot("03-overview-disguised-exe.png"))),
        (500, lambda: (goto(0), w._load_file(str(photo)))),
        (12000, lambda: goto(0)),                                  # App springt nach Analyse zur Detailansicht
        (14000, lambda: shot("04-dashboard-globe-gps.png")),       # Kameraflug nach Berlin abwarten
        (1500, lambda: (goto(1, 0), shot("05-sandbox-preview.png"))),
        (500, app.quit),
    ]

    def run(i=0):
        if i < len(steps):
            delay, fn = steps[i]
            QTimer.singleShot(delay, lambda: (fn(), run(i + 1)))

    run()
    app.exec()


if __name__ == "__main__":
    main()
