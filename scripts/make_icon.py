"""Erzeugt resources/sentinel.ico (Radar-Symbol im SENTINEL-F-Look). Einmalig ausführen, das Ergebnis ist im Repo."""
from pathlib import Path

from PIL import Image, ImageDraw

BG, ACCENT, DIM = (5, 7, 10, 255), (53, 255, 138, 255), (24, 120, 68, 255)


def draw(size=1024):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size / 256
    d.rounded_rectangle([8 * s, 8 * s, 248 * s, 248 * s], radius=52 * s, fill=BG, outline=ACCENT, width=round(10 * s))
    c = 128 * s
    d.pieslice([c - 82 * s, c - 82 * s, c + 82 * s, c + 82 * s], -90, -30, fill=(16, 78, 45, 255))
    for r, w, col in ((82, 10, ACCENT), (52, 6, DIM)):
        d.ellipse([c - r * s, c - r * s, c + r * s, c + r * s], outline=col, width=round(w * s))
    d.line([c, 34 * s, c, 222 * s], fill=DIM, width=round(5 * s))
    d.line([34 * s, c, 222 * s, c], fill=DIM, width=round(5 * s))
    d.ellipse([c - 16 * s, c - 16 * s, c + 16 * s, c + 16 * s], fill=ACCENT)
    d.ellipse([168 * s, 70 * s, 190 * s, 92 * s], fill=(255, 42, 63, 255))       # Treffer
    return img


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "resources" / "sentinel.ico"
    draw().save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    draw().resize((256, 256), Image.LANCZOS).save(out.with_suffix(".png"))
    print(out)
