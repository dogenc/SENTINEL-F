"""Werbegrafiken aus echten Screenshots: LinkedIn (1200×1200) und GitHub-Social-Preview (1280×640)."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
SHOTS = ROOT / "docs" / "screenshots"
OUT = ROOT / "docs" / "promo"
BG, ACCENT, TEXT, MUTE, RED = (5, 7, 10), (53, 255, 138), (220, 232, 226), (120, 140, 132), (255, 42, 63)
FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")


def font(size, bold=False, mono=True):
    name = ("DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf") if mono else \
           ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf")
    for d in (FONT_DIR, Path("C:/Windows/Fonts")):
        if (d / name).exists():
            return ImageFont.truetype(str(d / name), size)
    return ImageFont.truetype("consolab.ttf" if bold else "consola.ttf", size)


def backdrop(w, h):
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    for x in range(0, w, 40):
        d.line([(x, 0), (x, h)], fill=(12, 20, 16))
    for y in range(0, h, 40):
        d.line([(0, y), (w, y)], fill=(12, 20, 16))
    glow = Image.new("RGB", (w, h), (0, 0, 0))
    ImageDraw.Draw(glow).ellipse([w * 0.15, h * 0.2, w * 0.85, h * 0.9], fill=(10, 60, 34))
    return Image.blend(img, glow.filter(ImageFilter.GaussianBlur(160)), 0.55)


def shot(name, width):
    im = Image.open(SHOTS / name).convert("RGB")
    im = im.resize((width, round(im.height * width / im.width)), Image.LANCZOS)
    framed = Image.new("RGB", (im.width + 4, im.height + 4), ACCENT)
    framed.paste(im, (2, 2))
    return framed


def paste_shadow(canvas, im, xy):
    sh = Image.new("RGBA", (im.width + 60, im.height + 60), (0, 0, 0, 0))
    ImageDraw.Draw(sh).rectangle([30, 30, im.width + 30, im.height + 30], fill=(0, 0, 0, 200))
    sh = sh.filter(ImageFilter.GaussianBlur(18))
    canvas.paste(sh, (xy[0] - 22, xy[1] - 14), sh)
    canvas.paste(im, xy)


def header(canvas, x, y, scale=1.0):
    d = ImageDraw.Draw(canvas)
    icon = Image.open(ROOT / "resources" / "sentinel.png").convert("RGBA").resize((round(96 * scale),) * 2)
    canvas.paste(icon, (x, y), icon)
    tx = x + round(116 * scale)
    d.text((tx, y - round(6 * scale)), "SENTINEL-F", font=font(round(74 * scale), True), fill=ACCENT)
    d.text((tx + 4, y + round(76 * scale)), "File-Forensic Intelligence Suite  ·  by DGKN@Labs",
           font=font(round(24 * scale)), fill=TEXT)


def pill(d, x, y, text, size=22):
    f = font(size, True, mono=False)
    w = d.textlength(text, font=f)
    d.rounded_rectangle([x, y, x + w + 36, y + size + 22], radius=(size + 22) // 2, fill=(10, 30, 20), outline=ACCENT, width=2)
    d.text((x + 18, y + 9), text, font=f, fill=TEXT)
    return x + w + 36


def linkedin():
    W = H = 1200
    c = backdrop(W, H)
    header(c, 60, 56)
    d = ImageDraw.Draw(c)
    d.text((64, 210), "Jede Datei zerlegt – in einer Sandbox ohne Netzwerk.", font=font(30, True, mono=False), fill=TEXT)
    d.text((64, 252), "Findet Malware, Fälschungen & Manipulation. Verknüpft Fälle. Schreibt den Bericht.",
           font=font(22, mono=False), fill=MUTE)
    paste_shadow(c, shot("01-dashboard-zipbomb.png", 800), (60, 320))
    paste_shadow(c, shot("14-payload-chain.png", 470), (670, 560))
    paste_shadow(c, shot("12-ioc-graph.png", 400), (700, 330))
    y, x = 930, 60
    for t in ("🛡 AppContainer-Sandbox", "💣 Zip-Bomben & getarnte EXEs", "🎯 MITRE ATT&CK"):
        x = pill(d, x, y, t.split(" ", 1)[1]) + 14
    y, x = 990, 60
    for t in ("🕸 IOC-Graph & YARA aus Fällen", "📸 Foto-Echtheit", "📄 Signierte Berichte"):
        x = pill(d, x, y, t.split(" ", 1)[1]) + 14
    d.line([(60, 1070), (W - 60, 1070)], fill=(30, 60, 44), width=2)
    d.text((64, 1092), "Open Source · GPL-3.0 · Windows Setup & Portable", font=font(24, True), fill=ACCENT)
    d.text((64, 1132), "github.com/dogenc/SENTINEL-F", font=font(24), fill=TEXT)
    d.text((W - 64 - d.textlength("● LIVE", font=font(22, True)), 1094), "● LIVE", font=font(22, True), fill=RED)
    return c


def social():
    W, H = 1280, 640
    c = backdrop(W, H)
    header(c, 56, 60, 0.9)
    d = ImageDraw.Draw(c)
    lines = ["Sandbox ohne Netzwerk", "Malware- & Fälschungs-Erkennung", "ATT&CK · IOC-Graph · YARA",
             "Signierte Forensik-Berichte", "Setup & Portable · GPL-3.0"]
    for i, t in enumerate(lines):
        d.text((64, 220 + i * 50), "▸ " + t, font=font(26, True, mono=False), fill=TEXT if i < 4 else ACCENT)
    paste_shadow(c, shot("14-payload-chain.png", 580), (660, 220))
    d.text((64, 560), "github.com/dogenc/SENTINEL-F", font=font(22), fill=MUTE)
    return c


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    linkedin().save(OUT / "linkedin-post.png", optimize=True)
    social().save(OUT / "github-social-preview.png", optimize=True)
    print(OUT)
