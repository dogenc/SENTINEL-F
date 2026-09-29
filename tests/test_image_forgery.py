"""JPEG-Ghost und Copy-Move: echte Fälschungen finden, normale (auch mehrfach gespeicherte) Fotos nicht."""
import io

import numpy as np
import pytest

from engines.image_engine import ImageForensicEngine

Image = pytest.importorskip("PIL.Image")


def _scene(seed, w=1024, h=768):
    """Fotoähnliche Szene: weiche Flächen, Kanten, Textur und Sensorrauschen."""
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:h, 0:w].astype(np.float32)
    img = np.zeros((h, w, 3), np.float32)
    for c in range(3):
        base = 90 + 60 * np.sin(x / rng.uniform(40, 140) + rng.uniform(0, 6)) \
                  * np.cos(y / rng.uniform(40, 140) + rng.uniform(0, 6))
        img[:, :, c] = base + 25 * np.sin((x + 2 * y) / rng.uniform(5, 15))
    for _ in range(40):                                   # Objekte mit Kanten
        cx, cy, r = rng.integers(0, w), rng.integers(0, h), rng.integers(15, 90)
        img[(x - cx) ** 2 + (y - cy) ** 2 < r * r] += rng.uniform(-70, 70, 3)
    noise = rng.normal(0, 1, (h // 4, w // 4, 3)).repeat(4, 0).repeat(4, 1) * 18
    img += noise + rng.normal(0, 14, img.shape)            # feine Textur (Laub, Stoff, Kies)
    return Image.fromarray(np.clip(img, 0, 255).astype(np.uint8))


def _jpeg(img, q):
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=q)
    buf.seek(0)
    return Image.open(buf).convert("RGB")


def _run(img, tmp_path, name, q):
    p = tmp_path / name
    img.save(p, "JPEG", quality=q)
    eng = ImageForensicEngine(str(p))
    return eng.jpeg_ghost_detection(), eng.clone_detection()


def test_resaved_photo_is_clean(tmp_path):
    photo = _jpeg(_scene(1), 75)                          # Kamera → später neu gespeichert
    ghost, clone = _run(photo, tmp_path, "resaved.jpg", 95)
    assert not ghost["ghost_detected"]
    assert clone["clone_pairs"] == 0


def test_spliced_region_shows_second_quality(tmp_path):
    back = _jpeg(_scene(2), 75)                           # Kamera-JPEG
    donor = _jpeg(_scene(3), 55)
    fake = back.copy()
    fake.paste(donor.crop((320, 240, 640, 560)), (512, 192))      # am 8×8-Raster ausgerichtet
    ghost, _ = _run(fake, tmp_path, "splice.jpg", 92)
    assert ghost["ghost_detected"]
    x, y, w, h = ghost["region"]
    assert abs(x - 512) <= 32 and abs(y - 192) <= 32 and 250 <= w <= 360 and 250 <= h <= 360
    assert abs(ghost["ghost_quality"] - 55) <= 8


def test_copy_move_found_with_shift(tmp_path):
    img = _jpeg(_scene(4), 85)
    img.paste(img.crop((100, 400, 280, 580)), (700, 120))
    _, clone = _run(img, tmp_path, "clone.jpg", 90)
    assert clone["clone_pairs"] > 0
    assert clone["shift"] == [600, -280] or clone["shift"] == [-600, 280]


def test_repeating_texture_is_not_a_clone(tmp_path):
    rng = np.random.default_rng(5)
    tile = rng.integers(40, 220, (48, 64, 3)).astype(np.uint8)       # Fliesen/Ziegel-Muster
    wall = np.tile(tile, (16, 16, 1)).astype(np.float32) + rng.normal(0, 3, (768, 1024, 3))
    img = Image.fromarray(np.clip(wall, 0, 255).astype(np.uint8))
    _, clone = _run(img, tmp_path, "wall.jpg", 88)
    assert clone["clone_pairs"] == 0


def test_scoring_uses_new_results(tmp_path):
    from engines import run_forensic
    img = _jpeg(_scene(4), 85)
    img.paste(img.crop((100, 400, 280, 580)), (700, 120))
    p = tmp_path / "c.jpg"
    img.save(p, "JPEG", quality=90)
    codes = {f["code"] for f in run_forensic(str(p))["score"]["findings"]}
    assert "clone_detected" in codes and "jpeg_ghost" not in codes
    clean = tmp_path / "ok.jpg"
    _jpeg(_scene(1), 75).save(clean, "JPEG", quality=95)
    codes = {f["code"] for f in run_forensic(str(clean))["score"]["findings"]}
    assert not codes & {"clone_detected", "jpeg_ghost"}
