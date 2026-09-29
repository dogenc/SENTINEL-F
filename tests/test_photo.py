"""Foto-Echtheit: C2PA, KI-Marker, PRNU-Kamerafingerabdruck."""
import os
import struct

import numpy as np
import pytest
from PIL import Image, PngImagePlugin

from core.history import HistoryDB
from engines import run_forensic
from engines.analyzers.photo import SAME_CAMERA_NCC, prnu_ncc


def _codes(res):
    return {f["code"] for f in res["score"]["findings"]}


def _jpeg_with_segment(path, marker, payload):
    Image.new("RGB", (64, 48), (90, 120, 200)).save(path, "JPEG", quality=90)
    data = path.read_bytes()
    seg = b"\xff" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload
    path.write_bytes(data[:2] + seg + data[2:])
    return path


def test_c2pa_manifest_with_ai_declaration(tmp_path):
    jumbf = (b"JP\x00\x01\x00\x00\x00\x01jumb\x00\x00\x00\x20jumdc2pa\x00\x11\x00\x10"
             b"c2pa.claim claim_generator\x00\x1a\"Adobe_Firefly/2.0\" c2pa.created "
             b"digitalSourceType http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia")
    p = _jpeg_with_segment(tmp_path / "firefly.jpg", 0xEB, jumbf)
    res = run_forensic(str(p))
    c2 = res["report"]["analyzers"]["photo"]["c2pa"]
    assert c2["present"] and "Firefly" in (c2["generator"] or "") and c2["source_type"] == "trainedAlgorithmicMedia"
    assert "created" in c2["actions"]
    assert "NOT verified" in c2["verification"] or "library present" in c2["verification"]
    assert {"c2pa_present", "c2pa_ai_declared", "ai_generated"} <= _codes(res)


def test_stable_diffusion_png(tmp_path):
    p = tmp_path / "gen.png"
    info = PngImagePlugin.PngInfo()
    info.add_text("parameters", "a castle at night\nNegative prompt: blurry\n"
                                "Steps: 30, Sampler: DPM++ 2M Karras, CFG scale: 7, Seed: 1, Size: 512x512")
    Image.new("RGB", (512, 512), (20, 30, 40)).save(p, pnginfo=info)
    res = run_forensic(str(p))
    assert "ai_generated" in _codes(res)
    assert res["score"]["level"] in ("ELEVATED", "HIGH RISK", "CRITICAL", "LOW RISK")
    assert any("Stable Diffusion" in m["marker"] for m in res["report"]["analyzers"]["photo"]["ai_markers"])


def test_comfyui_and_iptc_xmp(tmp_path):
    p = tmp_path / "comfy.png"
    info = PngImagePlugin.PngInfo()
    info.add_text("prompt", '{"3": {"class_type": "KSampler"}}')
    Image.new("RGB", (64, 64)).save(p, pnginfo=info)
    assert "ai_generated" in _codes(run_forensic(str(p)))
    xmp = (b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta><rdf:Description "
           b"Iptc4xmpExt:DigitalSourceType=\"http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia\"/>"
           b"</x:xmpmeta>")
    j = _jpeg_with_segment(tmp_path / "iptc.jpg", 0xE1, xmp)
    assert "ai_generated" in _codes(run_forensic(str(j)))


def test_plain_photo_has_no_authenticity_findings(tmp_path, jpeg_file):
    res = run_forensic(str(jpeg_file))
    assert not _codes(res) & {"ai_generated", "c2pa_present", "c2pa_ai_declared", "ai_generated_hint"}
    assert "prnu" not in res["report"]["analyzers"]["photo"]           # zu klein für PRNU


def _camera_shots(tmp_path, cam, k, n, W=900, H=700):
    out = []
    for i in range(n):
        r = np.random.default_rng(hash((cam, i)) % 10_000)
        y, x = np.mgrid[0:H, 0:W]
        s = 128 + 70 * np.sin(x / (37 + i * 11)) * np.cos(y / (51 + i * 5))
        for _ in range(10):
            cx, cy, rad = r.integers(0, W), r.integers(0, H), r.integers(30, 200)
            s = s + ((x - cx) ** 2 + (y - cy) ** 2 < rad ** 2) * r.integers(-40, 40)
        img = np.clip(s, 10, 245) * (1 + k) + r.normal(0, 2, (H, W))
        p = tmp_path / f"{cam}_{i}.jpg"
        Image.fromarray(np.clip(img, 0, 255).astype(np.uint8)).save(p, quality=92)
        out.append(p)
    return out


def test_prnu_links_photos_of_the_same_camera(tmp_path):
    rng = np.random.default_rng(7)
    kA, kB = rng.normal(0, 0.012, (700, 900)), rng.normal(0, 0.012, (700, 900))
    db = HistoryDB(tmp_path / "h.db")
    ids = {}
    for p in _camera_shots(tmp_path, "A", kA, 2) + _camera_shots(tmp_path, "B", kB, 1):
        res = run_forensic(str(p))
        assert res["fingerprints"]["prnu"].startswith("900x700:")
        ids[p.stem] = db.record(res)
    sims = db.similar(ids["A_0"])
    assert [s["name"] for s in sims] == ["A_1.jpg"]
    assert sims[0]["match"] == ["prnu"] and sims[0]["ncc"] >= SAME_CAMERA_NCC
    assert db.similar(ids["B_0"]) == []
    fa = db.fingerprints_for(ids["A_0"])["prnu"]
    assert prnu_ncc(fa, "800x600:" + fa.split(":", 1)[1]) is None           # andere Auflösung → kein Vergleich
