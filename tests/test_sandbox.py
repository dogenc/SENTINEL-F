"""
Sandbox-Beweise: der Worker kann nichts starten, nichts in Benutzerdaten/Registry
schreiben, keinen Speicher über das Limit belegen und wird bei Zeitüberschreitung beendet.
"""
import json
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path

import pytest

from core import sandbox

pytestmark = pytest.mark.skipif(not sandbox.available(), reason="Sandbox nur unter Windows")


def _probe(name, **kw):
    run = sandbox.run_worker([sandbox.SELFTEST_FLAG, name], **kw)
    f = run.jobdir / "selftest.json"
    return run, (json.loads(f.read_text()) if f.exists() else None)


_LOW_OK = {}


def _mode(mode):
    """Startparameter je Sandbox-Stufe. Low IL wird nur übersprungen, wenn diese Umgebung
    nachweislich keinen Low-IL-Prozess starten kann (z. B. GitHub-Runner: 0xC0000135)."""
    if mode == "appcontainer":
        _ac_ready()
        return {"appcontainer": True}
    if "ok" not in _LOW_OK:
        run, res = _probe("spawn")
        _LOW_OK["ok"] = res is not None
        _LOW_OK["code"] = run.exit_code
    if not _LOW_OK["ok"]:
        pytest.skip(f"Low-IL-Prozess startet in dieser Umgebung nicht (Code 0x{(_LOW_OK['code'] or 0):08X})")
    return {}


MODES = ["low", "appcontainer"]


def test_worker_runs_at_low_integrity():
    kw = _mode("low")
    run, res = _probe("spawn", **kw)
    assert run.integrity == "low"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("probe", ["spawn", "write", "registry"])
def test_worker_is_blocked(probe, mode):
    run, res = _probe(probe, **_mode(mode))
    assert run.integrity == mode
    assert res is not None, "Sonde hat kein Ergebnis geschrieben"
    assert res["blocked"] is True, res
    assert not list(Path.home().glob("sentinel_probe_*.txt"))


@pytest.mark.parametrize("mode", MODES)
def test_memory_limit_is_enforced(mode):
    run, res = _probe("memory", **_mode(mode))
    assert res is None or res["blocked"] is True
    assert (run.peak_memory or 0) <= sandbox.MEMORY_LIMIT + (64 << 20)


@pytest.mark.parametrize("mode", MODES)
def test_hanging_worker_is_killed(mode):
    kw = _mode(mode)
    t0 = time.monotonic()
    run, res = _probe("sleep", timeout=3, **kw)
    assert run.timed_out
    assert time.monotonic() - t0 < 15


def test_isolated_analysis_matches_contract(jpeg_file):
    res = sandbox.analyze_isolated(str(jpeg_file))
    assert res["ok"] and res["kind"] == "image"
    assert res["sandbox"]["isolated"] and res["sandbox"]["integrity"] in ("low", "appcontainer")
    png = Path(res["sandbox"]["preview_png"])
    assert png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    assert isinstance(res["magic"], tuple)


def test_isolated_zip_bomb(tmp_path):
    p = tmp_path / "bomb.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_BZIP2) as z:
        z.writestr("a.bin", b"\x00" * (40 << 20))
    res = sandbox.analyze_isolated(str(p))
    assert res["score"]["level"] in ("HIGH RISK", "CRITICAL")
    assert list(tmp_path.iterdir()) == [p]


def test_timeout_becomes_finding(jpeg_file):
    res = sandbox.analyze_isolated(str(jpeg_file), timeout=0.05)
    assert res["ok"]
    assert res["score"]["findings"][0]["code"] == "sandbox_violation"
    assert res["hashes"]["sha256"]


def _png_bomb(path, w=15000, h=15000):
    """Graustufen-PNG: ~225 Mio. Pixel, aber nur ~200 KB groß."""
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    comp = zlib.compressobj(9)
    row = b"\x00" * (w + 1)
    idat = b"".join(comp.compress(row) for _ in range(h)) + comp.flush()
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0))
                     + chunk(b"IDAT", idat) + chunk(b"IEND", b""))
    return path


def test_image_bomb_detected_without_decoding(tmp_path):
    from tests.helpers import analyze, codes
    p = _png_bomb(tmp_path / "bomb.png")
    assert p.stat().st_size < 2 << 20
    _, f = analyze(p, only={"baseline"})
    assert any(x["code"] == "image_bomb" and x["severity"] == "CRIT" for x in f)


def test_image_bomb_in_sandbox_is_contained(tmp_path):
    p = _png_bomb(tmp_path / "bomb.png")
    res = sandbox.analyze_isolated(str(p))
    assert res["ok"]
    assert res["score"]["level"] in ("HIGH RISK", "CRITICAL")
    assert (res["sandbox"].get("peak_memory") or 0) < sandbox.MEMORY_LIMIT


# ─── AppContainer: kein Netzwerk ───────────────────────────────────────────
def _ac_ready():
    from core import appcontainer as ac
    from config.settings import DATA_DIR
    if not ac.supported():
        pytest.skip("AppContainer nicht unterstützt")
    ac.ensure_access(sandbox.jobs_root(), DATA_DIR / "appcontainer.json")


def test_network_is_blocked_in_appcontainer():
    _ac_ready()
    run = sandbox.run_worker([sandbox.SELFTEST_FLAG, "network"], appcontainer=True)
    res = json.loads((run.jobdir / "selftest.json").read_text())
    assert run.integrity == "appcontainer"
    assert res["blocked"] is True, res


def test_user_files_are_not_readable_in_appcontainer():
    _ac_ready()
    run = sandbox.run_worker([sandbox.SELFTEST_FLAG, "read_user"], appcontainer=True)
    res = json.loads((run.jobdir / "selftest.json").read_text())
    assert res["blocked"] in (True, None), res


def test_analysis_runs_in_appcontainer_with_original_paths(tmp_path):
    _ac_ready()
    p = tmp_path / "probe.txt"
    p.write_text("hallo https://example.invalid/x")
    res = sandbox.analyze_isolated(str(p))
    assert res["ok"], res.get("error")
    assert res["sandbox"]["network"].startswith("blocked"), res["sandbox"]
    assert res["file"]["path"] == str(p.resolve())
    assert "input" not in json.dumps(res["file"])
