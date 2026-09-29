"""Plattformunabhängige Teile des AppContainer-Betriebs (Staging, Pfad-Rückabbildung)."""
import json

from core import appcontainer as ac
from core import sandbox


def test_stage_file_copies_evidence_without_touching_it(tmp_path):
    src = tmp_path / "Beweis.docx"
    src.write_bytes(b"PK\x03\x04 evidence")
    before = src.stat()
    job = tmp_path / "job"
    job.mkdir()
    dst = ac.stage_file(str(src), job)
    assert dst.endswith("Beweis.docx") and "input" in dst
    assert open(dst, "rb").read() == src.read_bytes()
    after = src.stat()
    assert (before.st_mtime_ns, before.st_mode) == (after.st_mtime_ns, after.st_mode)


def test_remap_paths_restores_original_locations():
    orig = r"C:\Users\A\Downloads\Rechnung.pdf"
    copy = r"C:\Users\A\AppData\LocalLow\DGKN_Sentinel\jobs\x\input\Rechnung.pdf"
    text = json.dumps({"file": {"path": copy}, "report": {"note": f"read {copy}"}})
    out = json.loads(sandbox.remap_paths(text, {orig: copy}))
    assert out["file"]["path"] == orig and out["report"]["note"] == f"read {orig}"


def test_read_paths_cover_python_and_program():
    paths = [str(p) for p in ac.read_paths()]
    import sys
    from pathlib import Path
    assert any(Path(sys.base_prefix).resolve() == Path(p).resolve() for p in paths)
    assert any(Path(p).resolve() == Path(__file__).resolve().parent.parent for p in paths)


def test_setting_exists():
    from config.settings import SANDBOX_BLOCK_NETWORK
    assert SANDBOX_BLOCK_NETWORK is True


def test_worker_gets_no_access_to_history_or_keys():
    """Freigaben nur für Code – nicht data/ (Verlauf), reports/, .cache/ oder local_secrets.py."""
    from pathlib import Path
    root = Path(ac.__file__).resolve().parent.parent
    paths = {Path(p).resolve() for p in ac.read_paths()}
    for forbidden in ("data", "reports", ".cache", "config/local_secrets.py", "gui"):
        assert (root / forbidden).resolve() not in paths
    assert (root / "engines").resolve() in paths and (root / "main.py").resolve() in paths
