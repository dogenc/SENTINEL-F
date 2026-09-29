"""GUI-Rauchtest: Analyse-Ansicht rendert Ergebnisse aller Dateiarten (headless)."""
import os
import sys
import zipfile

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
QtWidgets = pytest.importorskip("PyQt6.QtWidgets")

from engines import run_forensic


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def _samples(tmp_path, jpeg_file, docx_file):
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_BZIP2) as f:
        f.writestr("a.bin", b"\x00" * (8 << 20))
    t = tmp_path / "n.txt"
    t.write_text("hallo https://example.invalid/x")
    b = tmp_path / "blob.bin"
    b.write_bytes(os.urandom(5000))
    return [jpeg_file, docx_file, z, t, b, sys.executable]


def test_analysis_view_renders_all_kinds(app, tmp_path, jpeg_file, docx_file):
    from gui.analysis_view import AnalysisView
    view = AnalysisView()
    for p in _samples(tmp_path, jpeg_file, docx_file):
        res = run_forensic(str(p))
        assert res["ok"], res["error"]
        view.load_result(res)
        assert view.tree_threats.topLevelItemCount() >= 1
        assert "THREAT ANALYSIS" in view.txt_overview.toPlainText()
        assert view.tbl_find.rowCount() == len(res["score"]["findings"])
    view.reset()
    assert view.tree_threats.topLevelItemCount() == 0


def test_sandboxed_preview_never_parses_original(app, jpeg_file, monkeypatch):
    from core import sandbox
    if not sandbox.available():
        pytest.skip("nur Windows")
    from gui.analysis_view import AnalysisView
    import gui.analysis_view as av
    # Würde die Ansicht das Original selbst dekodieren, schlägt der Test fehl
    monkeypatch.setattr(AnalysisView, "_preview_image_file", lambda *a: pytest.fail("Original geparst"))
    monkeypatch.setattr(AnalysisView, "_preview_pdf", lambda *a: pytest.fail("Original geparst"))
    res = sandbox.analyze_isolated(str(jpeg_file))
    view = AnalysisView()
    view.load_result(res)
    assert view.preview_image.pixmap() is not None and not view.preview_image.pixmap().isNull()
    assert "SANDBOX" in view.preview_header.text()
    assert "SANDBOX  : isolated" in view.txt_overview.toPlainText()
