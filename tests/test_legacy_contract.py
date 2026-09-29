"""Charakterisierung: der Ergebnisvertrag von run_forensic, den die GUI liest."""
import pytest

from engines import run_forensic

SCORE_KEYS = {"score", "level", "color", "findings", "top", "total_signals"}


def _check_contract(res, kind):
    assert res["ok"], res.get("error")
    assert res["kind"] == kind
    assert set(res["hashes"]) >= {"md5", "sha1", "sha256"}
    assert len(res["magic"]) == 3
    assert isinstance(res["report"], dict)
    assert SCORE_KEYS <= set(res["score"])
    assert 0 <= res["score"]["score"] <= 100


@pytest.mark.parametrize("fixture,kind", [
    ("jpeg_file", "image"),
    ("pdf_file", "pdf"),
    ("docx_file", "document"),
    ("xlsx_file", "document"),
])
def test_known_types_keep_contract(request, fixture, kind):
    _check_contract(run_forensic(str(request.getfixturevalue(fixture))), kind)


def test_image_report_keeps_engine_sections(jpeg_file):
    rep = run_forensic(str(jpeg_file))["report"]
    assert "metadata" in rep and "ela" in rep


def test_pdf_report_keeps_info(pdf_file):
    rep = run_forensic(str(pdf_file))["report"]
    assert rep["info"]["page_count"] >= 1
