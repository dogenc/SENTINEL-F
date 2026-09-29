"""Zeitleiste & Zeitstempel-Widersprüche (engines/timeline.py)."""
import datetime
import os

import pytest

from engines import run_forensic
from engines.timeline import parse_ts, build_timeline


def test_parse_formats():
    assert parse_ts("2024:05:03 09:00:00") == (datetime.datetime(2024, 5, 3, 9), False)
    dt, tz = parse_ts("D:20230101120000Z")
    assert tz and dt == datetime.datetime(2023, 1, 1, 12, tzinfo=datetime.timezone.utc).astimezone().replace(tzinfo=None)
    assert parse_ts("D:20230101120000+01'00'")[1]
    assert parse_ts("D:2023")[0].year == 2023
    assert parse_ts("2021-01-01T00:00:00Z")[1]
    assert parse_ts("Tue, 01 Oct 2024 10:00:00 +0000")[1]
    assert parse_ts("0000:00:00 00:00:00") == (None, False)
    assert parse_ts("kein datum") == (None, False)


def _result(meta=None, analyzers=None, fs_mod="2026-01-01 12:00:00", ts="2026-09-29 10:00:00"):
    return {"timestamp": ts, "file": {"modified": fs_mod, "created": fs_mod, "accessed": fs_mod},
            "report": {"metadata": meta or {}, "analyzers": analyzers or {}}}


def _descs(tl):
    return [a["desc"] for a in tl["anomalies"]]


def test_consistent_document_has_no_contradictions():
    tl = build_timeline(_result({"CreationDate": "D:20240101100000Z", "ModDate": "D:20240301100000Z"}))
    assert tl["anomalies"] == []
    assert [e["label"] for e in tl["events"]][:2] == ["Created (PDF)", "Modified (PDF)"]
    assert tl["span"][1].startswith("2026-09-29")


@pytest.mark.parametrize("meta,src", [
    ({"CreationDate": "D:20240301100000Z", "ModDate": "D:20240101100000Z"}, "PDF"),
    ({"Created": "2021-01-01T00:00:00Z", "Modified": "2020-01-01T00:00:00Z"}, "Office"),
    ({"EXIF.DateTimeOriginal": "2024:05:05 09:00:00", "EXIF.DateTime": "2024:05:01 09:00:00"}, "EXIF"),
])
def test_created_after_modified(meta, src):
    d = _descs(build_timeline(_result(meta)))
    assert any(x.startswith(f"{src}: created") for x in d), d


def test_timezone_slack_prevents_false_alarm():
    # EXIF ohne Zone, 10 h "später" als Änderung → innerhalb der Toleranz
    tl = build_timeline(_result({"EXIF.DateTimeOriginal": "2024:05:01 19:00:00", "EXIF.DateTime": "2024:05:01 09:00:00"}))
    assert tl["anomalies"] == []


def test_future_and_forged_against_disk():
    now = datetime.datetime(2026, 9, 29, 10)
    tl = build_timeline(_result({"Created": "2031-01-01T00:00:00Z", "Modified": "2031-02-01T00:00:00Z"}), now=now)
    assert any("future" in x for x in _descs(tl))
    tl = build_timeline(_result({"CreationDate": "D:20260601000000Z", "ModDate": "D:20260602000000Z"},
                                fs_mod="2025-01-01 00:00:00"), now=now)
    assert any("later than the file's last write" in x for x in _descs(tl))


def test_exif_edited_later_is_info():
    tl = build_timeline(_result({"EXIF.DateTimeOriginal": "2024:05:01 09:00:00", "EXIF.DateTime": "2024:08:01 09:00:00"}))
    assert [a["severity"] for a in tl["anomalies"]] == ["INFO"]


def test_email_backdated_and_pe():
    mail = {"date": "Tue, 01 Oct 2024 18:00:00 +0000",
            "received": ["from a by b; Tue, 01 Oct 2024 10:05:00 +0000",
                         "from c by a; Tue, 01 Oct 2024 10:00:00 +0000"]}
    tl = build_timeline(_result(analyzers={"email": mail, "pe": {"compile_time": "2020-02-02T00:00:00+00:00"}}))
    assert any("Date header is" in x for x in _descs(tl))
    labels = [e["label"] for e in tl["events"]]
    assert "Compiled" in labels and "Received hop 2" in labels


def test_pipeline_real_files(tmp_path):
    import docx
    p = tmp_path / "vertrag.docx"
    d = docx.Document()
    d.core_properties.created = datetime.datetime(2021, 1, 1)
    d.core_properties.modified = datetime.datetime(2020, 1, 1)
    d.save(p)
    old = datetime.datetime(2022, 1, 1).timestamp()
    os.utime(p, (old, old))
    res = run_forensic(str(p))
    assert any(x.startswith("Office: created") for x in _descs(res["timeline"]))

    ok = tmp_path / "ok.docx"
    d = docx.Document()
    d.core_properties.created = datetime.datetime(2020, 1, 1)
    d.core_properties.modified = datetime.datetime(2020, 6, 1)
    d.save(ok)
    assert run_forensic(str(ok))["timeline"]["anomalies"] == []


def test_timeline_tab(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    from gui.analysis_view import AnalysisView
    view = AnalysisView()
    res = _result({"CreationDate": "D:20240301100000Z", "ModDate": "D:20240101100000Z"})
    res.update(ok=True, kind="pdf", score={"findings": []}, threat={})
    view.timeline.set_result(res)
    assert "contradiction" in view.timeline.lbl_summary.text()
    assert view.timeline.table.rowCount() == len(view.timeline.data["events"])
    view.timeline.set_result(None)
    assert view.timeline.table.rowCount() == 0
