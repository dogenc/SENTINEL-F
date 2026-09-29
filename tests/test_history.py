"""Analyse-Verlauf & Fälle (core/history.py) sowie die HISTORY-Ansicht."""
import os

import pytest

from core.history import HistoryDB, extract_iocs
from engines import run_forensic


@pytest.fixture
def db(tmp_path):
    return HistoryDB(tmp_path / "h.db")


@pytest.fixture
def ioc_file(tmp_path):
    p = tmp_path / "notiz.txt"
    p.write_text("siehe https://evil-host.invalid/payload und http://second.invalid/x")
    return p


def test_record_and_reopen_roundtrip(db, ioc_file):
    res = run_forensic(str(ioc_file))
    assert res["ok"]
    aid = db.record(res)
    back = db.get_result(aid)
    assert back["hashes"] == res["hashes"]
    assert back["score"]["score"] == res["score"]["score"]
    assert isinstance(back["magic"], tuple)
    assert back["history"]["id"] == aid
    row = db.list_analyses()[0]
    assert row["sha256"] == res["hashes"]["sha256"].lower() and row["name"] == "notiz.txt"


def test_known_file_is_recognised_by_hash(db, ioc_file, tmp_path):
    first = db.record(run_forensic(str(ioc_file)))
    renamed = tmp_path / "harmlos.txt"
    renamed.write_bytes(ioc_file.read_bytes())
    res = run_forensic(str(renamed))
    second = db.record(res)
    prev = db.previous(res["hashes"]["sha256"], exclude_id=second)
    assert [p["id"] for p in prev] == [first]
    assert prev[0]["name"] == "notiz.txt"
    assert db.previous(res["hashes"]["sha256"].upper(), exclude_id=first)[0]["id"] == second


def test_iocs_are_searchable(db, ioc_file, tmp_path):
    aid = db.record(run_forensic(str(ioc_file)))
    other = tmp_path / "leer.bin"
    other.write_bytes(os.urandom(64))
    db.record(run_forensic(str(other)))

    values = {v for _, v in extract_iocs(db.get_result(aid))}
    assert any("evil-host.invalid" in v for v in values)
    hits = db.search_ioc("EVIL-HOST")
    assert {h["id"] for h in hits} == {aid}
    # Freitextsuche der Übersicht findet ebenfalls über IOCs
    assert [r["id"] for r in db.list_analyses(search="second.invalid")] == [aid]


def test_search_by_hash_prefix_and_name(db, ioc_file):
    res = run_forensic(str(ioc_file))
    aid = db.record(res)
    assert [r["id"] for r in db.list_analyses(search=res["hashes"]["sha256"][:10].upper())] == [aid]
    assert [r["id"] for r in db.list_analyses(search="notiz")] == [aid]
    assert db.list_analyses(search="gibtsnicht") == []


def test_cases_filter_assign_and_delete(db, ioc_file):
    res = run_forensic(str(ioc_file))
    cid = db.create_case("INC-4711")
    with pytest.raises(ValueError):
        db.create_case("INC-4711")
    with pytest.raises(ValueError):
        db.create_case("   ")
    in_case = db.record(res, case_id=cid)
    loose = db.record(res)
    assert [r["id"] for r in db.list_analyses(case_id=cid)] == [in_case]
    assert [r["id"] for r in db.list_analyses(case_id=0)] == [loose]
    assert len(db.list_analyses()) == 2

    db.assign([loose], cid)
    case = db.list_cases()[0]
    assert case["name"] == "INC-4711" and case["analyses"] == 2

    # Fall löschen lässt die Analysen im Verlauf
    db.delete_case(cid)
    assert db.list_cases() == []
    assert len(db.list_analyses(case_id=0)) == 2

    db.delete_analyses([in_case])
    assert [r["id"] for r in db.list_analyses()] == [loose]
    assert db.iocs_for(in_case) == []


def test_stats(db, ioc_file):
    res = run_forensic(str(ioc_file))
    db.record(res)
    db.record(res)
    st = db.stats()
    assert st["analyses"] == 2 and st["files"] == 1 and st["cases"] == 0


def test_history_view_records_and_opens(tmp_path, ioc_file, db):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    from gui.history_view import HistoryView

    view = HistoryView(db=db)
    cid = db.create_case("Fall A")
    view.reload_cases(select_id=cid)
    assert view.active_case_id() == cid

    res = run_forensic(str(ioc_file))
    aid, prev = view.record(res)
    assert prev == []
    assert db.list_analyses(case_id=cid)[0]["id"] == aid
    assert view.table.rowCount() == 1

    _, prev = view.record(res)
    assert [p["id"] for p in prev] == [aid]

    opened = []
    view.openRequested.connect(opened.append)
    view.table.selectRow(0)
    view._open_selected()
    assert len(opened) == 1

    view.search.setText("evil-host")
    view.refresh()
    assert view.table.rowCount() == 2
    view.search.setText("nichts-davon")
    view.refresh()
    assert view.table.rowCount() == 0
