"""Ähnlichkeitssuche: TLSH (reines Python, referenzgleich), Imphash/Rich, Verlauf."""
import json
import os
import random
import sqlite3

import pytest

from core.history import HistoryDB
from engines import run_forensic
from engines.similarity import tlsh_hash, tlsh_diff, label, fingerprints

# Mit der Referenzbibliothek py-tlsh erzeugte Werte
REF = [
    (bytes(range(256)) * 20, "T1F6B19524E6514D7D1F175ADCD04E44DF554FCDE302C5002517F186D1C510294440ED1D"),
    (b"The quick brown fox jumps over the lazy dog. " * 30,
     "T15321024A311C1794658A1888438D95B2D2C9C910612114116570604219482359CD8551"),
]


def test_matches_reference_vectors():
    for data, ref in REF:
        assert tlsh_hash(data) == ref
    random.seed(42)
    rnd = bytes(random.getrandbits(8) for _ in range(5000))
    assert tlsh_hash(rnd) == "T111A16C048BD5174F0F891F50C6C9ECBE73B2325AF3649A4E65157B16E99F05CA7883E0"
    assert tlsh_diff(REF[0][1], REF[1][1]) == 378
    assert tlsh_diff(REF[0][1], REF[0][1]) == 0


def test_against_installed_reference_if_available():
    tlsh = pytest.importorskip("tlsh")
    for n in (50, 51, 656, 657, 3199, 3200, 70000):
        data = os.urandom(n)
        ref = tlsh.hash(data)
        assert tlsh_hash(data) == (None if ref in ("TNULL", "") else ref)
    a, b = tlsh.hash(os.urandom(9000)), tlsh.hash(os.urandom(9000))
    assert tlsh_diff(a, b) == tlsh.diff(a, b)


def test_invalid_inputs():
    assert tlsh_hash(b"x" * 49) is None           # zu kurz
    assert tlsh_hash(b"a" * 5000) is None         # zu gleichförmig
    assert tlsh_diff("T1xyz", REF[0][1]) is None
    assert label(0) == "identical structure" and label(25) == "near-identical" and label(200) == "unrelated"


def _script(tmp_path, name, extra=""):
    p = tmp_path / name
    body = "\n".join(f"$v{i} = Get-Item 'C:\\Users\\Public\\f{i}.txt' ; Write-Output $v{i}.Length" for i in range(60))
    p.write_text(body + extra)
    return p


def test_variant_is_found_but_identical_file_is_not(tmp_path):
    db = HistoryDB(tmp_path / "h.db")
    a = db.record(run_forensic(str(_script(tmp_path, "a.ps1"))))
    same = db.record(run_forensic(str(_script(tmp_path, "kopie.ps1"))))          # identisch → "seen before"
    var = db.record(run_forensic(str(_script(tmp_path, "b.ps1", "\n# kleine Änderung\n"))))
    other = tmp_path / "anders.txt"
    other.write_bytes(os.urandom(6000))
    db.record(run_forensic(str(other)))

    sims = db.similar(var)
    names = [s["name"] for s in sims]
    assert names == ["a.ps1"] or names == ["kopie.ps1"]          # gleicher SHA wird nur einmal gezeigt
    assert sims[0]["match"] == ["tlsh"] and sims[0]["distance"] <= 30
    assert all(s["sha256"] != db.list_analyses(search="b.ps1")[0]["sha256"] for s in sims)
    assert [s["name"] for s in db.similar(a)] == ["b.ps1"]      # die Kopie ist nicht "ähnlich"
    assert db.similar(same)[0]["name"] == "b.ps1"


def _fake(name, sha, fp):
    return {"ok": True, "timestamp": "2026-01-01 10:00:00", "file": {"name": name, "path": "/x/" + name},
            "hashes": {"sha256": sha}, "score": {"score": 80, "level": "CRITICAL"}, "fingerprints": fp}


def test_imphash_and_rich_matches_and_generic_imphash(tmp_path):
    db = HistoryDB(tmp_path / "h.db")
    a = db.record(_fake("dropper_v1.exe", "a" * 64, {"imphash": "i1", "rich": "r1"}))
    db.record(_fake("dropper_v2.exe", "b" * 64, {"imphash": "i1"}))
    db.record(_fake("same_toolchain.exe", "c" * 64, {"rich": "r1"}))
    got = {s["name"]: s["match"] for s in db.similar(a)}
    assert got == {"dropper_v2.exe": ["imphash"], "same_toolchain.exe": ["rich"]}
    for i in range(55):                                           # sehr häufiger Imphash → zu allgemein
        db.record(_fake(f"x{i}.exe", f"{i:064d}", {"imphash": "common"}))
    b = db.record(_fake("y.exe", "d" * 64, {"imphash": "common"}))
    assert db.similar(b) == []


def test_dotnet_imphash_is_ignored_and_rich_is_used():
    r = {"report": {"analyzers": {"pe": {"imphash": "f34d", "dotnet": True, "rich_hash": "rr"}}},
         "fingerprints": {"tlsh": None}}
    assert fingerprints(r) == {"rich": "rr"}


def test_backfill_for_old_databases(tmp_path):
    path = tmp_path / "old.db"
    db = HistoryDB(path)
    res = {"file": {"name": "old.exe"}, "hashes": {"sha256": "e" * 64},
           "report": {"analyzers": {"pe": {"imphash": "legacy"}}}}
    db.record(res)
    with sqlite3.connect(path) as con:                  # Zustand vor dem Update simulieren
        con.execute("DELETE FROM fingerprints")
        con.execute("PRAGMA user_version = 0")
    db2 = HistoryDB(path)
    assert db2.fingerprints_for(db2.list_analyses()[0]["id"]) == {"imphash": "legacy"}


def test_similar_tab(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    from gui.analysis_view import AnalysisView
    v = AnalysisView()
    rows = [{"id": 7, "name": "a.ps1", "match": ["tlsh"], "distance": 12, "level": "CRITICAL", "score": 90,
             "case_name": None, "analyzed_at": "2026-01-01", "path": "/a.ps1"}]
    v.set_similar(rows, {"tlsh": "T1ABC"})
    assert v.similar.table.rowCount() == 1 and "near-identical" in v.similar.table.item(0, 1).text()
    assert "SIMILAR  1" in v.tabs.tabText(v.tabs.indexOf(v.similar))
    got = []
    v.similar.openRequested.connect(got.append)
    v.similar._open(v.similar.table.model().index(0, 0))
    assert got == [7]
    v.reset()
    assert v.similar.table.rowCount() == 0
