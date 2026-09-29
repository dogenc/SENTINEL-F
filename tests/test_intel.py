"""Eigene Threat-Intel: Cluster-YARA-Regeln, Rückwärtstest, Aktivierung, STIX/MISP/CSV-Export."""
import csv
import json
import os

import pytest

from core import intel
from core.history import HistoryDB
from core.iocgraph import graph_from_db
from engines import run_forensic


def _campaign(tmp_path):
    d = tmp_path / "mails"
    d.mkdir()
    (d / "rechnung.html").write_text('<form action="https://pay-portal.invalid/login"><input type=password></form>'
                                     '<script>fetch("http://203.0.113.45/c")</script>')
    (d / "mahnung.html").write_text('<form action="https://pay-portal.invalid/p"><input type=password></form>'
                                    '<img src="http://203.0.113.45/t.gif">')
    (d / "=cmd+x.txt").write_text("Kontakt: https://pay-portal.invalid/support")
    (d / "harmlos.txt").write_text("Einkauf: https://shop.example.invalid/")
    return d


@pytest.fixture
def db_graph(tmp_path):
    db = HistoryDB(tmp_path / "h.db")
    for p in sorted(_campaign(tmp_path).iterdir()):
        db.record(run_forensic(str(p)))
    g = graph_from_db(db)
    return db, g


def test_rule_generation_compiles_and_backtests(db_graph):
    db, g = db_graph
    rule = intel.cluster_rule(db, g, g["clusters"][0], name="Pay Portal Wave")
    assert rule["name"] == "SENTINEL_GEN_Pay_Portal_Wave"
    assert "pay-portal.invalid" in rule["iocs"] and "203.0.113.45" in rule["iocs"]
    assert "shop.example.invalid" not in rule["text"]
    assert rule["threshold"] == 1
    pytest.importorskip("yara")
    assert intel.compile_check(rule["text"]) is None
    bt = intel.backtest(db, rule)
    assert len(bt["inside"]) == bt["cluster_size"] and bt["outside"] == []
    assert intel.compile_check("rule broken { condition: }")


def test_activated_rule_detects_new_variant(db_graph, tmp_path, monkeypatch):
    pytest.importorskip("yara")
    import config.settings as cs
    import engines.analyzers.yara_scan as ys
    db, g = db_graph
    monkeypatch.setattr(cs, "DATA_DIR", tmp_path / "data")
    rule = intel.cluster_rule(db, g, g["clusters"][0], name="wave")
    path = intel.activate(rule, directory=tmp_path / "data" / "yara_generated")
    assert path.exists() and intel.generated_rules(tmp_path / "data" / "yara_generated") == [path]
    ys._cache["key"] = None
    new = tmp_path / "neue_welle.txt"                  # unbekannte Datei derselben Kampagne
    new.write_text("Bitte bestätigen Sie unter hxxps://pay-portal.invalid/confirm – oder pay-portal.invalid")
    res = run_forensic(str(new))
    assert any(f["code"] == "yara_match" and "SENTINEL_GEN_wave" in f["desc"] for f in res["score"]["findings"])


def test_no_rule_without_shared_evidence(tmp_path):
    db = HistoryDB(tmp_path / "h.db")
    g = {"files": {"a": {"id": 1, "name": "a", "sha256": "a"}, "b": {"id": 2, "name": "b", "sha256": "b"}},
         "iocs": [], "similar": [("a", "b", "tlsh 5")],
         "clusters": [{"name": "Cluster 1", "files": ["a", "b"], "iocs": [], "max_score": 50}]}
    assert intel.cluster_rule(db, g, g["clusters"][0]) is None


def test_exports(db_graph, tmp_path):
    db, g = db_graph
    data = intel.collect(db)
    keys = {k for k in data["iocs"]}
    assert ("domain", "pay-portal.invalid") in keys and ("ipv4", "203.0.113.45") in keys
    assert all(f["level"] not in ("CLEAN", "LOW RISK") for f in data["files"])

    stix = json.loads(intel.write_export(data, tmp_path / "x.stix.json", "Wave").read_text())
    assert stix["type"] == "bundle"
    types = {o["type"] for o in stix["objects"]}
    assert {"identity", "indicator", "report"} <= types
    pats = [o["pattern"] for o in stix["objects"] if o["type"] == "indicator"]
    assert "[domain-name:value = 'pay-portal.invalid']" in pats
    assert any(p.startswith("[file:hashes.'SHA-256' = '") for p in pats)
    again = intel.to_stix(data, "Wave")
    assert {o["id"] for o in again["objects"] if o["type"] == "indicator"} == \
           {o["id"] for o in stix["objects"] if o["type"] == "indicator"}          # stabile IDs

    misp = json.loads(intel.write_export(data, tmp_path / "x.misp.json", "Wave").read_text())["Event"]
    assert misp["info"] == "Wave" and {"type": "domain", "category": "Network activity", "value": "pay-portal.invalid",
                                       "to_ids": True} .items() <= next(a for a in misp["Attribute"]
                                                                         if a["value"] == "pay-portal.invalid").items()
    assert misp["Tag"][0]["name"] == "tlp:amber"

    data["iocs"][("domain", "=evil.invalid")] = {"=HYPERLINK(1)"}
    rows = list(csv.reader(intel.write_export(data, tmp_path / "x.csv", "Wave").open(encoding="utf-8-sig"),
                           delimiter=";"))
    assert all(not c.startswith("=") for r in rows for c in r)


def test_graph_buttons(db_graph, tmp_path, monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    from gui.history_view import HistoryView
    from gui.graph_view import GraphView
    import gui.intel_dialog as idl
    db, _g = db_graph
    view = GraphView(history=HistoryView(db=db))
    view.rebuild()
    assert not view.btn_rule.isEnabled()
    view.lst_clusters.setCurrentRow(0)
    assert view.btn_rule.isEnabled()
    monkeypatch.setattr(idl.RuleDialog, "exec", lambda self: 0)
    dlg = view.generate_rule()
    assert "outside" not in dlg.lbl.text() and "cluster files matched" in dlg.lbl.text()
    out = view.export_iocs(str(tmp_path / "c.stix.json"))
    assert json.loads(open(out).read())["type"] == "bundle"
