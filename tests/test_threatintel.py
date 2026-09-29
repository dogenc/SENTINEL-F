"""Hash-Abfrage (opt-in, nur Hashes) gegen einen lokalen Schein-Dienst."""
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core import threatintel as ti
from core.history import HistoryDB

BAD = "a" * 64
GOOD = "b" * 64
NEW = "c" * 64
SEEN = []


class _Svc(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode())

    def do_GET(self):
        SEEN.append(("GET", self.path, dict(self.headers)))
        h = self.path.rsplit("/", 1)[-1]
        if self.path.startswith("/circl/"):
            if h == GOOD:
                return self._json(200, {"FileName": "notepad.exe", "ProductName": "Windows", "source": "NSRL"})
            return self._json(404, {"message": "Non existing"})
        if self.path.startswith("/vt/"):
            if self.headers.get("x-apikey") != "VTKEY":
                return self._json(401, {"error": {"message": "wrong key"}})
            if h == BAD:
                return self._json(200, {"data": {"attributes": {
                    "last_analysis_stats": {"malicious": 41, "suspicious": 2, "undetected": 27, "harmless": 0},
                    "popular_threat_classification": {"suggested_threat_label": "trojan.agenttesla/msil"},
                    "names": ["invoice.exe"], "first_submission_date": 1700000000}}})
            return self._json(404, {"error": {"code": "NotFoundError"}})

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        SEEN.append(("POST", self.path, body))
        if self.headers.get("Auth-Key") != "MBKEY":
            return self._json(401, {})
        if BAD in body:
            return self._json(200, {"query_status": "ok", "data": [{"signature": "AgentTesla", "tags": ["exe", "stealer"],
                                                                     "first_seen": "2024-01-01 10:00:00"}]})
        return self._json(200, {"query_status": "hash_not_found"})

    def log_message(self, *a):
        pass


@pytest.fixture
def svc(monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), _Svc)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    monkeypatch.setattr(ti, "CIRCL_URL", base + "/circl/{h}")
    monkeypatch.setattr(ti, "VT_URL", base + "/vt/{h}")
    monkeypatch.setattr(ti, "MB_URL", base + "/mb")
    SEEN.clear()
    yield {"enabled": True, "vt_key": "VTKEY", "mb_key": "MBKEY"}
    srv.shutdown()


def test_malicious_file(svc):
    r = ti.lookup(BAD, cfg=svc)
    assert r["virustotal"]["status"] == "malicious" and r["virustotal"]["detections"] == "41/70"
    assert "agenttesla" in r["virustotal"]["detail"]
    assert r["malwarebazaar"]["status"] == "malicious" and r["malwarebazaar"]["family"] == "AgentTesla"
    assert r["circl"]["status"] == "unknown"
    assert ti.summary(r) == "malicious"


def test_known_good_and_unknown(svc):
    assert ti.summary(ti.lookup(GOOD, cfg=svc)) == "known_good"
    r = ti.lookup(NEW, cfg=svc)
    assert {k: v["status"] for k, v in r.items()} == {"circl": "unknown", "virustotal": "unknown",
                                                       "malwarebazaar": "unknown"}


def test_only_hashes_leave_the_machine(svc):
    ti.lookup(BAD, cfg=svc)
    for method, path, extra in SEEN:
        payload = path + (extra if isinstance(extra, str) else "")
        assert BAD in payload
        assert len(payload) < 400                       # keine Dateiinhalte, nur Hash + Parameter


def test_missing_keys_are_skipped(svc):
    r = ti.lookup(BAD, cfg={"enabled": True, "vt_key": "", "mb_key": ""})
    assert r["virustotal"]["status"] == "skipped" and r["malwarebazaar"]["status"] == "skipped"


def test_disabled_by_default():
    assert ti.settings()["enabled"] is False or os.environ.get("DGKN_HASH_LOOKUP") == "1"


def test_cache(svc, tmp_path, monkeypatch):
    monkeypatch.setattr(ti, "settings", lambda: svc)
    db = HistoryDB(tmp_path / "h.db")
    first = ti.cached_lookup(db, BAD, cfg=svc)
    n = len(SEEN)
    second = ti.cached_lookup(db, BAD, cfg=svc)
    assert second.get("_cached") and len(SEEN) == n            # kein zweiter Netzzugriff
    assert second["virustotal"] == first["virustotal"]
    ti.cached_lookup(db, BAD, force=True, cfg=svc)
    assert len(SEEN) > n


def test_intel_tab_detective_and_report(svc, tmp_path, monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    monkeypatch.setattr(ti, "settings", lambda: svc)
    from engines import run_forensic
    from engines.detective import build_evidence, narrative
    from core.report import file_report_html
    from gui.intel_widget import IntelView
    p = tmp_path / "x.txt"
    p.write_text("x")
    res = run_forensic(str(p))
    res["hashes"]["sha256"] = BAD
    view = IntelView(lookup_fn=lambda h: ti.lookup(h, cfg=svc))
    got = []
    view.intelChanged.connect(got.append)
    view.set_result(res)
    assert view.btn.isEnabled()
    view.run_lookup(run_async=False)
    app.processEvents()
    assert "MALICIOUS" in view.lbl.text() and view.table.rowCount() == 3 and got
    ev = build_evidence(res)
    assert any(e["kind"] == "intel" and "malicious" in e["text"] for e in ev)
    assert "Externe Threat-Intel" in narrative(ev, "de")
    assert "Threat intelligence (hash lookup)" in file_report_html(res)
