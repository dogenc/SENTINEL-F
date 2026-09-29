"""Signierte Berichte: Ed25519 (.sig) und RFC-3161-Zeitstempel (.tsr)."""
import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core import signing


@pytest.fixture
def report(tmp_path):
    p = tmp_path / "bericht.html"
    p.write_text("<html>Befund: CRITICAL</html>", encoding="utf-8")
    return p


def test_sign_and_verify(report):
    doc = signing.sign_file(report, signer="A. Analyst")
    assert doc["alg"] == "Ed25519" and doc["sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()
    res = signing.verify_file(report)
    assert res["valid"] and res["own_key"] and res["signer"] == "A. Analyst"
    assert res["key_fingerprint"] == signing.own_fingerprint()


def test_tampered_report_is_detected(report):
    signing.sign_file(report, signer="A")
    report.write_text("<html>Befund: CLEAN</html>", encoding="utf-8")
    res = signing.verify_file(report)
    assert not res["valid"] and "MODIFIED" in res["reason"]


def test_tampered_signature_metadata_is_detected(report):
    signing.sign_file(report, signer="A")
    sig = report.with_name(report.name + ".sig")
    doc = json.loads(sig.read_text())
    doc["signer"] = "Jemand anderes"
    sig.write_text(json.dumps(doc))
    res = signing.verify_file(report)
    assert not res["valid"] and "altered" in res["reason"]


def test_foreign_key_is_flagged(report, tmp_path):
    signing.sign_file(report, signer="Kollege", key_dir=tmp_path / "other")
    res = signing.verify_file(report)
    assert res["valid"] and not res["own_key"]


def test_key_is_persistent_and_private(tmp_path):
    k1 = signing.own_fingerprint(tmp_path / "k")
    assert signing.own_fingerprint(tmp_path / "k") == k1
    priv = tmp_path / "k" / "ed25519_private.key"
    if os.name != "nt":
        assert oct(priv.stat().st_mode & 0o777) == "0o600"
    assert (tmp_path / "k" / "ed25519_public.pem").read_text().startswith("-----BEGIN PUBLIC KEY-----")


def test_missing_signature(report):
    assert "no signature" in signing.verify_file(report)["reason"]


def _fake_tsr(digest, status=0):
    t = signing._tlv
    tst_info = t(0x30, signing._int(1) + t(0x06, b"\x2b\x06\x01") +
                 t(0x30, t(0x30, signing.SHA256_OID + b"\x05\x00") + t(0x04, digest)) +
                 signing._int(42) + t(0x18, b"20260929101500Z"))
    token = t(0x30, t(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02") + t(0xA0, t(0x04, tst_info)))
    return t(0x30, t(0x30, signing._int(status)) + token)


def test_timestamp_request_structure():
    d = hashlib.sha256(b"x").digest()
    req = signing.timestamp_request(d, nonce=7)
    assert req[0] == 0x30 and signing.SHA256_OID in req and b"\x04\x20" + d in req and req.endswith(b"\x01\x01\xff")


def test_timestamp_roundtrip_with_local_tsa(report):
    digest = hashlib.sha256(report.read_bytes()).digest()

    class TSA(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            assert self.headers["Content-Type"] == "application/timestamp-query" and digest in body
            data = _fake_tsr(digest)
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), TSA)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    info = signing.request_timestamp(report, f"http://127.0.0.1:{srv.server_port}/tsr")
    assert info["granted"] and info["hash_match"] and info["gen_time"] == "2026-09-29 10:15:00 UTC"
    signing.sign_file(report, signer="A")
    ts = signing.verify_file(report)["timestamp"]
    assert ts["hash_match"] and ts["gen_time"].startswith("2026-09-29")
    assert not signing.parse_timestamp_response(_fake_tsr(digest, status=2), digest)["granted"]


def test_report_dialog_signs(tmp_path, monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    import gui.report_dialog as rd
    out = tmp_path / "r.html"
    monkeypatch.setattr(rd, "ask_examiner", lambda parent: "Tester")
    monkeypatch.setattr(rd.QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), "HTML report (*.html)"))
    shown = []
    monkeypatch.setattr(rd.QMessageBox, "information", lambda *a, **k: shown.append(a[2]))
    monkeypatch.setattr(rd.QMessageBox, "warning", lambda *a, **k: shown.append(a[2]))
    rd.save_report(None, lambda ex: f"<html>{ex}</html>", "x")
    assert "Signed (Ed25519)" in shown[-1] and out.with_name("r.html.sig").exists()
    res = rd.verify_dialog(None, str(out))
    assert res["valid"] and "this workstation's key" in shown[-1]
