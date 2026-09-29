"""Gemeinsamer Ablauf zum Speichern von Berichten (Bearbeiter merken, HTML/PDF wählen)."""
import datetime
import re

from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QFileDialog, QInputDialog, QMessageBox

from config.settings import DATA_DIR, REPORT_DIR
from core.utils import LOG


def _settings():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return QSettings(str(DATA_DIR / "report.ini"), QSettings.Format.IniFormat)


def ask_examiner(parent):
    s = _settings()
    name, ok = QInputDialog.getText(parent, "Forensic report", "Examiner (name / ID, shown in the report):",
                                    text=s.value("examiner", "", type=str))
    if not ok:
        return None
    s.setValue("examiner", name.strip())
    return name.strip()


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text or "report").strip("_")[:60] or "report"


def save_report(parent, build_html, base_name):
    """build_html(examiner) → str. Fragt Bearbeiter und Ziel ab, schreibt Bericht + .sha256."""
    from core.report import write_report
    examiner = ask_examiner(parent)
    if examiner is None:
        return None
    default = REPORT_DIR / f"{safe_name(base_name)}_{datetime.datetime.now():%Y%m%d_%H%M%S}.html"
    path, flt = QFileDialog.getSaveFileName(parent, "Save forensic report", str(default),
                                            "HTML report (*.html);;PDF report (*.pdf)")
    if not path:
        return None
    if "pdf" in flt.lower() and not path.lower().endswith(".pdf"):
        path += ".pdf"
    try:
        digest = write_report(build_html(examiner), path)
    except Exception as e:
        QMessageBox.critical(parent, "Report failed", str(e))
        return None
    extra = sign_and_stamp(path, examiner)
    LOG.log(f"Report written: {path} (SHA-256 {digest[:16]}…)", "OK")
    QMessageBox.information(parent, "Report", f"Report written:\n{path}\n\nSHA-256 (also in .sha256 file):\n{digest}"
                            + (f"\n\n{extra}" if extra else ""))
    return path


def sign_and_stamp(path, examiner):
    """Signatur (Ed25519) und optional RFC-3161-Zeitstempel. → Hinweistext"""
    from config.settings import REPORT_SIGN, REPORT_TSA_URL
    notes = []
    if REPORT_SIGN:
        try:
            from core.signing import sign_file
            sig = sign_file(path, signer=examiner)
            notes.append(f"Signed (Ed25519) · key {sig['key_fingerprint']} → .sig")
        except Exception as e:
            notes.append(f"⚠ Signing failed: {e}")
    if REPORT_TSA_URL:
        try:
            from core.signing import request_timestamp
            ts = request_timestamp(path, REPORT_TSA_URL)
            notes.append(f"Time-stamped by {REPORT_TSA_URL}: {ts['gen_time']} → .tsr")
        except Exception as e:
            notes.append(f"⚠ Time-stamp failed: {e}")
    for n in notes:
        LOG.log(n, "WARN" if n.startswith("⚠") else "OK")
    return "\n".join(notes)


def verify_dialog(parent, path=None):
    """Bericht auswählen und Signatur/Zeitstempel prüfen. → Ergebnis-dict"""
    from core.signing import verify_file, own_fingerprint, KEY_DIR
    if path is None:
        path, _ = QFileDialog.getOpenFileName(parent, "Verify signed report", str(REPORT_DIR),
                                              "Reports (*.html *.pdf);;All files (*.*)")
        if not path:
            return None
    res = verify_file(path)
    lines = [("✔ " if res["valid"] else "✘ ") + res["reason"]]
    if res["signer"] is not None:
        lines.append(f"Signed by: {res['signer'] or '—'} · at {res['signed_at']}")
        lines.append(f"Key: {res['key_fingerprint']}" + ("  (this workstation's key)" if res["own_key"] else
                                                          "  (FOREIGN key – compare with the sender's fingerprint)"))
    ts = res.get("timestamp")
    if ts:
        lines.append(f"RFC 3161 time-stamp: {ts['gen_time']} · hash {'matches' if ts['hash_match'] else 'DOES NOT match'}"
                     " (full chain check: openssl ts -verify)")
    try:
        lines.append(f"\nYour public key: {own_fingerprint()}  ({KEY_DIR / 'ed25519_public.pem'})")
    except Exception:
        pass
    box = QMessageBox.information if res["valid"] else QMessageBox.warning
    box(parent, "Report verification", "\n".join(lines))
    return res
