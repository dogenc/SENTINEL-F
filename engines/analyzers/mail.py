"""
E-Mails (.eml): Absender-Fälschung, SPF/DKIM/DMARC-Ergebnis, Übertragungsweg,
gefährliche Anhänge, getarnte Links (Linktext ≠ Ziel).
"""
import email
import email.policy
import re
from email.utils import getaddresses, parseaddr
from urllib.parse import urlparse

from core.filetype import DANGEROUS_EXTS
from .base import finding

HREF = re.compile(r"<a\b[^>]*href\s*=\s*['\"]([^'\"]+)['\"][^>]*>(.*?)</a>", re.I | re.S)
TAG = re.compile(r"<[^>]+>")


def _domain(addr):
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


class EmailAnalyzer:
    name = "email"

    def applies(self, ctx):
        return ctx.category == "email" or ctx.ext == ".eml"

    def run(self, ctx):
        msg = email.message_from_bytes(ctx.data, policy=email.policy.default)
        h = lambda k: str(msg.get(k, "") or "")
        frm = parseaddr(h("From"))
        reply = parseaddr(h("Reply-To"))
        ret = parseaddr(h("Return-Path"))
        d = {
            "from": h("From"), "to": [a for _, a in getaddresses(msg.get_all("To", []) or [])][:50],
            "subject": h("Subject"), "date": h("Date"), "message_id": h("Message-ID"),
            "reply_to": h("Reply-To"), "return_path": h("Return-Path"), "x_mailer": h("X-Mailer") or h("User-Agent"),
            "received": [str(r)[:300] for r in (msg.get_all("Received") or [])][:30],
            "auth_results": h("Authentication-Results")[:1000],
        }
        findings = []
        fdom = _domain(frm[1])
        if reply[1] and _domain(reply[1]) and _domain(reply[1]) != fdom:
            findings.append(finding("email_reply_mismatch", f"Antworten gehen an {reply[1]}, nicht an den Absender {frm[1]}", "WARN"))
        if ret[1] and _domain(ret[1]) and fdom and _domain(ret[1]) != fdom and not _domain(ret[1]).endswith("." + fdom):
            findings.append(finding("email_sender_mismatch", f"Return-Path {ret[1]} ≠ From {frm[1]}", "INFO"))
        # Anzeigename enthält eine andere Adresse („PayPal <x@evil.tld>“)
        disp = frm[0] or ""
        m = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", disp)
        if m and _domain(m.group(0)) != fdom:
            findings.append(finding("email_display_spoof", f"Anzeigename täuscht Adresse {m.group(0)} vor, echter Absender {frm[1]}", "CRIT"))
        auth = d["auth_results"].lower()
        for mech in ("spf", "dkim", "dmarc"):
            mm = re.search(mech + r"\s*=\s*(\w+)", auth)
            if mm:
                d[f"{mech}_result"] = mm.group(1)
                if mm.group(1) in ("fail", "softfail", "permerror"):
                    findings.append(finding("email_auth_fail", f"{mech.upper()}-Prüfung fehlgeschlagen ({mm.group(1)})",
                                            "CRIT" if mech == "dmarc" else "WARN"))

        atts = []
        for part in msg.walk():
            fn = part.get_filename()
            if not fn and part.get_content_disposition() != "attachment":
                continue
            payload = part.get_payload(decode=True) or b""
            ext = "." + fn.rsplit(".", 1)[-1].lower() if fn and "." in fn else ""
            a = {"filename": fn, "content_type": part.get_content_type(), "size": len(payload),
                 "magic": payload[:8].hex(), "is_pe": payload[:2] == b"MZ"}
            import hashlib
            a["sha256"] = hashlib.sha256(payload).hexdigest()
            atts.append(a)
            if ext in DANGEROUS_EXTS or a["is_pe"]:
                findings.append(finding("email_dangerous_attachment", f"Gefährlicher Anhang: {fn}", "CRIT"))
            elif ext in (".zip", ".7z", ".rar", ".iso", ".img", ".html", ".htm", ".svg", ".one", ".pdf.html"):
                findings.append(finding("email_risky_attachment", f"Häufig missbrauchter Anhang-Typ: {fn}", "WARN"))
            if fn and len(fn.split(".")) >= 3 and "." + fn.split(".")[-2].lower() in (".pdf", ".doc", ".docx", ".xlsx", ".jpg"):
                findings.append(finding("double_extension", f"Anhang mit Doppel-Endung: {fn}", "CRIT"))
        d["attachments"] = atts

        # Links: sichtbarer Text zeigt andere Domain als das echte Ziel
        html = ""
        body = msg.get_body(preferencelist=("html",))
        if body is not None:
            try:
                html = body.get_content()
            except Exception:
                html = ""
        links, masked = [], []
        for href, label in HREF.findall(html)[:300]:
            text = TAG.sub("", label).strip()
            links.append({"href": href[:300], "text": text[:120]})
            shown = re.search(r"(?:https?://)?([\w-]+(?:\.[\w-]+)+)", text)
            real = urlparse(href).netloc.lower()
            if shown and real and "." in shown.group(1) and shown.group(1).lower() not in real and real not in shown.group(1).lower():
                masked.append(f"„{text[:40]}“ → {real}")
        d["links"] = links[:100]
        if masked:
            findings.append(finding("email_masked_link", f"{len(masked)} getarnte(r) Link(s): {masked[0]}", "CRIT"))
        return {"data": d, "findings": findings}
