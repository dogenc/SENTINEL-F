"""
HTML / SVG / HTA / MHT: HTML-Smuggling, Phishing-Formulare, versteckte iframes,
Weiterleitungen und verschleiertes JavaScript. Nur Textanalyse, kein Rendern.
"""
import re
from urllib.parse import urlparse

from .base import finding

RX = {
    "script_tags": re.compile(r"<script\b", re.I),
    "iframes": re.compile(r"<iframe\b[^>]*>", re.I),
    "forms": re.compile(r"<form\b[^>]*>", re.I),
    "password_inputs": re.compile(r"<input\b[^>]*type\s*=\s*['\"]?password", re.I),
    "meta_refresh": re.compile(r"<meta\b[^>]*http-equiv\s*=\s*['\"]?refresh[^>]*>", re.I),
    "event_handlers": re.compile(r"\bon(?:load|error|mouseover|click|focus)\s*=", re.I),
    "data_uris": re.compile(r"data:[\w/+.-]+;base64,[A-Za-z0-9+/=]{200,}", re.I),
    "external_scripts": re.compile(r"<script\b[^>]*src\s*=\s*['\"]?(https?:)?//", re.I),
}

SMUGGLING = re.compile(
    r"(?:new\s+Blob\s*\(|msSaveOrOpenBlob|createObjectURL)[\s\S]{0,4000}?(?:\.download\s*=|download\s*=|msSaveOrOpenBlob)"
    r"|(?:atob\s*\([\s\S]{0,400}?new\s+Blob)", re.I)
JS_OBF = re.compile(r"eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)|document\.write\s*\(\s*(?:unescape|atob)|"
                    r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){30,}|_0x[0-9a-f]{4,6}", re.I)
BRANDS = ("microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint", "paypal", "apple id", "icloud",
          "sparkasse", "volksbank", "dhl", "docusign", "adobe", "google", "amazon", "netflix", "ing-diba", "commerzbank",
          "deutsche bank", "postbank", "n26", "dropbox", "wetransfer")


class WebAnalyzer:
    name = "web"

    def applies(self, ctx):
        return ctx.category == "web" or ctx.ext in (".html", ".htm", ".svg", ".hta", ".mht", ".mhtml", ".xhtml", ".shtml")

    def run(self, ctx):
        text = ctx.text
        low = text.lower()
        d, findings = {}, []
        counts = {k: len(rx.findall(text)) for k, rx in RX.items()}
        d["counts"] = counts

        if SMUGGLING.search(text):
            findings.append(finding("html_smuggling",
                                    "HTML-Smuggling: Seite baut eine Datei im Browser zusammen und startet den Download "
                                    "(umgeht Mail- und Proxy-Filter)", "CRIT"))
        big_data = [m.group(0)[:60] for m in RX["data_uris"].finditer(text)]
        if big_data and any(t in low for t in ("application/octet-stream", "application/x-msdownload",
                                                "application/zip", "application/x-iso")):
            findings.append(finding("html_smuggling", "Große eingebettete Binärdatei (data:-URI) zum Herunterladen", "CRIT"))

        if JS_OBF.search(text):
            findings.append(finding("script_obfuscation", "Verschleiertes JavaScript (eval/atob/Hex-Ketten)", "WARN"))

        # Phishing: Passwortfeld + Formular an fremde Adresse + Markenname
        actions = re.findall(r"<form\b[^>]*action\s*=\s*['\"]?([^'\" >]+)", text, re.I)
        ext_actions = [a for a in actions if a.lower().startswith(("http", "//"))]
        d["form_actions"] = actions[:20]
        brands = [b for b in BRANDS if b in low]
        d["brands_mentioned"] = brands
        if counts["password_inputs"]:
            if ctx.p.suffix.lower() in (".html", ".htm", ".shtml", ".svg") and (ext_actions or "fetch(" in low or "xmlhttprequest" in low):
                sev = "CRIT" if brands else "WARN"
                findings.append(finding("phishing_form",
                                        "Lokale HTML-Datei mit Passwortfeld, die Daten nach außen sendet"
                                        + (f" – gibt sich als {', '.join(brands[:3])} aus" if brands else ""), sev))
        if "api.telegram.org/bot" in low or "discord.com/api/webhooks" in low:
            findings.append(finding("phishing_exfil", "Sendet Daten an Telegram-Bot/Discord-Webhook (typisch für Phishing-Kits)", "CRIT"))

        hidden_iframes = [i for i in RX["iframes"].findall(text)
                          if re.search(r"(?:width|height)\s*=\s*['\"]?[01]\b|display\s*:\s*none|visibility\s*:\s*hidden", i, re.I)]
        if hidden_iframes:
            findings.append(finding("hidden_iframe", f"{len(hidden_iframes)} unsichtbare(r) iframe(s)", "WARN"))
        if counts["meta_refresh"]:
            m = re.search(r"url\s*=\s*['\"]?([^'\" >]+)", RX["meta_refresh"].search(text).group(0), re.I)
            tgt = m.group(1) if m else "?"
            d["redirect"] = tgt
            host = urlparse(tgt).netloc
            if host:
                findings.append(finding("web_redirect", f"Automatische Weiterleitung nach {host}", "INFO"))
        if ctx.subtype == "svg" and (counts["script_tags"] or counts["event_handlers"]):
            findings.append(finding("svg_script", "SVG-Bild enthält ausführbares JavaScript", "WARN"))
        if ctx.subtype == "hta" or "<hta:application" in low:
            # Die Skript-Regeln laufen für HTA zusätzlich über den ScriptAnalyzer.
            findings.append(finding("hta_file", "HTML-Application: läuft mit vollen Benutzerrechten außerhalb des Browsers", "WARN"))
        return {"data": d, "findings": findings}
