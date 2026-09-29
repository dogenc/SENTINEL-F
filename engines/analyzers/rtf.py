"""
RTF: eingebettete OLE-Objekte, automatische Aktualisierung (\\objupdate),
Equation-Editor-Exploit (CVE-2017-11882 / CVE-2018-0802), Verschleierung.
"""
import re

from .base import finding


class RtfAnalyzer:
    name = "rtf"

    def applies(self, ctx):
        return ctx.subtype == "rtf"

    def run(self, ctx):
        raw = ctx.data
        low = raw.lower()
        d = {
            "objects": low.count(b"\\object"),
            "objdata": low.count(b"\\objdata"),
            "objupdate": low.count(b"\\objupdate"),
            "bin_blocks": low.count(b"\\bin"),
            "classes": sorted({m.decode("latin-1") for m in re.findall(rb"\\objclass\s+([\w.]+)", raw, re.I)})[:20],
        }
        findings = []
        if d["objdata"]:
            findings.append(finding("rtf_ole_object", f"{d['objdata']} eingebettete(s) OLE-Objekt(e)", "WARN"))
        if d["objupdate"]:
            findings.append(finding("rtf_autoupdate", "\\objupdate: Objekt wird beim Öffnen automatisch geladen", "CRIT"))
        # Equation Editor: Klassenname im Klartext oder hex-kodiert in \objdata
        eq_hex = b"4571756174696f6e2e33"  # "Equation.3"
        compact = re.sub(rb"[\s\r\n]", b"", low)
        if b"equation.3" in low or eq_hex in compact or b"0002ce02" in compact:
            findings.append(finding("rtf_equation_exploit", "Equation-Editor-Objekt (Exploit CVE-2017-11882/2018-0802)", "CRIT"))
        if re.search(rb"\\objclass\s+(?:package|htmlfile|word\.document\.8|excel\.sheet)", low):
            findings.append(finding("rtf_ole_object", "OLE-Paket/HTML-Objekt eingebettet (kann Dateien ablegen)", "WARN"))
        # Verschleierung: absichtlich kaputte Kontrollwörter, riesige Hex-Blöcke
        if len(re.findall(rb"\\[a-z]{1,32}-?\d*\\[\\{}]", raw)) > 500 or re.search(rb"[0-9a-f]{20000,}", compact):
            findings.append(finding("rtf_obfuscation", "Stark verschleierte RTF-Struktur / großer Hex-Block", "WARN"))
        if ctx.ext in (".doc", ".docx") and ctx.subtype == "rtf":
            findings.append(finding("extension_mismatch", "RTF-Datei als Word-Dokument getarnt (häufig bei Exploits)", "WARN"))
        return {"data": d, "findings": findings}
