"""
Statische Skript-Analyse: PowerShell, VBScript, JScript/JavaScript, Batch, HTA, WSF,
Python, Shell, PHP.  Skripte werden NIE ausgeführt – nur Text-Muster und
Dekodierung (Base64 / -EncodedCommand) zur Anzeige.
"""
import base64
import re

from .base import finding

# (code, severity, regex, beschreibung) – case-insensitive auf den Skripttext
RULES = [
    # Download / Nachladen
    ("script_downloader", "WARN",
     r"DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\s+-?u?r?i?\s*['\"]?https?|Start-BitsTransfer|"
     r"Net\.WebClient|XMLHTTP|ServerXMLHTTP|WinHttp\.WinHttpRequest|URLDownloadToFile|bitsadmin\s+/transfer|"
     r"(?:curl|wget)\s+[^\n|;]*https?://[^\n]*\|\s*(?:ba)?sh|certutil[^\n]{0,40}-urlcache",
     "Lädt Inhalte aus dem Internet nach"),
    # Ausführung
    ("script_exec", "WARN",
     r"\bIEX\b|Invoke-Expression|\beval\s*\(|\bExecute(?:Global)?\s*[\(\"]|WScript\.Shell|Shell\.Application|"
     r"\.ShellExecute|\.Run\s*\(|Start-Process|new\s+ActiveXObject|CreateObject\s*\(\s*[\"']WScript|"
     r"\bexec\s*\(|os\.system|subprocess\.|shell_exec|passthru|\bsystem\s*\(|popen\s*\(",
     "Führt dynamisch Code oder Programme aus"),
    # Obfuskation
    ("script_obfuscation", "WARN",
     r"FromBase64String|\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|fromCharCode|\bChrW?\s*\(\s*\d+\s*\)\s*[&+]\s*ChrW?\s*\(|"
     r"\[char\]\s*\d+\s*\+\s*\[char\]|-join\s*\(?\s*\[char|StrReverse|unescape\s*\(|atob\s*\(|"
     r"\$\{?env:comspec\}?\[|-bxor|\[System\.Text\.Encoding\]::\w+\.GetString|gzinflate|str_rot13|base64_decode",
     "Verschleiert seinen eigentlichen Code"),
    ("script_hidden_window", "WARN",
     r"-w(?:indowstyle)?\s+h(?:idden)?\b|-nop\b.*-w\s+hidden|\.Run\s*\([^,]+,\s*0\s*[,)]|CreateNoWindow\s*=\s*\$?true",
     "Startet unsichtbar im Hintergrund"),
    ("script_amsi_bypass", "CRIT",
     r"AmsiUtils|amsiInitFailed|AmsiScanBuffer|amsi\.dll|System\.Management\.Automation\.A['\"+]*msi",
     "Versucht den Windows-Virenschutz-Scan (AMSI) auszuhebeln"),
    ("script_execution_policy", "INFO",
     r"-ExecutionPolicy\s+Bypass|-ep\s+bypass|Set-ExecutionPolicy\s+Unrestricted",
     "Umgeht die PowerShell-Ausführungsrichtlinie"),
    ("script_persistence", "WARN",
     r"CurrentVersion\\Run|schtasks\s+/create|Register-ScheduledTask|New-Service|\\Startup\\|"
     r"crontab\s+-|/etc/cron|systemctl\s+enable|\.bashrc|HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion",
     "Richtet Autostart ein"),
    ("script_webshell", "CRIT",
     r"(?:eval|assert|system|passthru|shell_exec)\s*\(\s*(?:base64_decode\s*\()?\s*\$_(?:POST|GET|REQUEST|COOKIE)|"
     r"Request\.Item\s*\[.+?\]\s*\)|Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter",
     "Webshell-Muster (führt Befehle aus Web-Anfragen aus)"),
    ("script_credential", "CRIT",
     r"Invoke-Mimikatz|sekurlsa|lsass\.exe|Get-Credential\s*\|\s*|ConvertFrom-SecureString|"
     r"Login Data|\\Google\\Chrome\\User Data|logins\.json|key4\.db|wallet\.dat",
     "Greift auf Passwörter / Browser-Anmeldedaten zu"),
    ("script_defense_evasion", "CRIT",
     r"Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|Remove-Item[^\n]*\\Windows Defender|"
     r"wevtutil\s+cl|Clear-EventLog|vssadmin\s+delete|bcdedit[^\n]*recoveryenabled",
     "Schaltet Schutz ab / löscht Spuren"),
    ("script_reflective_load", "CRIT",
     r"\[System\.Reflection\.Assembly\]::Load|Reflection\.Assembly::Load\(|VirtualAlloc[^\n]{0,80}Marshal|"
     r"GetDelegateForFunctionPointer|kernel32\.dll[^\n]{0,60}DllImport",
     "Lädt Programmcode direkt in den Speicher (dateilos)"),
    ("script_ransom", "CRIT",
     r"\.(?:encrypted|locked|crypt)\b['\"]?\s*[;)]|your files (?:have been|are) encrypted|decrypt(?:ion)? key|"
     r"AesCryptoServiceProvider[^\n]*Get-ChildItem|Get-ChildItem[^\n]*-Recurse[^\n]*\|\s*ForEach[^\n]*Encrypt",
     "Ransomware-Muster (Dateien verschlüsseln / Lösegeld)"),
]

_CRE = [(c, s, re.compile(rx, re.I), d) for c, s, rx, d in RULES]

ENC_CMD = re.compile(r"-e(?:c|nc|nco|ncod|ncode|ncodedcommand)?\s+([A-Za-z0-9+/=]{40,})", re.I)
B64_CALL = re.compile(r"FromBase64String\s*\(\s*['\"]([A-Za-z0-9+/=]{40,})['\"]", re.I)


def _decode_payloads(text):
    """Dekodiert -EncodedCommand / FromBase64String-Literale nur zur Anzeige."""
    out = []
    for rx, utf16 in ((ENC_CMD, True), (B64_CALL, False)):
        for m in rx.finditer(text):
            raw = m.group(1)
            try:
                dec = base64.b64decode(raw + "=" * (-len(raw) % 4))
            except Exception:
                continue
            if utf16:
                txt = dec.decode("utf-16-le", "replace")
            else:
                txt = dec.decode("utf-8", "replace") if dec[:2] != b"MZ" else "[Windows-Programm (MZ)]"
            out.append({"source": m.group(0)[:40] + "…", "decoded": txt[:2000], "is_pe": dec[:2] == b"MZ"})
            if len(out) >= 10:
                return out
    return out


def _obfuscation_metrics(text):
    lines = text.splitlines() or [""]
    longest = max(len(l) for l in lines)
    n = max(1, len(text))
    specials = sum(text.count(c) for c in "^`+&%$[]{}()'\"")
    return {
        "lines": len(lines),
        "longest_line": longest,
        "special_char_ratio": round(specials / n, 3),
        "caret_count": text.count("^"),
        "backtick_count": text.count("`"),
        "concat_count": len(re.findall(r"['\"]\s*[+&]\s*['\"]", text)),
    }


class ScriptAnalyzer:
    name = "script"

    def applies(self, ctx):
        return ctx.category == "script" or ctx.subtype in ("hta", "wsf")

    def run(self, ctx):
        text = ctx.text
        findings, d = [], {"language": ctx.subtype}
        hits = {}
        for code, sev, rx, desc in _CRE:
            ms = [m.group(0)[:100] for m in rx.finditer(text)][:8]
            if ms:
                hits[code] = ms
                findings.append(finding(code, f"{desc}: „{ms[0][:60]}“" + (f" (+{len(ms) - 1})" if len(ms) > 1 else ""), sev))
        d["matches"] = hits

        m = _obfuscation_metrics(text)
        d["metrics"] = m
        if m["longest_line"] > 2000 and m["special_char_ratio"] > 0.08:
            findings.append(finding("script_obfuscation", f"Extrem lange, zeichenlastige Zeile ({m['longest_line']:,} Zeichen)", "WARN"))
        if ctx.subtype == "batch" and m["caret_count"] > 40:
            findings.append(finding("script_obfuscation", f"{m['caret_count']} ^-Zeichen (Batch-Verschleierung)", "WARN"))
        if ctx.subtype == "powershell" and m["backtick_count"] > 30:
            findings.append(finding("script_obfuscation", f"{m['backtick_count']} Backticks (PowerShell-Verschleierung)", "WARN"))
        if m["concat_count"] > 50:
            findings.append(finding("script_obfuscation", f"{m['concat_count']} String-Verkettungen (Zerstückelung von Befehlen)", "WARN"))

        decoded = _decode_payloads(text)
        if decoded:
            d["decoded_payloads"] = decoded
            for p in decoded:
                if p["is_pe"]:
                    findings.append(finding("base64_executable", "Skript enthält ein Base64-kodiertes Windows-Programm", "CRIT"))
                    break
            # dekodierte Nutzlast ebenfalls gegen die Regeln prüfen
            inner = "\n".join(p["decoded"] for p in decoded)
            for code, sev, rx, desc in _CRE:
                mm = rx.search(inner)
                if mm and code not in hits:
                    findings.append(finding(code, f"{desc} (in dekodierter Nutzlast): „{mm.group(0)[:60]}“", sev))

        # Kombination: Nachladen + Ausführen = klassischer Downloader
        if "script_downloader" in hits and ("script_exec" in hits or "script_hidden_window" in hits):
            findings.append(finding("script_dropper", "Lädt Code herunter und führt ihn aus (Downloader/Dropper)", "CRIT"))

        # Authenticode-Signaturblock (z. B. Microsoft-Module): eine Stufe milder.
        # Die Signatur wird statisch NICHT geprüft – ein kopierter Block bleibt sichtbar.
        d["signature_block"] = "# SIG # Begin signature block" in text
        if d["signature_block"]:
            findings = [dict(f, severity={"CRIT": "WARN", "WARN": "INFO"}.get(f["severity"], f["severity"]),
                             desc=f["desc"] + " (Skript mit Signaturblock, ungeprüft)") for f in findings]
        return {"data": d, "findings": findings}
