"""
Basisanalyse für JEDE Datei:
  * Entropie gesamt + Blockprofil (gepackte/verschlüsselte Bereiche)
  * Dateinamen-Tricks (Doppel-Endung, RTLO, Leerzeichen-Padding)
  * Typ ≠ Endung (getarnte Programme)
  * Eingebettete Signaturen (EXE in Bild, Polyglot) + angehängte Daten
  * Strings + IOCs (URLs, IPs, Domains, Mails, Pfade, Registry, Base64, Krypto-Wallets)
  * Verdächtige Befehle (LOLBins, Ransomware-Vorbereitung)
  * Mark-of-the-Web (Zone.Identifier) — woher kam die Datei?
"""
import base64
import ipaddress
import math
import re
import struct
from collections import Counter

from core.filetype import DANGEROUS_EXTS
from . import limits
from .base import finding

COMPRESSED_CATEGORIES = {"archive", "media", "image", "font", "container"}
COMPRESSED_SUBTYPES = {"pdf", "docx", "xlsx", "pptx", "jar", "apk", "odf", "epub", "appx", "vsix", "onenote"}

RTLO = "‮"
BIDI_CHARS = {"‮", "‭", "‪", "‫", "⁦", "⁧", "⁨", "‏"}
DECOY_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".gif",
              ".mp3", ".mp4", ".zip", ".rtf", ".ppt", ".pptx", ".csv", ".html", ".odt", ".avi"}

# ── Regex ──────────────────────────────────────────────────────────────────
RX = {
    "url": re.compile(rb"\b(?:https?|ftp|hxxps?)://[\w\-.~%]+(?::\d{1,5})?(?:/[\w\-./?%&=+#~:@!$,;*]*)?", re.I),
    "ipv4": re.compile(rb"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"),
    "email": re.compile(rb"\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})*\.[a-z]{2,24}\b", re.I),
    "win_path": re.compile(rb"\b[a-z]:\\(?:[^\\/:*?\"<>|\r\n\x00]{1,120}\\)*[^\\/:*?\"<>|\r\n\x00]{1,120}", re.I),
    "unc_path": re.compile(rb"\\\\[\w.\-]{2,63}\\[\w$.\-]{1,80}(?:\\[^\\\r\n\x00\"<>|]{1,80})*"),
    "registry": re.compile(rb"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]{4,20})\\[\w\\ .\-{}]{3,200}", re.I),
    "base64": re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])"),
    "btc": re.compile(rb"\b(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "xmr": re.compile(rb"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "onion": re.compile(rb"\b[a-z2-7]{16,56}\.onion\b", re.I),
}

# Befehls-Muster, die bei legitimen Dateien selten vorkommen
COMMANDS = [
    ("ransom_prep", "CRIT", rb"vssadmin(?:\.exe)?\s+delete\s+shadows|wmic(?:\.exe)?\s+shadowcopy\s+delete|"
                            rb"bcdedit(?:\.exe)?\s+/set\s+\{?default\}?\s+recoveryenabled\s+no|wbadmin\s+delete\s+catalog",
     "Löscht Schattenkopien/Backups (typische Ransomware-Vorbereitung)"),
    ("defender_tamper", "CRIT", rb"Set-MpPreference\s+-Disable|Add-MpPreference\s+-Exclusion|"
                                rb"DisableAntiSpyware|DisableRealtimeMonitoring",
     "Schaltet Microsoft Defender ab / setzt Ausnahmen"),
    ("lolbin", "WARN", rb"certutil(?:\.exe)?\s+-(?:urlcache|decode|encode)|bitsadmin(?:\.exe)?\s+/transfer|"
                       rb"mshta(?:\.exe)?\s+(?:https?|vbscript|javascript)|regsvr32(?:\.exe)?\s+/s\s+/n\s+/u\s+/i:|"
                       rb"rundll32(?:\.exe)?\s+javascript:|msiexec(?:\.exe)?\s+/q\S*\s+/i\s+https?",
     "Missbrauch von Windows-Bordmitteln (LOLBin) zum Laden/Dekodieren"),
    ("encoded_powershell", "WARN", rb"powershell(?:\.exe)?[^\r\n]{0,80}\s-(?:e|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{20,}",
     "PowerShell mit Base64-kodiertem Befehl"),
    ("persistence", "WARN", rb"schtasks(?:\.exe)?\s+/create|\\CurrentVersion\\Run(?:Once)?\\?|"
                            rb"\\Winlogon\\(?:Userinit|Shell)|sc(?:\.exe)?\s+create\s",
     "Autostart/Persistenz-Mechanismus"),
    ("credential_access", "CRIT", rb"sekurlsa::|lsadump::|mimikatz|procdump[^\r\n]{0,40}lsass|comsvcs(?:\.dll)?[^\r\n]{0,30}MiniDump",
     "Zugriff auf Anmeldedaten (LSASS / Mimikatz)"),
    ("reverse_shell", "CRIT", rb"bash\s+-i\s+>&\s*/dev/tcp/|nc(?:\.exe)?\s+-e\s+(?:/bin/sh|cmd)|"
                              rb"New-Object\s+System\.Net\.Sockets\.TCPClient",
     "Reverse-Shell-Muster"),
    ("crypto_miner", "WARN", rb"stratum\+tcp://|stratum\+ssl://|xmrig|--donate-level",
     "Krypto-Miner-Konfiguration"),
]


def shannon(buf):
    if not buf:
        return 0.0
    counts = Counter(buf)
    n = len(buf)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _entropy_profile(ctx):
    size = ctx.size
    block = limits.ENTROPY_BLOCK
    nblocks = max(1, math.ceil(size / block))
    step = max(1, math.ceil(nblocks / limits.ENTROPY_MAX_BLOCKS))
    profile = []
    with open(ctx.path, "rb") as f:
        for i in range(0, nblocks, step):
            f.seek(i * block)
            profile.append(round(shannon(f.read(block)), 3))
    return profile, block * step


def _filename_checks(ctx):
    out = []
    name = ctx.p.name
    if any(c in name for c in BIDI_CHARS):
        shown = name.replace(RTLO, "")
        out.append(finding("rtlo_filename",
                           f"Dateiname enthält Unicode-Richtungszeichen (RTLO-Trick): „{shown}“ – "
                           f"Windows zeigt eine falsche Endung an", "CRIT"))
    parts = name.lower().split(".")
    if len(parts) >= 3:
        inner, outer = "." + parts[-2].strip(), "." + parts[-1].strip()
        if inner in DECOY_EXTS and outer in DANGEROUS_EXTS:
            out.append(finding("double_extension",
                               f"Doppel-Endung „{inner}{outer}“ – tarnt eine ausführbare Datei als Dokument", "CRIT"))
    if re.search(r"\s{5,}\.[a-z0-9]{2,5}$", name, re.I) or re.search(r"_{8,}\.[a-z0-9]{2,5}$", name):
        out.append(finding("filename_padding", "Dateiname mit langem Füllraum vor der Endung (versteckt die echte Endung)", "WARN"))
    return out


def _mismatch_checks(ctx):
    ft = ctx.filetype
    if not ft.get("extension_mismatch"):
        return []
    real = ft["description"]
    ext = ctx.ext or "(keine)"
    if ctx.category == "executable" and ctx.ext not in DANGEROUS_EXTS:
        return [finding("disguised_executable",
                        f"Ausführbare Datei ({real}) getarnt mit Endung {ext}", "CRIT")]
    if ctx.ext in DECOY_EXTS and ctx.category in ("script", "web") and ctx.subtype in ("hta", "wsf", "powershell", "vbscript", "javascript"):
        return [finding("disguised_executable", f"Skript ({real}) getarnt mit Endung {ext}", "CRIT")]
    return [finding("extension_mismatch", f"Endung {ext} passt nicht zum echten Typ: {real}", "WARN")]


EMBEDDED_SIGS = [
    (b"PK\x03\x04", "zip", "ZIP-Daten"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip-Daten"),
    (b"Rar!\x1a\x07", "rar", "RAR-Daten"),
    (b"%PDF-", "pdf", "PDF-Daten"),
    (b"\x7fELF", "elf", "ELF-Programm"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "OLE-Dokument"),
]


def _find_embedded_elf(data, start):
    """Echte ELF-Köpfe: Magic + Klasse (32/64) + Byte-Reihenfolge + Version 1 + plausibler Typ/Maschine."""
    hits = []
    pos = data.find(b"\x7fELF", start)
    while pos != -1 and len(hits) < 20:
        if pos + 24 <= len(data) and data[pos + 4] in (1, 2) and data[pos + 5] in (1, 2) and data[pos + 6] == 1:
            e_type, e_machine, e_version = struct.unpack_from("<HHI" if data[pos + 5] == 1 else ">HHI", data, pos + 16)
            if e_type in (1, 2, 3, 4) and 0 < e_machine < 0x200 and e_version == 1:
                hits.append(pos)
        pos = data.find(b"\x7fELF", pos + 4)
    return hits


def _find_embedded_pe(data, start):
    """Sucht echte PE-Header (MZ + gültiger e_lfanew → 'PE\\0\\0') ab Offset start."""
    hits = []
    pos = data.find(b"MZ", start)
    while pos != -1 and len(hits) < 20:
        if pos + 0x40 <= len(data):
            lfanew = struct.unpack_from("<I", data, pos + 0x3C)[0]
            if 0x40 <= lfanew < 0x1000 and data[pos + lfanew:pos + lfanew + 4] == b"PE\x00\x00":
                hits.append(pos)
        pos = data.find(b"MZ", pos + 2)
    return hits


def _embedded_checks(ctx):
    out, data_out = [], {}
    data = ctx.data
    is_pe = ctx.subtype == "pe"
    # Bei ZIP-basierten Formaten sind die Inhalte komprimiert → Signaturen am Rohstrom sinnlos.
    if ctx.category == "archive" and ctx.subtype not in ("tar",):
        return out, data_out
    pe_hits = _find_embedded_pe(data, 1 if is_pe else 0)
    if pe_hits:
        data_out["embedded_pe_offsets"] = pe_hits[:20]
        # In Installern sind eingebettete Programme normal → dort nur Hinweis
        sev = "INFO" if is_pe else "CRIT"
        what = "weitere PE-Programme im Programm (Dropper/Resource)" if is_pe \
            else f"ausführbares Windows-Programm in {ctx.filetype['description']} versteckt"
        out.append(finding("embedded_executable", f"{len(pe_hits)}× {what} (Offset 0x{pe_hits[0]:X})", sev))
    elif ctx.category in ("image", "media", "pdf", "document", "text", "font"):
        # Linux-Programme (ELF) in Bildern/Dokumenten – Kopf wird auf Plausibilität geprüft
        elf_hits = _find_embedded_elf(data, 1)
        if elf_hits:
            data_out["embedded_elf_offsets"] = elf_hits[:20]
            out.append(finding("embedded_executable", f"{len(elf_hits)}× ausführbares Linux-Programm (ELF) in "
                                                      f"{ctx.filetype['description']} versteckt (Offset 0x{elf_hits[0]:X})",
                               "CRIT"))
    others = []
    for sig, key, desc in EMBEDDED_SIGS:
        if ctx.subtype == key or (key == "zip" and ctx.category == "document"):
            continue
        pos = data.find(sig, 16)
        if pos != -1:
            others.append({"type": key, "desc": desc, "offset": pos})
    if others:
        data_out["embedded_signatures"] = others
        if ctx.category in ("image", "media", "pdf", "font", "text"):
            out.append(finding("polyglot",
                               "Eingebettete Fremddaten: " + ", ".join(f"{o['desc']} @0x{o['offset']:X}" for o in others[:4]),
                               "WARN"))
    return out, data_out


def _trailing_data(ctx):
    """Daten hinter dem offiziellen Dateiende (klassisches Versteck)."""
    size = ctx.size
    tail_len = min(size, limits.SCAN_TAIL)
    with open(ctx.path, "rb") as f:
        f.seek(size - tail_len)
        tail = f.read()
    base = size - tail_len
    end = None
    if ctx.subtype == "jpeg":
        i = tail.rfind(b"\xff\xd9")
        end = base + i + 2 if i != -1 else None
    elif ctx.subtype == "png":
        i = tail.rfind(b"IEND")
        end = base + i + 8 if i != -1 else None
    elif ctx.subtype == "gif":
        i = tail.rfind(b"\x00\x3b")
        end = base + i + 2 if i != -1 else None
    elif ctx.subtype == "pdf":
        i = tail.rfind(b"%%EOF")
        end = base + i + 5 if i != -1 else None
    if end is None:
        return [], {}
    extra = size - end
    rest = tail[end - base:]
    if extra > 32 and rest.strip(b"\r\n\x00 \t"):
        sev = "WARN" if extra > 1024 else "INFO"
        return ([finding("appended_data", f"{extra:,} Bytes hinter dem Dateiende ({ctx.subtype.upper()})", sev)],
                {"appended_bytes": extra, "appended_offset": end, "appended_entropy": round(shannon(rest[:1 << 20]), 3)})
    return [], {}


def _image_bomb(ctx):
    """Bild-Bombe: winzige Datei, gigantische Pixelzahl. Liest NUR den Header (dekodiert nichts)."""
    if ctx.category != "image":
        return [], {}
    import warnings
    from PIL import Image
    old = Image.MAX_IMAGE_PIXELS
    try:
        Image.MAX_IMAGE_PIXELS = None          # nur für das Header-Lesen: Größe erfahren statt Abbruch
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with Image.open(ctx.path) as im:
                w, h = im.size
                bands = len(im.getbands())
    except Exception:
        return [], {}
    finally:
        Image.MAX_IMAGE_PIXELS = old
    pixels = w * h
    raw = pixels * bands
    ratio = raw / max(1, ctx.size)
    d = {"dimensions": [w, h], "pixels": pixels, "decoded_bytes": raw, "decode_ratio": round(ratio, 1)}
    limit = old or 89_478_485
    if pixels > 2 * limit or (raw > 1 << 30 and ratio > 1000):
        return [finding("image_bomb", f"Bild-Bombe: {w:,}×{h:,} Pixel (~{raw / (1 << 30):.1f} GiB entpackt) "
                                      f"aus {ctx.size:,} Bytes", "CRIT")], d
    if pixels > limit:
        return [finding("image_bomb", f"Übergroßes Bild: {w:,}×{h:,} Pixel", "WARN")], d
    return [], d


def _strings(data, min_len=5):
    ascii_rx = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    utf16_rx = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    a = ascii_rx.findall(data)
    u = [s.decode("utf-16-le", "replace").encode() for s in utf16_rx.findall(data)]
    return a, u


def _valid_ip(raw):
    try:
        ip = ipaddress.ip_address(raw.decode())
    except ValueError:
        return False
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or str(ip).startswith("255."):
        return False
    # Versionsnummern wie 1.2.0.0 ausfiltern
    parts = [int(x) for x in str(ip).split(".")]
    return not (parts[0] < 10 and parts[1] < 30 and parts[2] < 30 and parts[3] < 30 and ip.is_global)


def _iocs(blob):
    iocs = {}
    for key, rx in RX.items():
        found, seen = [], set()
        for m in rx.finditer(blob):
            v = m.group(0)
            if key == "ipv4" and not _valid_ip(v):
                continue
            if key == "base64":
                try:
                    dec = base64.b64decode(v + b"=" * (-len(v) % 4), validate=True)
                except Exception:
                    continue
                if len(set(v)) < 20:
                    continue
                preview = dec[:60]
                v = v[:60] + b"..." if len(v) > 60 else v
                txt = v.decode("ascii", "replace")
                item = {"sample": txt, "decoded_len": len(dec),
                        "decoded_is_pe": dec[:2] == b"MZ",
                        "decoded_preview": preview.decode("latin-1").encode("unicode_escape").decode()[:80]}
                if txt not in seen:
                    seen.add(txt)
                    found.append(item)
            else:
                txt = v.decode("latin-1").strip(".,;)")
                if txt not in seen:
                    seen.add(txt)
                    found.append(txt)
            if len(found) >= limits.MAX_IOCS_PER_TYPE:
                break
        if found:
            iocs[key] = found
    if "url" in iocs:
        doms = []
        for u in iocs["url"]:
            m = re.match(r"(?:hxxps?|https?|ftp)://([^/:?#]+)", u, re.I)
            if m and m.group(1).lower() not in doms:
                doms.append(m.group(1).lower())
        iocs["domain"] = doms[:limits.MAX_IOCS_PER_TYPE]
    return iocs


# Domains, deren Nennung in Dateien normal ist
BENIGN_DOMAINS = ("microsoft.com", "w3.org", "openxmlformats.org", "adobe.com", "purl.org", "xml.org",
                  "schemas.", "apple.com", "google.com", "mozilla.org", "digicert.com", "verisign.com",
                  "globalsign", "sectigo.com", "usertrust.com", "symantec.com", "thawte.com", "iptc.org",
                  "ns.adobe.com", "xmlsoap.org", "example.com", "python.org", "gnu.org", "apache.org",
                  "java.com", "oracle.com", "github.com", "npmjs.", "wikipedia.org", "creativecommons.org")


def _mark_of_the_web(ctx):
    """Liest den NTFS-Stream Zone.Identifier (nur Windows, nur lesend)."""
    try:
        with open(ctx.path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
            raw = f.read(4096)
    except OSError:
        return None
    motw = {}
    for line in raw.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            motw[k.strip()] = v.strip()
    zones = {"0": "Lokal", "1": "Intranet", "2": "Vertrauenswürdig", "3": "Internet", "4": "Eingeschränkt"}
    motw["ZoneName"] = zones.get(motw.get("ZoneId", ""), "?")
    return motw


class BaselineAnalyzer:
    name = "baseline"

    def applies(self, ctx):
        return True

    def run(self, ctx):
        findings, data = [], {}
        data["filetype"] = ctx.filetype
        data["size"] = ctx.size
        data["scan_truncated"] = ctx.truncated

        # Entropie
        overall = shannon(ctx.data)
        profile, block = _entropy_profile(ctx)
        data["entropy"] = {"overall": round(overall, 4), "block_size": block, "profile": profile,
                           "max_block": max(profile) if profile else 0,
                           "high_blocks": sum(1 for e in profile if e > 7.2)}
        naturally_dense = ctx.category in COMPRESSED_CATEGORIES or ctx.subtype in COMPRESSED_SUBTYPES
        if overall > 7.9 and not naturally_dense and ctx.size > 4096:
            findings.append(finding("entropy_suspicious",
                                    f"Sehr hohe Entropie ({overall:.2f}/8) – Inhalt verschlüsselt oder gepackt", "WARN"))
        elif (ctx.category in ("text", "script", "web") and len(profile) > 1
              and max(profile) > 7.0):
            findings.append(finding("entropy_suspicious",
                                    "Textdatei mit hochentropischem Block (kodierte/verschlüsselte Nutzlast?)", "WARN"))

        # Dateiname / Typ
        findings += _filename_checks(ctx)
        findings += _mismatch_checks(ctx)

        # Eingebettetes & Anhänge
        f2, d2 = _embedded_checks(ctx)
        findings += f2
        data.update(d2)
        f3, d3 = _trailing_data(ctx)
        findings += f3
        data.update(d3)
        f4, d4 = _image_bomb(ctx)
        findings += f4
        if d4:
            data["image"] = d4

        # Strings + IOCs
        a, u = _strings(ctx.data)
        data["strings"] = {"ascii_count": len(a), "utf16_count": len(u),
                           "sample": [s.decode("latin-1")[:160] for s in (a + u)[:limits.MAX_STRINGS]]}
        blob = ctx.data + b"\n" + b"\n".join(u)
        iocs = _iocs(blob)
        data["iocs"] = iocs
        ctx.shared["iocs"] = iocs
        interesting_urls = [x for x in iocs.get("url", []) if not any(b in x.lower() for b in BENIGN_DOMAINS)]
        if interesting_urls and ctx.category in ("executable", "script", "web", "shortcut", "rtf", "document", "pdf"):
            findings.append(finding("network_iocs",
                                    f"{len(interesting_urls)} externe URL(s), z. B. {interesting_urls[0][:80]}", "INFO"))
        if iocs.get("onion"):
            findings.append(finding("tor_address", f"Tor-Adresse gefunden: {iocs['onion'][0]}", "WARN"))
        if (iocs.get("btc") or iocs.get("xmr")) and ctx.category in ("executable", "script", "text", "web"):
            findings.append(finding("crypto_wallet", "Krypto-Wallet-Adresse (typisch für Erpressungsnachrichten/Miner)", "INFO"))
        pe_b64 = [b for b in iocs.get("base64", []) if b.get("decoded_is_pe")]
        if pe_b64:
            findings.append(finding("base64_executable", "Base64-kodiertes Windows-Programm eingebettet", "CRIT"))

        # Befehlsmuster
        cmds = []
        for code, sev, rx, desc in COMMANDS:
            m = re.search(rx, blob, re.I)
            if m:
                cmds.append({"code": code, "match": m.group(0)[:120].decode("latin-1")})
                findings.append(finding(code, f"{desc}: „{m.group(0)[:70].decode('latin-1')}“", sev))
        data["commands"] = cmds

        # Herkunft
        motw = _mark_of_the_web(ctx)
        if motw:
            data["mark_of_the_web"] = motw
            src = motw.get("HostUrl") or motw.get("ReferrerUrl")
            findings.append(finding("motw_internet" if motw.get("ZoneId") == "3" else "motw_present",
                                    f"Herkunft (Mark-of-the-Web): Zone {motw['ZoneName']}" + (f", Quelle {src[:90]}" if src else ""),
                                    "INFO"))
        return {"data": data, "findings": findings}
