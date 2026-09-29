"""
Statische Analyse von Windows-Programmen (EXE/DLL/SYS/SCR/CPL …) mit pefile.

Nichts wird geladen oder ausgeführt – pefile parst nur die Bytes.
Indikatoren: verdächtige API-Kombinationen, Packer, W+X-Sections, Entropie,
Einstiegspunkt außerhalb des Codes, TLS-Callbacks, Overlay, fehlende Signatur,
Zeitstempel-Manipulation, Tarnung über Versionsinfo.
"""
import datetime
import math
from collections import Counter

from .base import finding

API_GROUPS = {
    "injection": ({"virtualallocex", "writeprocessmemory", "createremotethread", "createremotethreadex",
                   "ntunmapviewofsection", "zwunmapviewofsection", "queueuserapc", "setthreadcontext",
                   "ntwritevirtualmemory", "rtlcreateuserthread", "ntcreatethreadex", "virtualprotectex"},
                  "Code-Injektion in fremde Prozesse"),
    "keylogger": ({"setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeystate",
                   "getkeyboardstate", "registerrawinputdevices"}, "Tastatur-Überwachung"),
    "anti_debug": ({"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
                    "outputdebugstringa", "ntsetinformationthread", "zwqueryinformationprocess"},
                   "Anti-Debugging / Analyse-Erkennung"),
    "network": ({"internetopena", "internetopenw", "internetopenurla", "internetopenurlw", "urldownloadtofilea",
                 "urldownloadtofilew", "winhttpopen", "winhttpsendrequest", "httpsendrequesta", "httpsendrequestw",
                 "wsastartup", "connect", "send", "recv", "internetreadfile", "wsasocketa", "wsasocketw"},
                "Netzwerkzugriff / Download"),
    "crypto": ({"cryptencrypt", "cryptgenkey", "cryptacquirecontexta", "cryptacquirecontextw", "bcryptencrypt",
                "bcryptgeneratesymmetrickey", "cryptimportkey", "cryptderivekey"}, "Verschlüsselung"),
    "persistence": ({"regsetvalueexa", "regsetvalueexw", "createservicea", "createservicew", "regcreatekeyexa",
                     "regcreatekeyexw", "changeserviceconfiga", "changeserviceconfigw"}, "Autostart / Dienste"),
    "privilege": ({"adjusttokenprivileges", "lookupprivilegevaluea", "lookupprivilegevaluew",
                   "openprocesstoken", "impersonateloggedonuser", "duplicatetokenex"}, "Rechteausweitung"),
    "execution": ({"winexec", "shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw",
                   "createprocessa", "createprocessw", "createprocessasusera", "createprocessasuserw"},
                  "Startet andere Programme"),
    "dynamic_load": ({"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "getprocaddress",
                      "ldrloaddll", "ldrgetprocedureaddress"}, "Lädt Funktionen zur Laufzeit"),
    "screen_capture": ({"bitblt", "getdc", "getwindowdc", "printwindow"}, "Bildschirm erfassen"),
    "clipboard": ({"getclipboarddata", "setclipboarddata", "openclipboard"}, "Zwischenablage"),
    "enumeration": ({"createtoolhelp32snapshot", "process32first", "process32firstw", "process32next",
                     "process32nextw", "enumprocesses"}, "Prozesse auflisten"),
}

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".mpress1": "MPRESS",
    ".mpress2": "MPRESS", ".petite": "Petite", ".themida": "Themida", ".winlice": "WinLicense",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect", ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".nsp0": "NsPack", ".nsp1": "NsPack", "pec1": "PECompact", "pec2": "PECompact", ".pec": "PECompact",
    ".packed": "Packer", ".yp": "Y0da", ".perplex": "Perplex", ".spack": "SimplePack", "mew": "MEW",
    ".boom": "Boomerang", ".ccg": "CCG", ".rlpack": "RLPack", "kkrunchy": "kkrunchy", ".ndata": "NSIS",
}

MACHINES = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64", 0x200: "IA64"}
SUBSYSTEMS = {1: "native", 2: "GUI", 3: "Konsole", 9: "WinCE", 10: "EFI-App", 11: "EFI-Boot", 12: "EFI-Runtime"}


def _entropy(buf):
    if not buf:
        return 0.0
    c = Counter(buf)
    n = len(buf)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _vs_info(pe):
    out = {}
    for fi in getattr(pe, "FileInfo", None) or []:
        for entry in fi:
            for st in getattr(entry, "StringTable", []) or []:
                for k, v in st.entries.items():
                    out[k.decode("latin-1", "replace")] = v.decode("latin-1", "replace")[:200]
    return out


class PEAnalyzer:
    name = "pe"

    def applies(self, ctx):
        return ctx.subtype == "pe"

    def run(self, ctx):
        import pefile
        findings, d = [], {}
        try:
            pe = pefile.PE(name=ctx.path, fast_load=True)   # mmap, auch für riesige Installer
        except pefile.PEFormatError as e:
            if ctx.head[:2] == b"MZ" and len(ctx.head) < 0x200:
                return {"data": {"note": "MZ-Stub ohne PE-Header"}, "findings": []}
            return {"data": {"parse_error": str(e)},
                    "findings": [finding("pe_malformed", f"PE-Header defekt/manipuliert: {e}", "WARN")]}
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
        ])
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        is_dll = bool(fh.Characteristics & 0x2000)
        is_driver = oh.Subsystem in (1, 10, 11, 12)   # native + EFI: keine normalen Imports
        # Reproduzierbarer Build: TimeDateStamp ist ein Hash, keine Uhrzeit
        repro = any(dbg.struct.Type == 16 for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or [])
        resource_only = oh.AddressOfEntryPoint == 0 and is_dll
        d["machine"] = MACHINES.get(fh.Machine, hex(fh.Machine))
        d["type"] = "Treiber" if is_driver else "DLL" if is_dll else "EXE"
        d["subsystem"] = SUBSYSTEMS.get(oh.Subsystem, oh.Subsystem)
        d["entrypoint"] = hex(oh.AddressOfEntryPoint)
        d["image_base"] = hex(oh.ImageBase)
        d["dotnet"] = hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")
        try:
            d["imphash"] = pe.get_imphash()
        except Exception:
            d["imphash"] = None
        try:
            d["rich_hash"] = pe.get_rich_header_hash() or None      # Build-Umgebung (Compiler/Linker)
        except Exception:
            d["rich_hash"] = None

        # Zeitstempel
        ts = fh.TimeDateStamp
        d["compile_time"] = datetime.datetime.fromtimestamp(ts, datetime.UTC).isoformat() if ts else None
        d["reproducible_build"] = repro
        now = datetime.datetime.now(datetime.UTC).timestamp()
        if repro:
            d["compile_time"] = None
        elif ts > now + 86400 * 2:
            findings.append(finding("pe_timestamp_anomaly", f"Kompilierzeit liegt in der Zukunft ({d['compile_time']})", "WARN"))
        elif ts and ts < 631152000 and not d["dotnet"]:  # vor 1990, nicht reproduzierbarer Build-Hash
            findings.append(finding("pe_timestamp_anomaly", "Kompilierzeit vor 1990 (gefälscht oder genullt)", "INFO"))

        # Sections
        secs, ep_sec = [], None
        ep = oh.AddressOfEntryPoint
        packers = set()
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
            ent = _entropy(s.get_data()[:4 << 20])
            ch = s.Characteristics
            w, x = bool(ch & 0x80000000), bool(ch & 0x20000000)
            secs.append({"name": name, "vsize": s.Misc_VirtualSize, "rsize": s.SizeOfRawData,
                         "entropy": round(ent, 3), "flags": ("R" if ch & 0x40000000 else "-") + ("W" if w else "-") + ("X" if x else "-")})
            if s.contains_rva(ep):
                ep_sec = name
            if name.lower() in PACKER_SECTIONS:
                packers.add(PACKER_SECTIONS[name.lower()])
            if w and x:
                findings.append(finding("pe_wx_section", f"Section {name} ist beschreibbar UND ausführbar (selbstmodifizierender Code)", "WARN"))
            if ent > 7.2 and s.SizeOfRawData > 4096:
                findings.append(finding("pe_high_entropy_section", f"Section {name} hochentropisch ({ent:.2f}) – gepackt/verschlüsselt", "WARN"))
            if s.SizeOfRawData == 0 and s.Misc_VirtualSize > 0x10000 and x:
                findings.append(finding("pe_packed", f"Section {name}: leer auf der Platte, groß im Speicher (entpackt sich zur Laufzeit)", "WARN"))
        d["sections"] = secs
        d["entrypoint_section"] = ep_sec
        if ep and ep_sec is None and not d["dotnet"]:
            findings.append(finding("pe_entrypoint_anomaly", "Einstiegspunkt liegt außerhalb aller Sections", "CRIT"))
        elif ep_sec and ep_sec.lower() not in (".text", "code", ".code", "text", ".itext", "init", "page", ".textbss") \
                and not is_dll and ep_sec.lower() not in PACKER_SECTIONS:
            findings.append(finding("pe_entrypoint_anomaly", f"Einstiegspunkt in ungewöhnlicher Section „{ep_sec}“", "WARN"))
        if packers:
            d["packers"] = sorted(packers)
            benign = packers <= {"NSIS"}
            findings.append(finding("pe_packed", f"Packer/Protector erkannt: {', '.join(sorted(packers))}", "INFO" if benign else "WARN"))

        # Imports
        imports, apis = {}, set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry.dll.decode("latin-1", "replace").lower()
            names = []
            for imp in entry.imports:
                n = imp.name.decode("latin-1", "replace") if imp.name else f"ord{imp.ordinal}"
                names.append(n)
                apis.add(n.lower())
            imports[dll] = names[:300]
        d["imports"] = imports
        d["import_count"] = sum(len(v) for v in imports.values())
        hits = {}
        for grp, (names, _desc) in API_GROUPS.items():
            m = sorted(apis & names)
            if m:
                hits[grp] = m
        d["api_capabilities"] = {g: {"desc": API_GROUPS[g][1], "apis": v} for g, v in hits.items()}

        if len(hits.get("injection", [])) >= 3:
            findings.append(finding("pe_injection_apis", "Prozess-Injektion möglich: " + ", ".join(hits["injection"][:5]), "CRIT"))
        elif len(hits.get("injection", [])) == 2:
            findings.append(finding("pe_injection_apis", "Teilweise Injektions-APIs: " + ", ".join(hits["injection"]), "WARN"))
        if hits.get("keylogger") and ("setwindowshookexa" in apis or "setwindowshookexw" in apis or "getasynckeystate" in apis):
            findings.append(finding("pe_keylogger_apis", "Tastatur-Hooks/-Abfragen: " + ", ".join(hits["keylogger"]), "WARN"))
        # IsDebuggerPresent/OutputDebugString stecken in jeder MSVC-Laufzeit → nicht mitzählen
        strong_ad = [a for a in hits.get("anti_debug", []) if a not in ("isdebuggerpresent", "outputdebugstringa")]
        if len(strong_ad) >= 2:
            findings.append(finding("pe_antidebug", "Mehrere Anti-Debugging-Techniken: " + ", ".join(hits["anti_debug"]), "WARN"))
        if hits.get("crypto") and hits.get("enumeration") and ("findfirstfilew" in apis or "findfirstfileexw" in apis):
            findings.append(finding("pe_ransomware_combo", "Verschlüsselung + Datei-Durchlauf + Prozessliste (Ransomware-Muster)", "WARN"))
        if hits.get("network") and hits.get("execution") and hits.get("persistence"):
            findings.append(finding("pe_dropper_combo", "Download + Programmstart + Autostart (Dropper-/Trojaner-Muster)", "WARN"))
        if d["import_count"] and d["import_count"] < 10 and hits.get("dynamic_load") and not d["dotnet"]:
            findings.append(finding("pe_packed", f"Nur {d['import_count']} Imports, aber LoadLibrary/GetProcAddress – Imports werden versteckt", "WARN"))
        if not imports and not d["dotnet"] and not is_driver and not resource_only:
            findings.append(finding("pe_packed", "Keine Import-Tabelle – typisch für gepackte/Shellcode-Programme", "WARN"))

        # Exports
        exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if exp:
            d["exports"] = [(e.name or b"").decode("latin-1", "replace") for e in exp.symbols[:200]]

        # TLS
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            d["tls_callbacks"] = True
            # häufig auch in legitimer Software (C++-Laufzeit, Rust, Go) → nur Hinweis
            findings.append(finding("pe_tls_callback", "TLS-Callbacks: Code läuft schon vor dem Einstiegspunkt", "INFO"))

        # Signatur
        sec = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        d["signed"] = bool(sec.VirtualAddress and sec.Size)
        if d["signed"]:
            d["signature_size"] = sec.Size
            blob = pe.__data__[sec.VirtualAddress:sec.VirtualAddress + min(sec.Size, 65536)]
            import re
            subjects = []
            for m in re.finditer(rb"\x06\x03\x55\x04\x03[\x0c\x13]([\x01-\x7f])", blob):
                ln = m.group(1)[0]
                subjects.append(blob[m.end():m.end() + ln].decode("latin-1", "replace"))
            d["signature_names"] = list(dict.fromkeys(subjects))[:6]
            d["_note_signature"] = "Signatur vorhanden – Gültigkeit wird statisch nicht kryptografisch geprüft"
        else:
            findings.append(finding("pe_unsigned", "Nicht digital signiert", "INFO"))

        # Overlay (bei signierten Dateien zählt nur, was NICHT die Signatur ist)
        ov = pe.get_overlay_data_start_offset()
        if d["signed"]:
            after_sig = sec.VirtualAddress + sec.Size
            if ctx.size - after_sig > 1024:
                findings.append(finding("pe_signed_appended",
                                        f"{ctx.size - after_sig:,} Bytes hinter der Signatur angehängt "
                                        f"(Signatur wirkt weiter gültig – bekannter Tarn-Trick)", "WARN"))
            if ov is not None and ov >= sec.VirtualAddress:
                ov = None
        if ov is not None:
            ov_size = (sec.VirtualAddress if d["signed"] else ctx.size) - ov
            if ov_size > 1024:
                ov_data = pe.__data__[ov:ov + (1 << 20)]
                d["overlay"] = {"offset": ov, "size": ov_size, "entropy": round(_entropy(ov_data), 3),
                                "magic": ov_data[:8].hex()}
                sev = "WARN" if d["overlay"]["entropy"] > 7.5 and ov_size > 64 * 1024 else "INFO"
                findings.append(finding("pe_overlay", f"{ov_size:,} Bytes Anhang hinter dem Programm (Overlay, Entropie {d['overlay']['entropy']})", sev))

        # Ressourcen
        res = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for t in pe.DIRECTORY_ENTRY_RESOURCE.entries[:50]:
                tname = str(t.name) if t.name else pefile.RESOURCE_TYPE.get(t.struct.Id, str(t.struct.Id))
                for e in (t.directory.entries if hasattr(t, "directory") else [])[:50]:
                    for lang in (e.directory.entries if hasattr(e, "directory") else [])[:5]:
                        ds = lang.data.struct
                        blob = pe.get_data(ds.OffsetToData, min(ds.Size, 1 << 20))
                        r = {"type": tname, "size": ds.Size, "entropy": round(_entropy(blob), 3)}
                        if blob[:2] == b"MZ":
                            r["contains_pe"] = True
                            findings.append(finding("embedded_executable", f"Programm in Ressource {tname} versteckt ({ds.Size:,} B)", "WARN"))
                        res.append(r)
        d["resources"] = res[:100]

        # Versionsinfo
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            vs = _vs_info(pe)
        except Exception:
            vs = {}
        d["version_info"] = vs
        orig = (vs.get("OriginalFilename") or "").lower()
        if orig and orig.rsplit(".", 1)[0] and ctx.p.name.lower() != orig and orig.rsplit(".", 1)[0] not in ctx.p.name.lower():
            findings.append(finding("pe_name_mismatch", f"Originalname „{orig}“ ≠ Dateiname „{ctx.p.name}“ (umbenannt?)", "INFO"))
        company = (vs.get("CompanyName") or "").lower()
        low_path = ctx.path.lower().replace("/", "\\")
        # Orte, an denen Microsoft-Dateien per Katalog (nicht eingebettet) signiert sind
        catalog_dirs = ("\\windows\\", "\\program files\\windows", "\\program files (x86)\\windows",
                        "\\windowsapps\\", "\\common files\\microsoft shared\\")
        if "microsoft" in company and not d["signed"] and not any(c in low_path for c in catalog_dirs):
            # Systemdateien sind per Katalog signiert; außerhalb von C:\Windows ist das auffällig
            findings.append(finding("pe_fake_vendor", "Gibt sich als Microsoft aus, hat aber keine eingebettete "
                                                      "Signatur (Katalogsignatur wird nicht geprüft)", "WARN"))

        pe.close()
        if d["signed"]:
            findings = [_soften(f) for f in findings]
        return {"data": d, "findings": findings}


# Fähigkeits-Findings, die bei signierten Programmen eine Stufe milder ausfallen:
# Systembibliotheken und legitime Tools importieren dieselben APIs.
_SOFTEN = {"pe_injection_apis", "pe_antidebug", "pe_keylogger_apis", "pe_ransomware_combo",
           "pe_dropper_combo", "pe_timestamp_anomaly", "pe_tls_callback", "pe_high_entropy_section",
           "pe_entrypoint_anomaly", "embedded_executable"}


def _soften(f):
    if f["code"] in _SOFTEN:
        f = dict(f, severity={"CRIT": "WARN", "WARN": "INFO"}.get(f["severity"], f["severity"]))
        f["desc"] += " (signiertes Programm)"
    return f
