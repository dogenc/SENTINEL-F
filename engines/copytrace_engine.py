#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║   COPYTRACE ENGINE — Exfiltration / Copy Indicator Analyzer  ║
║   Integrated into DGKN@Labs-FileForensic  ·  SENTINEL-F      ║
╚══════════════════════════════════════════════════════════════╝

Forensischer Nachweis von Datei-Kopiervorgaengen auf einer ausgebauten
Windows-Systemplatte. Read-only.

WICHTIG / Methodik & Grenzen
----------------------------
Windows/NTFS fuehrt KEINEN "Kopier-Zaehler" pro Datei. Ein Kopiervorgang
hinterlaesst an der Quelldatei selbst keine Spur. Diese Engine weist
Kopier-/Zugriffsvorgaenge daher INDIREKT ueber Spuren-Artefakte nach:
USBSTOR/MountedDevices/setupapi, LNK-Dateien, Jump Lists, ShellBags und
das (separat extrahierte) USN-Journal.

=> Eine LNK auf E:\\Bilder\\IMG_001.jpg (DRIVE_REMOVABLE) ist ein STARKES
   INDIZ fuer eine Kopie inkl. Ziel/Zeit, aber kein Beweis ueber die exakte
   Anzahl der Kopiervorgaenge.

Standalone nutzbar; in FileForensic ueber CopyTraceEngine(...).run()
angesprochen. Logik identisch zur getesteten CLI-Variante.
"""

import datetime
import html
import os
import struct

# ---- Abhaengigkeiten -------------------------------------------------------
try:
    import LnkParse3
except ImportError:
    LnkParse3 = None
try:
    from Registry import Registry
except ImportError:
    Registry = None
try:
    import olefile
except ImportError:
    olefile = None


# ===========================================================================
#  Hilfsfunktionen / Aesthetik
# ===========================================================================

def filetime_to_dt(ft: int):
    """Windows FILETIME (100ns seit 1601) -> aware UTC datetime, oder None."""
    if not ft:
        return None
    try:
        return datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + \
            datetime.timedelta(microseconds=ft / 10)
    except (OverflowError, OSError, ValueError):
        return None


def iso(dt):
    if dt is None:
        return ""
    if isinstance(dt, datetime.datetime):
        return dt.replace(microsecond=0).isoformat()
    return str(dt)


def safe_str(v):
    return "" if v is None else str(v)


# ===========================================================================
#  Artefakt-Discovery
# ===========================================================================

def find_artifacts(root: str):
    """Findet alle relevanten Pfade unter der gemounteten Beweisplatte."""
    art = {
        "system_hive": None,
        "setupapi": [],
        "users": [],          # Liste dicts: {name, recent, autodest, customdest, usrclass}
    }
    # SYSTEM-Hive
    for cand in (
        os.path.join(root, "Windows", "System32", "config", "SYSTEM"),
        os.path.join(root, "WINDOWS", "system32", "config", "SYSTEM"),
    ):
        if os.path.isfile(cand):
            art["system_hive"] = cand
            break
    # setupapi
    for cand in (
        os.path.join(root, "Windows", "INF", "setupapi.dev.log"),
        os.path.join(root, "Windows", "inf", "setupapi.dev.log"),
        os.path.join(root, "Windows", "setupapi.dev.log"),
    ):
        if os.path.isfile(cand):
            art["setupapi"].append(cand)

    users_dir = None
    for cand in (os.path.join(root, "Users"), os.path.join(root, "Dokumente und Einstellungen")):
        if os.path.isdir(cand):
            users_dir = cand
            break
    if users_dir:
        skip = {"All Users", "Default", "Default User", "Public", "Standard",
                "LocalService", "NetworkService", "systemprofile"}
        for name in sorted(os.listdir(users_dir)):
            base = os.path.join(users_dir, name)
            if not os.path.isdir(base) or name in skip:
                continue
            recent = os.path.join(base, "AppData", "Roaming", "Microsoft", "Windows", "Recent")
            entry = {
                "name": name,
                "recent": recent if os.path.isdir(recent) else None,
                "autodest": os.path.join(recent, "AutomaticDestinations"),
                "customdest": os.path.join(recent, "CustomDestinations"),
                "usrclass": os.path.join(base, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"),
            }
            if not os.path.isdir(entry["autodest"]):
                entry["autodest"] = None
            if not os.path.isdir(entry["customdest"]):
                entry["customdest"] = None
            if not os.path.isfile(entry["usrclass"]):
                entry["usrclass"] = None
            # Nur aufnehmen, wenn irgendwas Brauchbares da ist
            if entry["recent"] or entry["autodest"] or entry["customdest"] or entry["usrclass"]:
                art["users"].append(entry)
    return art


# ===========================================================================
#  SYSTEM-Hive: USB-Geraete + MountedDevices
# ===========================================================================

# Device-Property-GUID fuer Install-/Connect-/Removal-Zeiten (Win7+)
_DEVPROP_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
_DEVPROP_PIDS = {"0064": "first_install", "0066": "last_connected", "0067": "last_removed"}


def _read_property_filetime(device_key):
    """Liest first_install/last_connected/last_removed aus dem Properties-Subkey."""
    out = {}
    try:
        props = device_key.subkey("Properties")
    except Registry.RegistryKeyNotFoundException:
        return out
    try:
        guid_key = props.subkey(_DEVPROP_GUID)
    except Registry.RegistryKeyNotFoundException:
        return out
    for pid_key in guid_key.subkeys():
        label = _DEVPROP_PIDS.get(pid_key.name())
        if not label:
            continue
        # Wert liegt typischerweise unter Subkey "00000000" als REG_BINARY FILETIME
        try:
            for fmt_key in pid_key.subkeys():
                for val in fmt_key.values():
                    raw = val.value()
                    if isinstance(raw, bytes) and len(raw) >= 8:
                        ft = struct.unpack("<Q", raw[:8])[0]
                        dt = filetime_to_dt(ft)
                        if dt:
                            out[label] = dt
        except Exception:
            pass
    return out


def parse_system_hive(path, log):
    """Gibt (usb_devices, mounted_devices, computer_name) zurueck."""
    usb_devices = []
    mounted = {}
    computer = None
    if Registry is None:
        log.warn("python-registry nicht installiert -> USB-Analyse uebersprungen.")
        return usb_devices, mounted, computer
    try:
        reg = Registry.Registry(path)
    except Exception as e:
        log.warn(f"SYSTEM-Hive nicht lesbar: {e}")
        return usb_devices, mounted, computer

    # Aktuelles ControlSet bestimmen (Default = 1)
    cs = "ControlSet001"
    try:
        sel = reg.open("Select")
        cur = sel.value("Current").value()
        cs = f"ControlSet{cur:03d}"
    except Exception:
        pass

    # Computername
    try:
        cn = reg.open(f"{cs}\\Control\\ComputerName\\ComputerName")
        computer = cn.value("ComputerName").value()
    except Exception:
        pass

    # USBSTOR (USB-Massenspeicher)
    try:
        usbstor = reg.open(f"{cs}\\Enum\\USBSTOR")
        for prod in usbstor.subkeys():
            for inst in prod.subkeys():
                dev = {
                    "kind": "USBSTOR",
                    "product": prod.name(),
                    "serial": inst.name(),
                    "friendly_name": "",
                    "key_last_write": inst.timestamp(),
                    "first_install": None,
                    "last_connected": None,
                    "last_removed": None,
                }
                try:
                    dev["friendly_name"] = inst.value("FriendlyName").value()
                except Exception:
                    pass
                dev.update(_read_property_filetime(inst))
                usb_devices.append(dev)
    except Registry.RegistryKeyNotFoundException:
        log.warn("Kein USBSTOR-Schluessel gefunden (evtl. nie USB-Speicher genutzt).")
    except Exception as e:
        log.warn(f"USBSTOR-Parsing-Fehler: {e}")

    # MountedDevices: DosDevices -> USB-Instanz-ID Mapping
    try:
        md = reg.open("MountedDevices")
        for val in md.values():
            name = val.name()
            if not name.startswith("\\DosDevices\\"):
                continue
            letter = name.split("\\")[-1]
            raw = val.value()
            decoded = ""
            sig = None
            try:
                if isinstance(raw, bytes):
                    if len(raw) == 12:
                        # Fixed disk: 4-byte signature + 8-byte offset
                        sig = struct.unpack("<I", raw[:4])[0]
                    else:
                        decoded = raw.decode("utf-16-le", errors="ignore")
            except Exception:
                pass
            mounted[letter] = {"raw_signature": sig, "decoded": decoded}
    except Exception as e:
        log.warn(f"MountedDevices-Parsing-Fehler: {e}")

    return usb_devices, mounted, computer


def map_letter_to_usb(mounted, usb_devices):
    """Ordnet Laufwerksbuchstaben (zuletzt gemountet) USB-Geraeten zu."""
    out = {}
    for letter, info in mounted.items():
        dec = (info.get("decoded") or "").upper()
        if "USBSTOR" not in dec:
            continue
        for dev in usb_devices:
            ser = dev["serial"].upper().split("&")[0]
            if ser and ser in dec:
                out[letter] = dev
                break
    return out


# ===========================================================================
#  setupapi.dev.log: Erst-Installationszeit pro Geraet
# ===========================================================================

def parse_setupapi(paths, log):
    """Sehr toleranter Parser: extrahiert 'Device Install' Bloecke mit Zeit."""
    events = []
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            log.warn(f"setupapi nicht lesbar: {e}")
            continue
        cur_dev, cur_time = None, None
        for ln in lines:
            s = ln.strip()
            low = s.lower()
            if low.startswith(">>>  [device install") or "[device install" in low:
                # Geraete-ID steht oft in derselben oder folgenden Zeile
                if "USBSTOR" in s.upper() or "USB" in s.upper():
                    cur_dev = s
            if ">>>  section start" in low:
                # Zeitstempel: Format 2023/03/12 14:32:01.123
                parts = s.split("section start")[-1].strip()
                cur_time = parts
                if cur_dev:
                    events.append({"device": cur_dev, "time": cur_time})
                    cur_dev = None
    return events


# ===========================================================================
#  LNK-Dateien
# ===========================================================================

def _lnk_record_from_json(j, source, user):
    li = j.get("link_info", {}) or {}
    loc = li.get("location_info", {}) or {}
    hdr = j.get("header", {}) or {}
    path = li.get("local_base_path_unicode") or li.get("local_base_path") or ""
    suffix = li.get("common_path_suffix_unicode") or li.get("common_path_suffix") or ""
    full = path + suffix if suffix else path
    drive_type = loc.get("drive_type") or ""
    letter = ""
    if full and len(full) >= 2 and full[1] == ":":
        letter = full[0].upper() + ":"
    return {
        "source": source,
        "user": user,
        "target_path": full,
        "drive_letter": letter,
        "drive_type": drive_type,
        "volume_label": loc.get("volume_label_unicode") or loc.get("volume_label") or "",
        "drive_serial": loc.get("drive_serial_number") or "",
        "file_size": hdr.get("file_size") or 0,
        "target_created": hdr.get("creation_time"),
        "target_modified": hdr.get("modified_time"),
        "target_accessed": hdr.get("accessed_time"),
    }


def parse_lnk_file(data, source, user, log):
    if LnkParse3 is None:
        return None
    try:
        lnk = LnkParse3.lnk_file(indata=data)
        j = lnk.get_json()
        return _lnk_record_from_json(j, source, user)
    except Exception as e:
        log.debug(f"LNK-Parse-Fehler ({source}): {e}")
        return None


def parse_recent_dir(recent_dir, user, log):
    records = []
    if not recent_dir or not os.path.isdir(recent_dir):
        return records
    for fn in os.listdir(recent_dir):
        if not fn.lower().endswith(".lnk"):
            continue
        fp = os.path.join(recent_dir, fn)
        try:
            with open(fp, "rb") as f:
                data = f.read()
        except Exception:
            continue
        rec = parse_lnk_file(data, f"Recent/{fn}", user, log)
        if rec and rec["target_path"]:
            try:
                rec["lnk_modified"] = datetime.datetime.fromtimestamp(
                    os.path.getmtime(fp), tz=datetime.timezone.utc)
            except Exception:
                rec["lnk_modified"] = None
            records.append(rec)
    return records


# ===========================================================================
#  Jump Lists (automaticDestinations-ms = OLE Compound mit LNK-Streams)
# ===========================================================================

# Bekannte AppID-Auszuege (gekuerzt; nur Hilfstext)
_KNOWN_APPIDS = {
    "1b4dd67f29cb1962": "Windows Explorer (frequent)",
    "5f7b5f1e01b83767": "Windows Explorer (recent)",
    "f01b4d95cf55d32a": "Windows Explorer",
    "9b9cdc69c1c24e2b": "Notepad",
    "918e0ecb43d17e23": "Paint",
}


def parse_jumplists(autodest_dir, custom_dir, user, log):
    records = []
    if olefile is None:
        log.warn("olefile nicht installiert -> Jump Lists uebersprungen.")
        return records
    if autodest_dir and os.path.isdir(autodest_dir):
        for fn in os.listdir(autodest_dir):
            if not fn.lower().endswith(".automaticdestinations-ms"):
                continue
            fp = os.path.join(autodest_dir, fn)
            appid = fn.split(".")[0].lower()
            app = _KNOWN_APPIDS.get(appid, f"AppID {appid}")
            try:
                ole = olefile.OleFileIO(fp)
            except Exception as e:
                log.debug(f"JumpList ungueltig ({fn}): {e}")
                continue
            for stream in ole.listdir():
                sname = stream[0] if stream else ""
                if sname.lower() in ("destlist",):
                    continue
                try:
                    data = ole.openstream(stream).read()
                except Exception:
                    continue
                rec = parse_lnk_file(data, f"JumpList/{app}/{sname}", user, log)
                if rec and rec["target_path"]:
                    rec["lnk_modified"] = None
                    records.append(rec)
            try:
                ole.close()
            except Exception:
                pass
    return records


# ===========================================================================
#  ShellBags (UsrClass.dat) - Best Effort: besuchte Ordnerpfade
# ===========================================================================

# --- ShellItem-Decoder -----------------------------------------------------
# ShellBag-Werte sind binaere ShellItem-ID-Listen. Sie duerfen NICHT als
# UTF-16 ueber die Rohbytes gelesen werden (das ergibt Kauderwelsch aus
# Groessen-/GUID-/Flag-Bytes). Stattdessen wird der ShellItem-Typ ausgewertet
# und der Name an der strukturell korrekten Stelle gelesen.

# Haeufige KnownFolder / Delegate-GUIDs (lesbare Namen statt {GUID})
_KNOWN_GUIDS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "This PC",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "f42ee2d3-909f-4907-8871-4c22fc0bf756": "Documents",
    "33e28130-4e1e-4676-835a-98395c3bc1a5": "Pictures",
    "a0c69a99-21c8-4671-8703-7934162fcf1d": "Music",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "1cf1260c-4dd0-4ebb-811f-33c572699fde": "My Music",
    "905e63b6-c1bf-494e-b29c-65b732d3d21a": "Program Files",
    "088e3905-0323-4b02-9826-5d99428e115f": "Downloads",
    "24ad3ad4-a569-4530-98e1-ab02f9417aa8": "Pictures (Library)",
    "035bee0a-0a52-432e-a93c-8acbe1646a82": "Removable Media",
}


def _dos_datetime(date, time):
    """FAT/DOS date+time -> 'YYYY-MM-DD HH:MM:SS' oder ''."""
    if date == 0 and time == 0:
        return ""
    try:
        day = date & 0x1F
        month = (date >> 5) & 0x0F
        year = ((date >> 9) & 0x7F) + 1980
        sec = (time & 0x1F) * 2
        minute = (time >> 5) & 0x3F
        hour = (time >> 11) & 0x1F
        if not (1 <= month <= 12 and 1 <= day <= 31):
            return ""
        return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{sec:02d}"
    except Exception:
        return ""


def _guid_mixed_endian(b):
    """16 Bytes (Windows mixed-endian GUID) -> kanonischer String."""
    if len(b) < 16:
        return ""
    import struct as _s
    d1 = _s.unpack("<I", b[0:4])[0]
    d2 = _s.unpack("<H", b[4:6])[0]
    d3 = _s.unpack("<H", b[6:8])[0]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{b[8:10].hex()}-{b[10:16].hex()}"


def _read_unicode_z(data, off):
    out = bytearray()
    i = off
    while i + 1 < len(data):
        ch = data[i:i + 2]
        if ch == b"\x00\x00":
            i += 2
            break
        out += ch
        i += 2
    return out.decode("utf-16-le", errors="ignore"), i


def _read_ascii_z(data, off):
    out = bytearray()
    i = off
    while i < len(data) and data[i] != 0:
        out.append(data[i])
        i += 1
    return out.decode("latin-1", errors="ignore"), i + 1


def decode_shellitem(data):
    """
    Dekodiert ein einzelnes ShellItem (Bytes OHNE fuehrendes 2-Byte size-Feld).
    Returns dict {type, name, mtime} oder None bei unbekanntem Typ.
    """
    import struct as _s
    if not data or len(data) < 3:
        return None
    item_type = data[0]
    cls = item_type & 0x70

    # 0x1F : Root / KnownFolder (Desktop, This PC, Pictures ...)
    if item_type == 0x1F and len(data) >= 18:
        guid = _guid_mixed_endian(data[2:18])
        return {"type": "root", "name": _KNOWN_GUIDS.get(guid, "{%s}" % guid), "mtime": ""}

    # 0x2E / 0x70 : GUID / delegate item
    if item_type in (0x2E, 0x70) and len(data) >= 19:
        guid = _guid_mixed_endian(data[3:19])
        return {"type": "guid", "name": _KNOWN_GUIDS.get(guid, "{%s}" % guid), "mtime": ""}

    # 0x2X : Volume / drive letter (e.g. "C:\")
    if cls == 0x20:
        name, _ = _read_ascii_z(data, 1)
        name = name.strip("\x00").strip()
        return {"type": "volume", "name": name or "?:", "mtime": ""}

    # 0x3X : File / folder entry
    if cls == 0x30:
        mtime = ""
        try:
            dos_date, dos_time = _s.unpack_from("<HH", data, 8)
            mtime = _dos_datetime(dos_date, dos_time)
        except Exception:
            pass
        ascii_name, _ = _read_ascii_z(data, 14)
        # Long (UTF-16) name lives in the 0xBEEF0004 extension block
        long_name = ""
        sig_off = data.find(b"\x04\x00\xef\xbe")
        if sig_off != -1:
            best = ""
            for cand in (sig_off + 0x0A, sig_off + 0x0E, sig_off + 0x10,
                         sig_off + 0x12, sig_off + 0x14, sig_off + 0x16):
                if cand < len(data):
                    s, _ = _read_unicode_z(data, cand)
                    s = "".join(c for c in s if c.isprintable())
                    if len(s) > len(best) and any(c.isalnum() for c in s):
                        best = s
            long_name = best
        name = long_name or ascii_name.strip()
        if name:
            return {"type": "file", "name": name, "mtime": mtime}

    return None


def parse_shellbags(usrclass, user, log):
    """
    Extrahiert besuchte Ordner aus BagMRU durch korrektes ShellItem-Parsing.
    Jeder Wert ist eine ShellItem-ID-Liste; pro Schluessel wird das letzte
    (tiefste) ShellItem dekodiert und der Pfad-Trail aus den Eltern gebildet.
    """
    out = []
    if Registry is None or not usrclass:
        return out
    try:
        reg = Registry.Registry(usrclass)
    except Exception as e:
        log.warn(f"UsrClass.dat ({user}) nicht lesbar: {e}")
        return out
    bagmru = None
    for path in ("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                 "Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"):
        try:
            bagmru = reg.open(path)
            break
        except Exception:
            continue
    if bagmru is None:
        return out

    def decode_value(raw):
        """ShellItem-Value -> (name, mtime). Dekodiert das ShellItem im Value."""
        if not isinstance(raw, bytes) or len(raw) < 3:
            return None, ""
        # Der Value ist meist EIN ShellItem (ggf. mit 2-Byte Laenge davor).
        # Versuch 1: ab Offset 0; Versuch 2: ab Offset 2 (mit size-Feld).
        for start in (0, 2):
            d = decode_shellitem(raw[start:])
            if d and d.get("name"):
                return d["name"], d.get("mtime", "")
        return None, ""

    def walk(key, trail):
        for val in key.values():
            name = val.name()
            if not name.isdigit():
                continue
            raw = val.value()
            label, mtime = decode_value(raw)
            new_trail = trail + ([label] if label else [])
            if label:
                out.append({
                    "user": user,
                    "path_hint": label,
                    "trail": " > ".join(trail) if trail else "(root)",
                    "item_mtime": mtime,
                    "last_write": key.timestamp(),
                })
            try:
                sub = key.subkey(name)
                walk(sub, new_trail)
            except Exception:
                pass

    try:
        walk(bagmru, [])
    except Exception as e:
        log.debug(f"ShellBag-Walk-Fehler: {e}")
    return out


# ===========================================================================
#  USN-Journal ($Extend\$UsnJrnl:$J) - separat extrahiert
# ===========================================================================

_USN_REASONS = {
    0x00000100: "DATA_OVERWRITE", 0x00000200: "DATA_EXTEND", 0x00000400: "DATA_TRUNCATION",
    0x00001000: "NAMED_DATA_OVERWRITE", 0x00010000: "FILE_CREATE", 0x00020000: "FILE_DELETE",
    0x00040000: "EA_CHANGE", 0x00080000: "SECURITY_CHANGE", 0x00100000: "RENAME_OLD_NAME",
    0x00200000: "RENAME_NEW_NAME", 0x00800000: "BASIC_INFO_CHANGE", 0x01000000: "HARD_LINK_CHANGE",
    0x80000000: "CLOSE",
}


def _decode_usn_reason(flags):
    return "|".join(name for bit, name in _USN_REASONS.items() if flags & bit) or hex(flags)


def parse_usn(jpath, log, max_records=200000):
    """Parst ein extrahiertes $UsnJrnl:$J (USN_RECORD_V2)."""
    out = []
    try:
        with open(jpath, "rb") as f:
            data = f.read()
    except Exception as e:
        log.warn(f"USN-Datei nicht lesbar: {e}")
        return out
    i, n = 0, len(data)
    count = 0
    while i + 4 <= n and count < max_records:
        rec_len = struct.unpack_from("<I", data, i)[0]
        if rec_len == 0:
            i += 8  # gepolsterte Nullen ueberspringen
            continue
        if rec_len < 60 or i + rec_len > n:
            i += 8
            continue
        try:
            major = struct.unpack_from("<H", data, i + 4)[0]
            if major != 2:
                i += rec_len
                continue
            timestamp = struct.unpack_from("<q", data, i + 32)[0]
            reason = struct.unpack_from("<I", data, i + 40)[0]
            name_len = struct.unpack_from("<H", data, i + 56)[0]
            name_off = struct.unpack_from("<H", data, i + 58)[0]
            name = data[i + name_off:i + name_off + name_len].decode("utf-16-le", errors="ignore")
            out.append({
                "filename": name,
                "reason": _decode_usn_reason(reason),
                "timestamp": filetime_to_dt(timestamp),
            })
            count += 1
        except Exception:
            pass
        i += rec_len
    return out


# ===========================================================================
#  Korrelation / Bewertung
# ===========================================================================

EXTERNAL_TYPES = {"DRIVE_REMOVABLE", "DRIVE_REMOTE", "DRIVE_CDROM"}


def correlate(lnk_records, jump_records, letter_usb_map):
    """Bestimmt, welche Ziele auf externen/Wechseldatentraegern lagen."""
    findings = []
    for rec in lnk_records + jump_records:
        dt = rec.get("drive_type", "") or ""
        letter = rec.get("drive_letter", "")
        external = dt in EXTERNAL_TYPES
        device = letter_usb_map.get(letter)
        # Auch ohne sauberen drive_type: wenn Buchstabe einem USB-Geraet zugeordnet ist
        if device and not external:
            external = True
        if external:
            f = dict(rec)
            f["external"] = True
            f["matched_device"] = device
            # Score-Heuristik
            score = 50
            if dt == "DRIVE_REMOVABLE":
                score += 30
            if device:
                score += 20
            if rec.get("file_size"):
                score += 5
            f["confidence"] = min(score, 99)
            findings.append(f)
    # Sortierung: staerkste Indizien zuerst, dann nach Zugriffszeit
    findings.sort(key=lambda x: (x["confidence"], iso(x.get("target_accessed"))), reverse=True)
    return findings




# ===========================================================================
#  HTML-Report (DGKN Dark Theme)
# ===========================================================================

HTML_HEAD = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DGKN CopyTrace Report</title>
<style>
:root{--bg:#0a0e0f;--pan:#11181a;--bd:#1f2c30;--fg:#c9d6d1;--mut:#5f7570;
--acc:#39ff7a;--warn:#ffcf4d;--dang:#ff5d5d;--blue:#4dd0ff;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font-family:'JetBrains Mono','Consolas',monospace;font-size:13px;line-height:1.5}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{color:var(--acc);font-size:20px;letter-spacing:1px;margin:0 0 2px}
.sub{color:var(--mut);font-size:12px;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:16px 0}
.card{background:var(--pan);border:1px solid var(--bd);border-radius:8px;padding:14px}
.card .n{font-size:26px;color:var(--acc);font-weight:bold}
.card.dang .n{color:var(--dang)}.card .l{color:var(--mut);font-size:11px;text-transform:uppercase}
h2{color:var(--blue);font-size:14px;border-bottom:1px solid var(--bd);padding-bottom:6px;margin-top:30px}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px}
th{text-align:left;color:var(--mut);border-bottom:1px solid var(--bd);padding:6px 8px;font-weight:normal}
td{padding:6px 8px;border-bottom:1px solid #16201f;vertical-align:top;word-break:break-all}
tr:hover td{background:#0e1516}
.fpath{color:var(--fg);font-weight:bold}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:bold}
.b-rem{background:#3a1414;color:var(--dang)}.b-net{background:#2a2410;color:var(--warn)}
.b-fix{background:#10241a;color:var(--acc)}
.conf{font-weight:bold}.c-hi{color:var(--dang)}.c-md{color:var(--warn)}.c-lo{color:var(--mut)}
.note{background:#101a1c;border-left:3px solid var(--warn);padding:10px 14px;margin:16px 0;color:var(--mut);font-size:12px}
.empty{color:var(--mut);padding:14px;font-style:italic}
footer{color:var(--mut);font-size:11px;margin-top:40px;border-top:1px solid var(--bd);padding-top:12px}
</style></head><body><div class="wrap">
"""


def _conf_class(c):
    return "c-hi" if c >= 80 else ("c-md" if c >= 60 else "c-lo")


def _drive_badge(dt):
    if dt == "DRIVE_REMOVABLE":
        return '<span class="badge b-rem">WECHSEL</span>'
    if dt == "DRIVE_REMOTE":
        return '<span class="badge b-net">NETZ</span>'
    if dt == "DRIVE_CDROM":
        return '<span class="badge b-net">CD/DVD</span>'
    return f'<span class="badge b-fix">{html.escape(dt or "?")}</span>'


def build_html_report(out_path, root, computer, usb_devices, findings,
                      shellbags, usn_events, setupapi_events, warnings):
    e = html.escape
    parts = [HTML_HEAD]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parts.append("<h1>&gt; DGKN CopyTrace</h1>")
    parts.append(f'<div class="sub">Exfiltration / Copy Indicator Report &middot; '
                 f'erstellt {now} &middot; Beweismittel: {e(root)} &middot; '
                 f'Host: {e(computer or "unbekannt")}</div>')

    # Kennzahlen
    ext_high = sum(1 for f in findings if f["confidence"] >= 80)
    parts.append('<div class="grid">')
    parts.append(f'<div class="card"><div class="n">{len(usb_devices)}</div>'
                 f'<div class="l">USB-Geraete</div></div>')
    parts.append(f'<div class="card {"dang" if findings else ""}"><div class="n">{len(findings)}</div>'
                 f'<div class="l">Kopier-Indizien</div></div>')
    parts.append(f'<div class="card {"dang" if ext_high else ""}"><div class="n">{ext_high}</div>'
                 f'<div class="l">hohe Konfidenz</div></div>')
    parts.append(f'<div class="card"><div class="n">{len(usn_events)}</div>'
                 f'<div class="l">USN-Ereignisse</div></div>')
    parts.append('</div>')

    parts.append('<div class="note"><b>Methodik-Hinweis:</b> Windows fuehrt keinen '
                 'Kopier-Zaehler. Die hier gelisteten Eintraege sind <b>Indizien</b> dafuer, '
                 'dass Dateien auf externen Datentraegern lagen und dort geoeffnet/zugegriffen '
                 'wurden &ndash; ein starkes Indiz fuer eine Kopie, aber kein Beweis ueber die '
                 'exakte Anzahl der Kopiervorgaenge.</div>')

    # USB-Geraete
    parts.append("<h2>// Angeschlossene USB-Massenspeicher</h2>")
    if usb_devices:
        parts.append("<table><tr><th>Geraet</th><th>Seriennummer</th>"
                     "<th>Erstinstallation</th><th>Zuletzt verbunden</th><th>Zuletzt entfernt</th></tr>")
        for d in usb_devices:
            fn = d.get("friendly_name") or d["product"]
            parts.append("<tr>"
                         f"<td class='fpath'>{e(fn)}</td>"
                         f"<td>{e(d['serial'])}</td>"
                         f"<td>{e(iso(d.get('first_install')) or '-')}</td>"
                         f"<td>{e(iso(d.get('last_connected')) or '-')}</td>"
                         f"<td>{e(iso(d.get('last_removed')) or '-')}</td>"
                         "</tr>")
        parts.append("</table>")
    else:
        parts.append('<div class="empty">Keine USB-Massenspeicher in der Registry gefunden.</div>')

    # Findings
    parts.append("<h2>// Kopier-/Zugriffs-Indizien auf externen Datentraegern</h2>")
    if findings:
        parts.append("<table><tr><th>Datei (Zielpfad)</th><th>Volume</th><th>Geraet</th>"
                     "<th>Zugriff</th><th>Groesse</th><th>Quelle</th><th>Konfidenz</th></tr>")
        for f in findings:
            dev = f.get("matched_device")
            devname = (dev.get("friendly_name") or dev.get("product")) if dev else \
                (f.get("volume_label") or "-")
            vol = (f"{f.get('drive_letter','?')} {_drive_badge(f.get('drive_type'))}"
                   f"<br><span style='color:#5f7570'>Label: {e(f.get('volume_label') or '-')} "
                   f"&middot; Ser: {e(str(f.get('drive_serial') or '-'))}</span>")
            cc = _conf_class(f["confidence"])
            parts.append("<tr>"
                         f"<td class='fpath'>{e(f['target_path'])}</td>"
                         f"<td>{vol}</td>"
                         f"<td>{e(devname)}</td>"
                         f"<td>{e(iso(f.get('target_accessed')) or '-')}</td>"
                         f"<td>{e(str(f.get('file_size') or '-'))}</td>"
                         f"<td style='color:#5f7570'>{e(f['user'])}<br>{e(f['source'])}</td>"
                         f"<td class='conf {cc}'>{f['confidence']}%</td>"
                         "</tr>")
        parts.append("</table>")
    else:
        parts.append('<div class="empty">Keine Datei-Zugriffe von externen Datentraegern '
                     'in LNK/Jump Lists gefunden.</div>')

    # ShellBags
    parts.append("<h2>// ShellBags &ndash; besuchte Ordner (Best Effort)</h2>")
    if shellbags:
        parts.append("<table><tr><th>Ordner/Hinweis</th><th>Pfad-Trail</th><th>Zuletzt geschrieben</th></tr>")
        for s in shellbags[:300]:
            parts.append("<tr>"
                         f"<td class='fpath'>{e(s['path_hint'])}</td>"
                         f"<td style='color:#5f7570'>{e(s['trail'])}</td>"
                         f"<td>{e(iso(s.get('last_write')))}</td>"
                         "</tr>")
        parts.append("</table>")
    else:
        parts.append('<div class="empty">Keine auswertbaren ShellBags gefunden.</div>')

    # USN
    parts.append("<h2>// USN-Journal &ndash; Dateisystem-Ereignisse</h2>")
    if usn_events:
        parts.append("<table><tr><th>Zeitstempel</th><th>Reason</th><th>Datei</th></tr>")
        for ev in usn_events[:2000]:
            parts.append("<tr>"
                         f"<td>{e(iso(ev['timestamp']))}</td>"
                         f"<td style='color:#5f7570'>{e(ev['reason'])}</td>"
                         f"<td class='fpath'>{e(ev['filename'])}</td>"
                         "</tr>")
        parts.append("</table>")
        if len(usn_events) > 2000:
            parts.append(f'<div class="empty">... gekuerzt auf 2000 von {len(usn_events)} Ereignissen.</div>')
    else:
        parts.append('<div class="empty">Kein USN-Journal geladen (Option --usn). '
                     'Das $UsnJrnl:$J muss separat extrahiert werden.</div>')

    if warnings:
        parts.append("<h2>// Hinweise / Warnungen</h2><table>")
        for w in warnings:
            parts.append(f"<tr><td>{e(w)}</td></tr>")
        parts.append("</table>")

    parts.append('<footer>DGKN@Labs &middot; CopyTrace &middot; read-only forensic analysis &middot; '
                 'Indizien, kein Beweis ueber exakte Kopier-Anzahl.</footer>')
    parts.append("</div></body></html>")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))
    return out_path



