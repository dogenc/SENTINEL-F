"""
Zeitleiste: alle Zeitstempel einer Datei auf einer Achse + Widersprüche.

Quellen: Dateisystem (MAC-Zeiten), EXIF/XMP, PDF-Info, Office-Kernprops,
PE-Kompilierzeit, E-Mail (Date + Received-Hops).

Zeitzonen: Werte mit Zone werden in Ortszeit umgerechnet. EXIF und Dateisystem
haben keine Zone – Vergleiche mit ihnen bekommen eine Toleranz von 14 h, damit
Zeitzonen-Unterschiede nie als Manipulation gemeldet werden.

Die Widersprüche fließen bewusst NICHT in den Score ein (dessen Kalibrierung
bleibt unverändert); sie sind Hinweise für die manuelle Prüfung.
"""
import datetime
import email.utils
import re

TZ_SLACK = datetime.timedelta(hours=14)
FUTURE_SLACK = datetime.timedelta(days=1)
MIN_PLAUSIBLE = datetime.datetime(1995, 1, 1)

_RX_PDF = re.compile(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(Z|[+-]\d{2}'?\d{2}'?)?")
_RX_EXIF = re.compile(r"^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})")

# Metadaten-Schlüssel → (Quelle, Bezeichnung, Rolle)   Rolle: created | modified | other
META_KEYS = {
    "EXIF.DateTimeOriginal": ("EXIF", "Photo taken", "created"),
    "EXIF.DateTimeDigitized": ("EXIF", "Digitised", "other"),
    "EXIF.DateTime": ("EXIF", "Last changed (EXIF)", "modified"),
    "XMP.CreateDate": ("XMP", "Created (XMP)", "created"),
    "XMP.ModifyDate": ("XMP", "Modified (XMP)", "modified"),
    "XMP.MetadataDate": ("XMP", "Metadata written (XMP)", "other"),
    "CreationDate": ("PDF", "Created (PDF)", "created"),
    "ModDate": ("PDF", "Modified (PDF)", "modified"),
    "Created": ("Office", "Created (Office)", "created"),
    "Modified": ("Office", "Last saved (Office)", "modified"),
    "LastPrinted": ("Office", "Last printed (Office)", "other"),
}


def parse_ts(value):
    """→ (datetime ohne Zone in Ortszeit, zone_bekannt) oder (None, False)."""
    if value is None:
        return None, False
    if isinstance(value, datetime.datetime):
        dt = value
    else:
        s = str(value).strip().strip("\x00")
        if not s or s.startswith("0000"):
            return None, False
        m = _RX_PDF.match(s)
        if m:
            y, mo, d, h, mi, se, tz = m.groups()
            try:
                dt = datetime.datetime(int(y), int(mo or 1), int(d or 1), int(h or 0), int(mi or 0), int(se or 0))
            except ValueError:
                return None, False
            if tz:
                if tz == "Z":
                    off = datetime.timedelta(0)
                else:
                    digits = tz.replace("'", "")
                    off = datetime.timedelta(hours=int(digits[1:3]), minutes=int(digits[3:5] or 0))
                    off = off if digits[0] == "+" else -off
                dt = dt.replace(tzinfo=datetime.timezone(off))
        elif _RX_EXIF.match(s):
            try:
                dt = datetime.datetime(*map(int, _RX_EXIF.match(s).groups()))
            except ValueError:
                return None, False
        else:
            try:
                dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                try:
                    dt = email.utils.parsedate_to_datetime(s)
                except (TypeError, ValueError, IndexError):
                    return None, False
    if dt.tzinfo is not None:
        return dt.astimezone().replace(tzinfo=None), True
    return dt, False


def _event(events, dt_raw, source, label, role="other", raw=None):
    dt, tz = parse_ts(dt_raw)
    if dt is None:
        return None
    ev = {"ts": dt.isoformat(sep=" ", timespec="seconds"), "source": source, "label": label,
          "role": role, "tz_known": tz, "raw": str(raw if raw is not None else dt_raw)[:80], "_dt": dt}
    events.append(ev)
    return ev


def _gap(a, b):
    """Toleranz für den Vergleich zweier Ereignisse."""
    return datetime.timedelta(0) if (a["tz_known"] and b["tz_known"]) else TZ_SLACK


def _human(delta):
    s = abs(delta.total_seconds())
    if s >= 86400 * 2:
        return f"{s / 86400:.0f} days"
    if s >= 3600:
        return f"{s / 3600:.1f} h"
    return f"{s / 60:.0f} min"


def build_timeline(result, now=None):
    now = now or datetime.datetime.now()
    events, anomalies = [], []
    fi = result.get("file") or {}
    rep = result.get("report") or {}
    an = rep.get("analyzers") or {}

    # Dateisystem
    fs_mod = _event(events, fi.get("modified"), "File system", "Modified (file system)", "modified")
    _event(events, fi.get("created"), "File system", "Created / changed (file system)", "fs_created")
    _event(events, fi.get("accessed"), "File system", "Accessed (file system)", "other")

    # Eingebettete Metadaten
    meta = rep.get("metadata") if isinstance(rep.get("metadata"), dict) else {}
    by_source = {}
    for key, (src, label, role) in META_KEYS.items():
        if key in meta:
            ev = _event(events, meta[key], src, label, role)
            if ev:
                by_source.setdefault(src, {})[role] = ev

    # Programme
    pe = an.get("pe") or {}
    _event(events, pe.get("compile_time"), "PE header", "Compiled", "created") if pe.get("compile_time") else None

    # E-Mail
    mail = an.get("email") or {}
    sent = _event(events, mail.get("date"), "E-mail", "Date header (sender clock)", "created") if mail.get("date") else None
    hops = []
    for i, r in enumerate(mail.get("received") or []):
        if ";" in r:
            ev = _event(events, r.rsplit(";", 1)[1].strip(), "E-mail", f"Received hop {i + 1}", "other")
            if ev:
                hops.append(ev)

    _event(events, result.get("timestamp"), "SENTINEL-F", "Analysed", "analysis")

    # ── Widersprüche ──────────────────────────────────────────────────
    def add(sev, desc, *evs):
        anomalies.append({"severity": sev, "desc": desc, "events": [e["label"] for e in evs if e]})

    for src, roles in by_source.items():
        c, m = roles.get("created"), roles.get("modified")
        if c and m and c["_dt"] - m["_dt"] > _gap(c, m):
            add("WARN", f"{src}: created {_human(c['_dt'] - m['_dt'])} AFTER it was last modified "
                        f"– impossible in normal use, metadata was edited or forged", c, m)
    exif = by_source.get("EXIF", {})
    if exif.get("created") and exif.get("modified"):
        d = exif["modified"]["_dt"] - exif["created"]["_dt"]
        if d > datetime.timedelta(days=1):
            add("INFO", f"EXIF: image re-saved {_human(d)} after the photo was taken (edited later?)",
                exif["created"], exif["modified"])

    embedded = [e for e in events if e["source"] not in ("File system", "SENTINEL-F")]
    for e in embedded:
        if e["_dt"] - now > FUTURE_SLACK:
            add("WARN", f"{e['label']} lies in the future ({e['ts']}) – clock manipulated or forged", e)
        elif e["_dt"] < MIN_PLAUSIBLE and e["source"] != "E-mail":
            add("INFO", f"{e['label']} is implausibly old ({e['ts']}) – zeroed or forged", e)
    if fs_mod:
        for e in embedded:
            if e["role"] == "created" and e["source"] != "E-mail" and e["_dt"] - fs_mod["_dt"] > _gap(e, fs_mod) \
                    and e["_dt"] - now <= FUTURE_SLACK:
                add("WARN", f"{e['label']} is {_human(e['_dt'] - fs_mod['_dt'])} later than the file's last "
                            "write on disk – embedded date was forged or the file clock was reset", e, fs_mod)
    if sent and hops:
        first_hop = min(hops, key=lambda h: h["_dt"])
        if sent["_dt"] - first_hop["_dt"] > datetime.timedelta(hours=1):
            add("WARN", f"E-mail Date header is {_human(sent['_dt'] - first_hop['_dt'])} after the first "
                        "server received it – backdated/forged Date or wrong sender clock", sent, first_hop)
        if first_hop["_dt"] - sent["_dt"] > datetime.timedelta(days=3):
            add("INFO", f"E-mail was sent {_human(first_hop['_dt'] - sent['_dt'])} before any server received it "
                        "(delayed delivery or backdated Date header)", sent, first_hop)

    events.sort(key=lambda e: e["_dt"])
    for e in events:
        e.pop("_dt", None)
    order = {"WARN": 0, "INFO": 1}
    anomalies.sort(key=lambda a: order.get(a["severity"], 2))
    return {"events": events, "anomalies": anomalies,
            "span": [events[0]["ts"], events[-1]["ts"]] if events else None}
