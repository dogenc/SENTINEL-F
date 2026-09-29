"""
SQLite: Tabellen, Zeilenzahlen, Freelist (Seiten gelöschter Daten = wiederherstellbar),
Erkennung typischer Browser-/Messenger-Datenbanken.
Geöffnet mit mode=ro&immutable=1 → es wird nichts geschrieben, kein Journal/WAL.
"""
import sqlite3
import struct
from pathlib import Path

from .base import finding

KNOWN = {
    frozenset({"urls", "visits"}): "Chromium-Browserverlauf (History)",
    frozenset({"moz_places", "moz_historyvisits"}): "Firefox-Verlauf (places.sqlite)",
    frozenset({"cookies"}): "Browser-Cookies",
    frozenset({"moz_cookies"}): "Firefox-Cookies",
    frozenset({"logins"}): "Browser-Passwortspeicher (Login Data)",
    frozenset({"downloads"}): "Browser-Downloads",
    frozenset({"message", "chat"}): "Messenger-Chatdatenbank",
    frozenset({"sms"}): "SMS-Datenbank",
}


class SqliteAnalyzer:
    name = "sqlite"

    def applies(self, ctx):
        return ctx.subtype == "sqlite"

    def run(self, ctx):
        hdr = ctx.head[:100]
        page_size = struct.unpack(">H", hdr[16:18])[0] or 65536
        page_size = 65536 if page_size == 1 else page_size
        d = {
            "page_size": page_size,
            "page_count": struct.unpack(">I", hdr[28:32])[0],
            "freelist_pages": struct.unpack(">I", hdr[36:40])[0],
            "schema_cookie": struct.unpack(">I", hdr[40:44])[0],
            "user_version": struct.unpack(">I", hdr[60:64])[0],
            "text_encoding": {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}.get(struct.unpack(">I", hdr[56:60])[0], "?"),
            "wal_mode": hdr[18] == 2,
        }
        findings = []
        uri = Path(ctx.path).resolve().as_uri() + "?mode=ro&immutable=1"
        tables = {}
        try:
            con = sqlite3.connect(uri, uri=True, timeout=2)
            try:
                con.execute("PRAGMA query_only = ON")
                rows = con.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') LIMIT 500").fetchall()
                for name, typ in rows:
                    try:
                        n = con.execute(f'SELECT COUNT(*) FROM "{name.replace(chr(34), "")}"').fetchone()[0]
                    except sqlite3.Error:
                        n = None
                    tables[name] = {"type": typ, "rows": n}
            finally:
                con.close()
        except sqlite3.Error as e:
            findings.append(finding("sqlite_unreadable", f"Datenbank nicht lesbar: {e}", "INFO"))
        d["tables"] = tables
        names = {t.lower() for t in tables}
        for keys, label in KNOWN.items():
            if keys <= names:
                d.setdefault("recognized_as", []).append(label)
        if d.get("recognized_as"):
            findings.append(finding("sqlite_known_db", "Erkannt: " + ", ".join(d["recognized_as"]), "INFO"))
        if d["freelist_pages"]:
            kb = d["freelist_pages"] * page_size // 1024
            findings.append(finding("sqlite_deleted_data",
                                    f"{d['freelist_pages']} freie Seiten (~{kb:,} KB) – gelöschte Datensätze evtl. wiederherstellbar", "INFO"))
        for side in ("-wal", "-journal"):
            if Path(ctx.path + side).exists():
                d[f"has{side}"] = True
                findings.append(finding("sqlite_journal", f"Begleitdatei {side} vorhanden (enthält evtl. neuere/gelöschte Daten)", "INFO"))
        return {"data": d, "findings": findings}
