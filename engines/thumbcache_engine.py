#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║   THUMBCACHE ENGINE — Windows Thumbnail Forensics            ║
║   Standalone · part of DGKN@Labs-FileForensic (SENTINEL-F)   ║
╚══════════════════════════════════════════════════════════════╝

Extrahiert Vorschaubilder (Thumbnails) aus den Windows-Thumbnail-Caches
einer ausgebauten Platte. Read-only.

WARUM DAS FORENSISCH WERTVOLL IST
---------------------------------
Wenn ein Bild im Explorer angesehen, kopiert oder geoeffnet wurde, legt
Windows ein Vorschaubild im zentralen Cache ab
(%LocalAppData%\\Microsoft\\Windows\\Explorer\\thumbcache_*.db).
Diese Vorschau bleibt OFT erhalten, AUCH WENN DIE ORIGINALDATEI LAENGST
GELOESCHT ODER AUF EINEN USB-STICK VERSCHOBEN WURDE.

=> Damit laesst sich rekonstruieren, WELCHE Bilder auf dem Rechner sichtbar
   waren — ein direkter visueller Beleg, kein blosser Pfad-Hinweis.

GRENZEN (ehrlich)
-----------------
* Thumbcaches enthalten KEINE Dateipfade, nur 64-bit Cache-Hashes (Entry-IDs).
  Das Pfad<->Hash-Mapping liegt in der Windows.edb (ESE-Datenbank) und wird
  hier NICHT aufgeloest. Geliefert werden also die BILDER + IDs, nicht der
  urspruengliche Dateiname.
* Thumbnails sind verkleinerte Versionen (32/96/256/1024 px), kein Original.
* Ein Thumbnail beweist, dass das Bild dem System bekannt war — nicht, wann
  oder ob es kopiert wurde (das ergaenzen LNK/ShellBags/USN aus CopyTrace).

Standalone-CLI:
    python thumbcache_engine.py --root E:\\ --out ./thumbs
In FileForensic ueber ThumbcacheEngine(root).run(out_dir) angesprochen.
"""

import os
import struct
import argparse


# ── eingebettete Bildsignaturen ──────────────────────────────────────────────
_IMG_SIGS = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff",       "jpg"),
    (b"BM",                 "bmp"),
    (b"GIF8",               "gif"),
]


def _detect_image(blob):
    for sig, ext in _IMG_SIGS:
        if blob.startswith(sig):
            return ext
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  Low-level Parser
# ══════════════════════════════════════════════════════════════════════════════

def parse_thumbcache_bytes(data, log=None):
    """
    Parst die Bytes einer thumbcache_*.db.

    Strategie: Eintraege beginnen mit der Signatur 'CMMM' gefolgt von einer
    4-Byte entry size und einem 8-Byte entry hash. Innerhalb jedes Eintrags
    wird das eingebettete Bild per Signatur lokalisiert. Bricht die
    size-Kette (Versionsunterschiede), wird auf reinen Signatur-Scan
    zurueckgefallen. Read-only, tolerant.

    Returns: Liste von dicts
        {entry_id (16-hex), entry_size, data_size, image_ext, data (bytes), offset}
    """
    entries = []
    if not data or len(data) < 8:
        return entries
    if data[:4] != b"CMMM" and log:
        log("Kein CMMM-Dateiheader — Signatur-Scan", "WARN")

    n = len(data)
    # erster Eintrag nach dem Datei-Header (ueberspringt Header-CMMM bei Offset 0)
    pos = data.find(b"CMMM", 4)
    if pos == -1:
        return entries

    seen_offsets = set()
    while pos + 16 <= n:
        if data[pos:pos + 4] != b"CMMM":
            nxt = data.find(b"CMMM", pos + 1)
            if nxt == -1:
                break
            pos = nxt
            continue
        if pos in seen_offsets:
            nxt = data.find(b"CMMM", pos + 4)
            if nxt == -1:
                break
            pos = nxt
            continue
        seen_offsets.add(pos)

        try:
            entry_size = struct.unpack_from("<I", data, pos + 4)[0]
            entry_hash = struct.unpack_from("<Q", data, pos + 8)[0]
        except struct.error:
            break

        # Plausibilitaet der entry size
        plausible = 16 <= entry_size <= (n - pos + 64)
        chunk = data[pos:pos + entry_size] if (plausible and pos + entry_size <= n) \
            else data[pos:data.find(b'CMMM', pos + 4) if data.find(b'CMMM', pos + 4) != -1 else n]

        img_ext, img_off = None, None
        for sig, ext in _IMG_SIGS:
            k = chunk.find(sig)
            if k != -1:
                img_ext, img_off = ext, k
                break

        blob = chunk[img_off:] if img_off is not None else b""
        # trailing Nullbytes (Padding) am Ende grob trimmen
        if blob:
            blob = blob.rstrip(b"\x00") or blob

        if img_ext:   # nur Eintraege mit echtem Bild aufnehmen
            entries.append({
                "entry_id": f"{entry_hash:016x}",
                "entry_size": entry_size if plausible else len(chunk),
                "data_size": len(blob),
                "image_ext": img_ext,
                "data": blob,
                "offset": pos,
            })

        step = entry_size if plausible and entry_size >= 16 else 16
        nxt = data.find(b"CMMM", pos + step)
        if nxt == -1:
            break
        pos = nxt

    if log:
        log(f"{len(entries)} Thumbnails extrahiert", "OK")
    return entries


def parse_thumbcache_file(path, log=None):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        if log:
            log(f"Cache nicht lesbar ({os.path.basename(path)}): {e}", "WARN")
        return []
    res = parse_thumbcache_bytes(data, log=log)
    for r in res:
        r["source_db"] = os.path.basename(path)
    return res


# ══════════════════════════════════════════════════════════════════════════════
#  Discovery
# ══════════════════════════════════════════════════════════════════════════════

def find_thumbcache_dbs(root):
    """
    Findet alle thumbcache_*.db (und iconcache_*.db) unter den Benutzerprofilen
    der gemounteten Platte. Gibt Liste von (user, path).
    """
    found = []
    users_dir = None
    for cand in (os.path.join(root, "Users"),
                 os.path.join(root, "Dokumente und Einstellungen")):
        if os.path.isdir(cand):
            users_dir = cand
            break
    if not users_dir:
        return found

    skip = {"All Users", "Default", "Default User", "Public", "Standard",
            "LocalService", "NetworkService", "systemprofile"}
    for name in sorted(os.listdir(users_dir)):
        base = os.path.join(users_dir, name)
        if not os.path.isdir(base) or name in skip:
            continue
        explorer = os.path.join(base, "AppData", "Local", "Microsoft",
                                "Windows", "Explorer")
        if not os.path.isdir(explorer):
            continue
        try:
            for fn in os.listdir(explorer):
                low = fn.lower()
                if (low.startswith("thumbcache_") or low.startswith("iconcache_")) \
                        and low.endswith(".db"):
                    found.append((name, os.path.join(explorer, fn)))
        except Exception:
            pass
    return found


# ══════════════════════════════════════════════════════════════════════════════
#  High-level engine
# ══════════════════════════════════════════════════════════════════════════════

class ThumbcacheEngine:
    """
    Findet & extrahiert Thumbnails von einer gemounteten Platte.

    run(out_dir) ->
        {
          "root": str,
          "databases": [ {user, db, path, count, size_label} ],
          "thumbnails": [ {user, source_db, entry_id, image_ext,
                           data_size, saved_path} ],
          "total": int,
          "by_db": {db_name: count},
          "warnings": [str],
        }
    Bilddaten werden nach out_dir geschrieben; die Rueckgabe enthaelt Pfade,
    nicht die Rohbytes (speicherschonend fuer die GUI).
    """

    def __init__(self, root, log_fn=None):
        self.root = root
        self._log = log_fn or (lambda m, l="INFO": None)
        self.warnings = []

    def log(self, msg, level="INFO"):
        if level == "WARN":
            self.warnings.append(msg)
        self._log(msg, level)

    def run(self, out_dir, min_bytes=64, save_images=True):
        os.makedirs(out_dir, exist_ok=True)
        result = {"root": self.root, "databases": [], "thumbnails": [],
                  "total": 0, "by_db": {}, "warnings": self.warnings}

        dbs = find_thumbcache_dbs(self.root)
        if not dbs:
            self.log("Keine thumbcache_*.db gefunden. Ist der Pfad die Wurzel "
                     "einer Windows-Partition?", "WARN")
            return result
        self.log(f"{len(dbs)} Thumbnail-Cache-Dateien gefunden", "OK")

        idx = 0
        for user, path in dbs:
            try:
                size = os.path.getsize(path)
            except Exception:
                size = 0
            self.log(f"Parse {os.path.basename(path)} ({user})", "INFO")
            thumbs = parse_thumbcache_file(path, log=self.log)
            thumbs = [t for t in thumbs if t["data_size"] >= min_bytes]

            for t in thumbs:
                idx += 1
                saved = ""
                if save_images and t["data"]:
                    fname = f"{idx:05d}_{t['source_db'].replace('.db','')}_{t['entry_id']}.{t['image_ext']}"
                    saved = os.path.join(out_dir, fname)
                    try:
                        with open(saved, "wb") as fh:
                            fh.write(t["data"])
                    except Exception as e:
                        self.log(f"Konnte Thumbnail nicht schreiben: {e}", "WARN")
                        saved = ""
                result["thumbnails"].append({
                    "user": user,
                    "source_db": t["source_db"],
                    "entry_id": t["entry_id"],
                    "image_ext": t["image_ext"],
                    "data_size": t["data_size"],
                    "saved_path": saved,
                })

            db_name = os.path.basename(path)
            result["databases"].append({
                "user": user,
                "db": db_name,
                "path": path,
                "count": len(thumbs),
                "size_label": _human(size),
            })
            result["by_db"][db_name] = result["by_db"].get(db_name, 0) + len(thumbs)

        result["total"] = len(result["thumbnails"])
        self.log(f"Fertig: {result['total']} Thumbnails aus {len(dbs)} Caches", "OK")
        return result


def _human(b):
    b = float(b or 0)
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.0f} {u}" if u == "B" else f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"


# ══════════════════════════════════════════════════════════════════════════════
#  Standalone CLI
# ══════════════════════════════════════════════════════════════════════════════

def _main():
    ap = argparse.ArgumentParser(
        description="Windows Thumbnail-Cache Forensik — extrahiert Vorschaubilder "
                    "von einer gemounteten Windows-Platte (read-only).")
    ap.add_argument("--root", required=True,
                    help="Wurzel der Windows-Partition (enthaelt Users\\).")
    ap.add_argument("--out", default="./thumbs_out",
                    help="Zielordner fuer extrahierte Thumbnails.")
    ap.add_argument("--min-bytes", type=int, default=64,
                    help="Mindestgroesse eines Thumbnails in Bytes.")
    args = ap.parse_args()

    def log(m, l="INFO"):
        print(f"[{l:<4}] {m}")

    eng = ThumbcacheEngine(args.root, log_fn=log)
    res = eng.run(args.out, min_bytes=args.min_bytes)
    print(f"\n{'='*60}")
    print(f"  Caches:     {len(res['databases'])}")
    print(f"  Thumbnails: {res['total']}")
    for db, c in res["by_db"].items():
        print(f"     {db}: {c}")
    print(f"  Ausgabe:    {os.path.abspath(args.out)}")
    print(f"{'='*60}")


if __name__ == "__main__":
    _main()
