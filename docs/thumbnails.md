# Update: Thumbnail-Forensik + ShellBag-Fix

## 1. Neuer Modus: THUMBNAILS (Sidebar, Taste `6`)
Windows-Thumbnail-Cache-Forensik. Extrahiert Vorschaubilder aus den
`thumbcache_*.db` der Benutzerprofile einer gemounteten Platte (read-only)
und zeigt sie als Galerie.

**Warum das stark ist:** Ein Vorschaubild bleibt oft erhalten, AUCH WENN die
Originaldatei geloescht oder auf einen USB-Stick verschoben wurde. Damit
laesst sich rekonstruieren, welche Bilder auf dem Rechner sichtbar waren —
ein direkter visueller Beleg.

**Grenze (ehrlich):** Thumbcaches enthalten KEINE Dateipfade, nur 64-bit
Hash-IDs. Das Pfad<->Hash-Mapping liegt in der `Windows.edb` (ESE-Datenbank)
und wird hier NICHT aufgeloest. Geliefert werden die Bilder + IDs.

Neue Dateien:
- `engines/thumbcache_engine.py`  — Parser + Engine (auch als CLI nutzbar)
- `gui/thumbnails_view.py`        — Galerie-View im SENTINEL-F-Look

Standalone-Nutzung ohne GUI:
```
python engines/thumbcache_engine.py --root E:\ --out ./thumbs
```

## 2. Fix: ShellBags wurden als Kauderwelsch angezeigt
Der alte ShellBag-Parser hat die rohen ShellItem-Bytes blind als UTF-16
gelesen — daher die chinesisch/wirr aussehenden Zeichen. Das ist
forensisch falsch: ShellItems haben eine Struktur, in der der lesbare Name
an definierter Stelle steht.

Neu: echter ShellItem-Decoder in `engines/copytrace_engine.py`
(`decode_shellitem`). Erkennt:
- Laufwerke (`C:\`),
- KnownFolder/GUID-Eintraege (This PC, Pictures, Downloads, ...),
- Datei-/Ordner-Eintraege inkl. langem UTF-16-Namen aus dem
  0xBEEF0004-Erweiterungsblock und DOS/FAT-Zeitstempel.

Die ShellBag-Tabelle im CopyTrace-Tab hat jetzt zusaetzlich die Spalte
**ITEM MTIME** (Zeitstempel des Ordner-Eintrags).

## Sidebar / Tasten (aktuell)
1 DASHBOARD · 2 ANALYSIS · 3 AI ANALYST · 5 COPYTRACE · 6 THUMBNAILS · 4 TELEMETRY
