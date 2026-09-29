# CopyTrace — Integration in FileForensic

Neuer Modus **COPYTRACE** (Sidebar, Taste `5`): forensischer Nachweis von
Datei-Kopiervorgaengen auf einer ausgebauten **Windows-Systemplatte**.
Read-only — es wird nichts auf das Beweismittel geschrieben.

## Neue/geaenderte Dateien
- `engines/copytrace_engine.py`  — Analyse-Engine (eigenstaendig, identisch zur getesteten CLI)
- `gui/copytrace_view.py`        — neuer View im SENTINEL-F-Look
- `gui/main_window.py`           — Sidebar-Button, Stack-Index 3, Shortcut `5`
  (TELEMETRY ist dadurch Stack-Index 4, Taste `4` — Verhalten unveraendert)
- `requirements.txt`             — python-registry, LnkParse3 ergaenzt (olefile war bereits drin)

## Bedienung
1. **COPYTRACE** in der Sidebar (oder `5`) oeffnen.
2. **EVIDENCE PATH** = Wurzel der Windows-Partition (Ordner mit `Windows\` und `Users\`),
   z.B. `E:\` oder ein read-only gemountetes Image.
3. Optional **USN JOURNAL** = separat extrahiertes `$Extend\$UsnJrnl:$J`
   (z.B. via `fsutil usn readjournal` oder RawCopy/FTK).
4. **RUN COPYTRACE**. Ergebnisse in den Tabs Copy Indicators / USB Devices /
   ShellBags / USN Journal; Export als **HTML** oder **JSON** (landet in `reports/`).

## Methodik & Grenzen (wichtig)
Windows fuehrt **keinen Kopier-Zaehler**. Die Treffer sind **Indizien**:
eine LNK/Jump-List/ShellBag, die eine Datei auf einem Wechseldatentraeger
(`DRIVE_REMOVABLE`) belegt, ist ein **starkes Indiz** fuer eine Kopie inkl.
Zielpfad und Zeit — aber kein Beweis ueber die exakte Anzahl der Vorgaenge.
Auf einer reinen Datenplatte ohne OS fehlen diese Spuren.

## Abhaengigkeiten
```
pip install python-registry LnkParse3 olefile
```
