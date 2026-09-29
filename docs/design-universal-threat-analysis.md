# SENTINEL-F · Universelle Datei- und Bedrohungsanalyse

Stand: 2026-09-29 · Freigabe: Projekteigentümer („darfst alles machen, alles komplett“)

## Ziel

Jede Datei wird analysiert, egal welcher Typ, statt `Unsupported file type`.
Zusätzlich statische Malware-Indikatoren, Archiv- und Zipbomb-Erkennung sowie
weitere Spezialanalysen. Die bestehende Bild-, PDF- und Office-Forensik bleibt
unverändert.

## Harte Sicherheitsregeln

1. **Nichts wird ausgeführt.** Die Analyse ist rein statisch. Es gibt kein
   `subprocess`, `os.startfile` oder `eval` auf Dateiinhalte.
2. **Nichts wird entpackt.** Archive werden nur im Speicher gestreamt und gezählt.
   Die gelesenen Bytes werden sofort verworfen, es entsteht keine Datei auf der Platte.
3. **Feste Grenzen** (`engines/analyzers/limits.py`): Lesefenster, Entpack-Obergrenze,
   Schachtelungstiefe, Eintragszahl und YARA-Timeout. Ein bösartiges Sample darf das
   Tool weder aufhängen noch den Speicher füllen.
4. **Isolation:** Wirft ein Analysator eine Exception, wird sie im Bericht protokolliert,
   und alle anderen Analysatoren laufen weiter.
5. SQLite-Dateien werden mit `mode=ro&immutable=1` geöffnet, sodass kein
   Journal/WAL geschrieben wird.

## Architektur

```
engines/__init__.py      run_forensic(): Legacy-Engines (unverändert) + Analysatoren
core/filetype.py         Signatur-Datenbank (~90 Typen), Typ vs. Endung
engines/analyzers/
  base.py                FileContext, Finding, Registry, JSON-sichere Ausgabe
  limits.py              alle Grenzwerte zentral
  baseline.py            JEDE Datei: Entropie-Profil, Strings, IOCs, Dateinamen-Tricks,
                         eingebettete Signaturen/Polyglot, angehängte Daten, Mark-of-the-Web
  archive.py             ZIP/JAR/APK/OOXML, TAR, GZ/BZ2/XZ, 7z, RAR → Zipbomb & Co.
  pe.py                  EXE/DLL/SYS: Imports, Sections, Packer, Signatur, Overlay, TLS
  elf.py                 Linux-Binaries
  script.py              PS1/VBS/JS/BAT/CMD/HTA/WSF/PY/SH: Downloader, Obfuskation,
                         AMSI-Bypass, dekodiert -EncodedCommand (nur Text)
  web.py                 HTML/SVG/HTA: HTML-Smuggling, Phishing-Formulare
  lnk.py                 Verknüpfungen: versteckte Befehle, Icon-Tarnung
  rtf.py                 RTF: OLE-Objekte, Equation-Editor-Exploit-Muster
  email.py               EML: Absender-Spoofing, SPF/DKIM/DMARC, gefährliche Anhänge,
                         Link-Tarnung
  sqlite.py              SQLite: Tabellen, Freelist (gelöschte Daten), Browser-DBs
  yara_scan.py           YARA mit mitgelieferten Regeln + eigenem Regelordner
resources/yara/*.yar     eigene Regeln (erweiterbar, z. B. YARA-Forge-Pakete)
```

Ein Analysator erklärt mit `applies(ctx)`, ob er zuständig ist, und liefert mit
`run(ctx)` `{"data": {...}, "findings": [...]}`. Neue Dateitypen bedeuten eine
neue Datei plus einen Eintrag in der Registry, ohne Eingriff in `run_forensic`.

## Ergebnisvertrag (kompatibel)

Die bisherigen Schlüssel `ok, kind, file, hashes, magic, report, score, error, timestamp`
bleiben erhalten. Neu hinzu kommen:

- `filetype`: erkannter Typ mit Beschreibung und `extension_mismatch`
- `report["analyzers"][name]`: Daten je Analysator (+ `_error`, `_ms`)
- `threat`: `{"verdict", "families": [...]}`, eine kurze Zusammenfassung für die GUI

`kind` behält für Bild, PDF und Dokumente die alten Werte. Neue Werte sind z. B.
`archive`, `executable`, `script`, `web`, `email`, `database`, `shortcut`,
`media`, `text`, `binary`.

## Scoring

Alle Findings (Legacy + Analysatoren) laufen durch die bestehende `ScoreEngine`
(Gewicht × Schweregrad). Neue Codes stehen mit Gewichten in `SCORE_WEIGHTS`.
Harte Treffer wie Zipbomb, getarnte EXE, RTLO-Trick oder Injektions-APIs erreichen
allein HIGH RISK/CRITICAL.

## GUI

- Dateidialog und Drop-Zone akzeptieren alle Dateien.
- Die Vorschau zeigt für unbekannte Typen einen Hexdump plus IOCs.
- Die Metadaten-Tabelle zeigt alle Analysator-Abschnitte generisch.
- Der Übersichtsbericht bekommt einen Abschnitt THREAT ANALYSIS.

## Tests

- Charakterisierung des Legacy-Vertrags (Bild/PDF/DOCX/XLSX)
- Je Analysator synthetische, harmlose Samples, die im Test erzeugt werden:
  Zipbomb (hohe Ratio), überlappende ZIP-Einträge, Zip-Slip, verschachtelte Archive,
  Doppel-Endung/RTLO, getarnte EXE, PowerShell-Downloader, HTML-Smuggling, EML-Spoofing
  und SQLite mit Freelist.
- Es werden keine echten Malware-Samples und keine AV-Teststrings auf die Platte
  geschrieben, weil Defender sonst Testdateien löscht.
