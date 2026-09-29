# Stand & nächste Schritte

Stand: 2026-09-29 · für die nächste Arbeitssitzung (Mensch oder Claude)

## Erledigt
- Universelle Analyse für jede Datei (`engines/analyzers/`), Zipbomb- und Bild-Bomben-Erkennung,
  statische Malware-Analyse (PE, ELF, Skripte, Web, LNK, RTF, E-Mail, SQLite, YARA)
- Sandbox (`core/sandbox.py`): Low Integrity + Job Object, Sperren per Test bewiesen
- GUI: THREATS-Tab, Vorschau nur aus der Sandbox, GitHub-README mit Screenshots
- Verlauf & Fälle (`core/history.py`, `gui/history_view.py`, Taste `7`): jede Analyse wird in
  `data/sentinel_history.db` gespeichert, bekannte Dateien werden am SHA-256 erkannt,
  Suche über Name/Hash/IOCs, Ergebnisse lassen sich ohne Neuanalyse wieder öffnen
- Ordner-/Stapelanalyse (`core/batch.py`, `gui/batch_view.py`, Taste `8`, Ordner einfach droppen):
  parallele Sandbox-Worker, Risiko-Sortierung, Duplikate/bekannte Dateien, eigener Fall, CSV-Export
  (gegen CSV-/Formel-Injection abgesichert)
- Watch-Folder (`core/watcher.py`, `gui/watch_view.py`, Taste `9`): Polling, wartet auf fertige
  Downloads, Tray-Alarm ab wählbarer Stufe, läuft im Tray weiter, Autostart; Einstellungen in `data/watch.ini`
- MITRE ATT&CK (`engines/attack.py`, Tab ATT&CK): ~90 Signal-Codes → Techniken, Heatmap nach Taktik,
  `result['attack']`; ältere Verlaufs-Ergebnisse werden nachträglich zugeordnet
- Zeitleiste (`engines/timeline.py`, Tab TIMELINE): FS/EXIF/XMP/PDF/Office/PE/E-Mail, Widerspruchs-Regeln
  mit 14-h-Zeitzonen-Toleranz; fließt bewusst NICHT in den Score (Kalibrierung bleibt), 0 Treffer auf 60 echten Dateien
- Ähnlichkeitssuche (`engines/similarity.py`, Tab SIMILAR): TLSH in reinem Python/numpy (gegen py-tlsh
  verifiziert, 8 MiB ≈ 1 s, darüber kein TLSH), Imphash (außer .NET/sehr häufige), Rich-Header-Hash;
  Tabelle `fingerprints` im Verlauf (Schema-Version 2, Altdaten werden nachgetragen); Batch markiert Varianten
- IOC-Graph (`core/iocgraph.py`, `gui/graph_view.py`, Taste `0`): nur IOCs, die ≥ 2 Dateien teilen,
  harmlose Domains gefiltert, Ähnlichkeitskanten, Cluster = mögliche Kampagnen, Layout je Cluster
- Forensische Berichte (`core/report.py`, Button 📄 REPORT / Ctrl+P, 📄 CASE REPORT im Verlauf): HTML oder PDF
  (Qt-Druck), Beweiskette mit erneuter SHA-256-Prüfung, IOCs entschärft, alles escaped, `<bericht>.sha256`
- README komplett neu mit 13 Screenshots; `config/local_secrets.example.py` als Schlüssel-Vorlage
- Payload-Kette (`engines/payloads.py`, Tab CHAIN): Stufen extrahieren (Archive, Mail/PDF-Anhänge, VBA,
  EncodedCommand, Base64-Blobs, eingebettete PE, Anhang hinter EOF, LNK-Befehl), rekursiv bis Tiefe 3,
  Budget 25 Stufen/128 MiB/150 s; Stufe liegt nur kurz im privaten Temp-Ordner; Score erbt vom Kind;
  0 neue Fehlalarme auf 140 echten Dateien (inkl. .whl/.jar/.gz/.zip)
- Eigene Threat-Intel (`core/intel.py`, Buttons im IOC-Graph): YARA-Regel je Cluster aus geteilten IOCs +
  Imphash, Schwelle per Rückwärtstest, Aktivieren → `data/yara_generated/` (vom YARA-Analysator geladen);
  Export STIX 2.1 / MISP / CSV
- Detektiv-Modus (`engines/detective.py`, Button 🕵 im AI-Panel, Abschnitt im Bericht): Beweisliste [E#],
  regelbasierte Erzählung offline, Ollama nur mit Belegen als JSON, jede Antwort satzweise geprüft (⚠ unbelegt)
- Foto-Echtheit (`engines/analyzers/photo.py`): C2PA erkennen (Signatur nur mit c2pa-python prüfbar),
  harte KI-Marker, PRNU 384² int8 im Verlauf (`fingerprints.kind='prnu'`), Schwelle 6σ; synthetisch 0 Fehlzuordnungen,
  schwache Sensoren/starke Kompression werden verfehlt → Indiz, kein Beweis
- Dokument-Stammbaum (`engines/analyzers/lineage.py`, `core/lineage.py`, Tab LINEAGE): PDF-/ID + Speicherstände,
  XMP DerivedFrom/History/OriginalDocumentID, Word rsidRoot/RSID-Teilmengen; Schutz vor Vorlagen-Zwillingen
  und generischen IDs (> 15 Dateien); Schema-Version 3 mit Nachtrag
- GPS-Bewegungsprofil (`core/geo.py`, `gui/route_dialog.py`, Button 🗺 ROUTE im Verlauf): Etappen mit Haversine,
  > 1100 km/h oder gleiche Sekunde an zwei Orten = unmöglich, > 300 km/h = nur per Flug; 2D-Karte + Globus-Route
- Sicherheitsfix: Dateiname wurde unescaped in Globus-JavaScript eingesetzt → jetzt JSON
- Vorher-Nachher-Vergleich (`engines/diff.py`, Worker-Modus `--sentinel-diff`, `gui/diff_dialog.py`, ⇄ COMPARE im
  Verlauf): Text-Diff, PDF-Seiten, Pixel-Regionen + Heatmap, Byte-Bereiche; Befund-Diff ohne Dateien
- Bugfix: clicked(bool) rutschte als Parameter in ROUTE/CASE REPORT/EXPORT IOCs/YARA RULE/REPORT → Lambdas
- AppContainer-Worker ohne Netzwerk (`core/appcontainer.py`, `SANDBOX_BLOCK_NETWORK`): Profil ohne Capabilities,
  Freigaben nur für Code (nicht data/, reports/, local_secrets.py), Beweisdatei wird in den Job-Ordner kopiert,
  Pfade im Ergebnis zurückgemappt, automatischer Rückfall auf Low IL; neue Sonden `network`, `read_user`
- Signierte Berichte (`core/signing.py`): Ed25519 je Arbeitsplatz (DPAPI unter Windows), `.sig` beim Speichern,
  ✔ VERIFY REPORT im Verlauf; optional RFC 3161 (`REPORT_TSA_URL`/`DGKN_TSA_URL`) → `.tsr`; neue Abhängigkeit
  `cryptography` (hat Windows-Wheels). Schlüssel liegt in `data/signing/` – beim PC-Wechsel mitnehmen
- Hash-Abfrage (`core/threatintel.py`, Tab INTEL): opt-in (`DGKN_HASH_LOOKUP=1`), nur SHA-256; CIRCL ohne Schlüssel,
  VT/MB mit `VT_API_KEY`/`MB_AUTH_KEY`; Cache 7 Tage (Tabelle `intel_cache`), Ergebnis im Befund/Bericht/Detektiv
- Postfach-Scan (`engines/mailbox_split.py`, Worker-Modus `--sentinel-mailbox`, 📧 im Batch-Scan): PST/OST
  (libpff-python, nur Windows-Wheel), MSG (extract-msg), mbox/Thunderbird, EML-Ordner; Zerlegen im Low-IL-Worker,
  jede Mail danach im AppContainer; Mails bleiben in `data/mailboxes/`. PST mit echter Datei unter Windows testen
- 182 Tests: `python -m pytest tests -q` (unter Linux schlagen 2 PE-Tests fehl, die `sys.executable`
  als Windows-EXE voraussetzen; 13 Sandbox-Tests laufen nur unter Windows)
- Design/Begründungen: `docs/design-universal-threat-analysis.md`

## Fehler-Runde (zuletzt)
- In Bildern/PDFs/Dokumenten versteckte **ELF**-Programme werden jetzt erkannt
  (`_find_embedded_elf` in `engines/analyzers/baseline.py`, Header validiert → keine FPs auf 260 echten Dateien)
- Tests unter Linux grün: 165 bestanden, 17 Windows-only übersprungen
- Batch-Scan: PRNU-Vergleich pro Datei abgeschaltet (`similar(..., use_prnu=False)`) → deutlich schneller
- Analyse-Tabs kompakter (META/JSON), alle 14 Tabs passen ab ~1100 px Breite
- README: ASCII-Logo, „How it works“-Pipeline, Screenshot-Galerie
- Aufgeräumt für die Veröffentlichung: alte Standalone-Skripte (`dgkn_copytrace.py`, `thumbcache_engine_standalone.py`),
  leere `tlsh`-Wheel entfernt, Notizen nach `docs/` verschoben, ungenutzte Importe/Variablen entfernt

## Veröffentlichung
- Lizenz: **GPL-3.0-or-later** (`LICENSE`, `THIRD_PARTY_NOTICES.md`), passend zu PyQt6
- Windows-Builds: `scripts\build_windows.ps1` → `dist\SENTINEL-F-<ver>-Setup-win64.exe` (Inno Setup, `installer/sentinel-f.iss`)
  und `dist\SENTINEL-F-<ver>-Portable-win64.zip` (Marker `portable.txt` → Daten in `UserData\`)
- Release automatisch: `git tag v1.0.0 && git push origin v1.0.0` → GitHub Actions (`.github/workflows/windows-release.yml`)
  testet, baut beide Editionen und hängt sie an ein Release
- Datenorte: Quellcode `data/`, Setup `%LOCALAPPDATA%\DGKN-FileForensic\`, Portable `UserData\`; `DGKN_USER_DIR` überschreibt
- Schlüssel kommen bei der EXE aus `<Nutzerdaten>\local_secrets.py`, die Spec schließt `config.local_secrets` aus
  (auf Linux mit Dummy-Schlüssel gebaut und geprüft: nicht im Build)
- **Unter Windows prüfen:** Setup installieren, Rechtsklick „Mit SENTINEL-F analysieren“, Portable vom USB-Stick,
  Deinstallation (Nutzerdaten bleiben erhalten)

## Windows-CI (GitHub Actions) – grün
- Lauf „Windows build“: alle Tests + Sandbox-Proben auf windows-latest grün, Setup + Portable gebaut
  (SENTINEL-F-1.0.0-Setup-win64.exe, SENTINEL-F-1.0.0-Portable-win64.zip, SHA256SUMS.txt)
- Dabei gefunden und behoben: Testdateinamen mit | < > (unter Windows unzulässig), blockierender Hinweis-Dialog
  beim Postfach-Scan, Postfach-Zerlegung jetzt wie jede Analyse bevorzugt im AppContainer (Datei/Ordner wird
  in den Job-Ordner kopiert), Startprüfung erkannte mailbox.json nicht
- Auf dem GitHub-Runner startet ein reiner Low-IL-Prozess nicht (0xC0000135); die Low-IL-Proben werden dort mit
  Begründung übersprungen, dieselben Proben laufen im AppContainer. Auf normalen PCs lief Low IL (Screenshots).

## Zwei Repos
- **dogenc/DGKN_FileForensic** (privat): Arbeits-Repo mit voller Historie
- **dogenc/SENTINEL-F** (öffentlich): je Release ein einziger Commit mit dem aktuellen Stand, dort laufen
  Windows-Build und Releases. Veröffentlichen: `scripts/publish_public.sh` (erzeugt einen Commit ohne Historie)

## Release
- **v1.0.0 veröffentlicht:** https://github.com/dogenc/DGKN_FileForensic/releases/tag/v1.0.0
  (Setup 180 MB, Portable 282 MB, SHA256SUMS.txt)
- Nächstes Release: `APP_VERSION` in config/settings.py erhöhen, dann Actions → Windows build → Run workflow → release ☑

## Offen
1. ~~Alte Bild-Engine: Fehlalarme bei `clone_detected` / `jpeg_ghost`~~ → neu geschrieben
   (Ghost = zweite JPEG-Qualität als zusammenhängende Fläche, Copy-Move = eine dominante Verschiebung).
   0 Treffer auf 58 echten Fotos, 5/5 Klone und 4/5 eingefügte Regionen erkannt (`tests/test_image_forgery.py`).
   **Unter Windows prüfen:** Hintergrundbilder in `C:\Windows\Web\Wallpaper` sollten jetzt sauber sein.
2. **EXE-Build** (`pyinstaller DGKN_FileForensic.spec`) bauen und testen, dabei prüfen,
   ob die Sandbox-Worker mit `--sentinel-worker` / `--sentinel-diff` / `--sentinel-mailbox` in der EXE starten
   (Spec sammelt jetzt alle Projektmodule automatisch, inkl. QtPrintSupport für PDF-Berichte)
3. RAR-Inhalte werden nur am Header erkannt (kein `rarfile`)
4. ~~Netzwerk im Sandbox-Worker nicht gesperrt~~ → AppContainer (`core/appcontainer.py`) umgesetzt.
   **Unter Windows noch einmal prüfen:** `python -m pytest tests/test_sandbox.py -v` (Sonden `network`,
   `read_user`, Analyse im AppContainer). Scheitert die Einrichtung, läuft der Low-IL-Worker weiter
   und `result['sandbox']['network']` nennt den Grund.

## Nächste Feature-Ideen (Reihenfolge)
1. Zeitleisten-Widersprüche optional als (niedrig gewichtetes) Signal in den Score übernehmen

## Einrichtung auf einem neuen PC
```bash
git clone https://github.com/dogenc/DGKN_FileForensic.git
pip install -r requirements.txt
```
Danach `config/local_secrets.example.py` nach `config/local_secrets.py` kopieren und
`CESIUM_ION_TOKEN` und `MAPTILER_KEY` eintragen (die Datei steht nicht im Repo) oder die Umgebungsvariablen `DGKN_CESIUM_ION_TOKEN` und
`DGKN_MAPTILER_KEY` setzen.
