# LinkedIn-Post · SENTINEL-F

Bild: `docs/promo/linkedin-post.png` (1200 × 1200)

---

🛰️ Ich habe ein Forensik-Tool gebaut – und stelle es heute Open Source: SENTINEL-F

Eine verdächtige Datei landet im Postfach. Rechnung.pdf? Oder eine getarnte EXE?
Bewerbungsunterlagen.zip? Oder eine Zip-Bombe, die 1 GB aus 21 KB macht?

SENTINEL-F beantwortet das, ohne die Datei je auszuführen:

🛡 Jede Datei wird in einer eigenen Windows-Sandbox zerlegt – AppContainer ohne Netzwerk, Job Object, 2 GiB-Limit, keine Adminrechte nötig
💣 Zip-, Bild- und XML-Bomben werden gemessen statt entpackt
🎭 Getarnte Programme, RTLO-Tricks, Makros, Webshells, HTML-Smuggling, Phishing-Kits
🔓 Payload-Kette: E-Mail → ZIP → JavaScript → PowerShell wird Stufe für Stufe freigelegt
🎯 Jedes Signal auf MITRE ATT&CK gemappt, als Kill-Chain-Heatmap
🕸 IOC-Graph über alle Fälle – aus einem Kampagnen-Cluster entsteht per Klick eine getestete YARA-Regel
📸 Foto-Echtheit: C2PA, KI-Generator-Spuren, Kamera-Fingerabdruck (PRNU), eingefügte und geklonte Bildbereiche
🗺 GPS-Bewegungsprofil deckt unmögliche Routen auf, der Vorher-Nachher-Vergleich zeigt retuschierte Stellen
🕵 Detektiv-Modus: Tathergang, in dem jeder Satz auf ein nummeriertes Beweisstück verweist
📄 Forensische Berichte mit Beweiskette, Ed25519-signiert, optional mit RFC-3161-Zeitstempel

Gebaut für Sicherheitstester, Forensiker und Incident Response.
Läuft komplett lokal. Nichts verlässt den Rechner, außer du schaltest die Hash-Abfrage bewusst ein.

⚙️ Python · PyQt6 · 199 Tests
🤖 Entwickelt von DGKN@Labs mit KI-Unterstützung: Idee, Architektur, Tests und eigener Code von mir, beschleunigt mit KI.
💾 Windows-Setup & Portable-Version · GPL-3.0

👉 github.com/dogenc/SENTINEL-F

Feedback, Issues und Pull Requests sind sehr willkommen – und wer es nutzt: bitte den Namen DGKN@Labs drin lassen 😉

#CyberSecurity #DigitalForensics #DFIR #IncidentResponse #MalwareAnalysis #ThreatIntelligence #OpenSource #InfoSec #Python #BlueTeam

---

## Kurzversion (falls der Text zu lang ist)

🛰️ SENTINEL-F ist jetzt Open Source!

Mein Forensik-Tool zerlegt jede Datei in einer Windows-Sandbox ohne Netzwerk und erkennt Malware, getarnte Programme, Zip-Bomben und manipulierte Fotos und Dokumente. Es mappt alles auf MITRE ATT&CK, verknüpft Fälle im IOC-Graph und schreibt signierte Forensik-Berichte.

Für Sicherheitstester, DFIR und Blue Teams. Setup & Portable für Windows, GPL-3.0.
Entwickelt von DGKN@Labs mit KI-Unterstützung.

👉 github.com/dogenc/SENTINEL-F

#CyberSecurity #DFIR #MalwareAnalysis #OpenSource #InfoSec

---

## English version

🛰️ I built a file-forensics suite – and it's now open source: SENTINEL-F

Every file is taken apart inside its own Windows sandbox (AppContainer, no network, Job Object) and never executed. It catches zip bombs, disguised executables, macro and script droppers, HTML smuggling and phishing kits. It unpacks payload chains layer by layer, maps every signal to MITRE ATT&CK and links cases in an IOC graph that turns campaigns into tested YARA rules. It checks photo authenticity (C2PA, AI traces, camera fingerprint, spliced and cloned regions) and writes chain-of-custody reports signed with Ed25519.

Built for security testers, DFIR and blue teams. Runs fully local.
Developed by DGKN@Labs with AI assistance. Windows Setup & Portable, GPL-3.0.

👉 github.com/dogenc/SENTINEL-F

#CyberSecurity #DigitalForensics #DFIR #MalwareAnalysis #OpenSource #InfoSec
