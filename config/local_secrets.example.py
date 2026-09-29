"""
Vorlage für lokale Schlüssel.

1. Diese Datei nach  config/local_secrets.py  kopieren
2. Eigene Schlüssel eintragen

config/local_secrets.py steht in .gitignore und wird NIE committet.
Alternativ die Umgebungsvariablen DGKN_CESIUM_ION_TOKEN / DGKN_MAPTILER_KEY setzen
(die haben Vorrang vor dieser Datei).
"""

# 3-D-Globus: Cesium Ion Access Token – https://ion.cesium.com/tokens (kostenloses Konto)
CESIUM_ION_TOKEN = ""

# Satelliten-/Hybrid-Kacheln für den Globus – https://cloud.maptiler.com/account/keys/
MAPTILER_KEY = ""

# Optional – Hash-Abfrage (nur mit HASH_LOOKUP_ENABLED / DGKN_HASH_LOOKUP=1; es werden nur Hashes gesendet)
VT_API_KEY = ""       # https://www.virustotal.com/gui/my-apikey
MB_AUTH_KEY = ""      # https://auth.abuse.ch/  (MalwareBazaar)
