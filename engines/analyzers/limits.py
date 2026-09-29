"""
Zentrale Grenzwerte. Ein bösartiges Sample darf das Tool weder aufhängen noch
den Speicher füllen, deshalb gilt jede Obergrenze hier für alle Analysatoren.
"""
MiB = 1 << 20
GiB = 1 << 30

# Wie viele Bytes einer Datei maximal in den Speicher gelesen werden
# (Strings, IOCs, Signatursuche). Größere Dateien: Kopf + Ende.
SCAN_WINDOW = 64 * MiB
SCAN_TAIL = 8 * MiB

# Entropie-Profil
ENTROPY_BLOCK = 64 * 1024
ENTROPY_MAX_BLOCKS = 256

# Archive / Zipbomb
DECOMP_CAP_TOTAL = 1 * GiB          # max. entpackte Bytes (nur gezählt, sofort verworfen)
DECOMP_CAP_ENTRY = 512 * MiB
NESTED_READ_CAP = 32 * MiB          # max. Größe eines inneren Archivs, das im RAM geöffnet wird
MAX_NEST_DEPTH = 4
MAX_ENTRIES = 20_000
MAX_LISTED_ENTRIES = 300
ARCHIVE_TIME_BUDGET = 20.0          # Sekunden je Archiv

RATIO_WARN = 100
RATIO_CRIT = 1000
DECLARED_SIZE_CRIT = 20 * GiB

# Strings / IOCs
MAX_STRINGS = 400
MAX_IOCS_PER_TYPE = 100

# YARA
YARA_TIMEOUT = 30
