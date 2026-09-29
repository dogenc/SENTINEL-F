"""
╔══════════════════════════════════════════════════════════════╗
║         DGKN@Labs FileForensic - Central Configuration       ║
║                    v1.0.0  by DGKN@Labs  2026                ║
╚══════════════════════════════════════════════════════════════╝
"""
from pathlib import Path

# ─── Application ──────────────────────────────────────────────────────────────
APP_NAME       = "DGKN@Labs-FileForensic"
APP_VERSION    = "1.0.0"
APP_CODENAME   = "SENTINEL-F"
APP_BUILD      = "2026.04.19"
APP_AUTHOR     = "DGKN@Labs"
APP_DESC       = "Unified Forensic Intelligence Suite // Classified-Tier"

# ─── Paths ────────────────────────────────────────────────────────────────────
# Drei Betriebsarten:
#   Quellcode   → alles im Projektordner (data/, reports/, .cache/)
#   Setup (EXE) → Programm unter Programme\, Nutzerdaten unter %LOCALAPPDATA%\DGKN-FileForensic
#   Portable    → Datei "portable.txt" neben der EXE: Nutzerdaten in UserData\ neben der EXE
# DGKN_USER_DIR überschreibt den Ort der Nutzerdaten in jedem Modus.
import sys as _sys
FROZEN         = bool(getattr(_sys, "frozen", False))
APP_DIR        = Path(_sys.executable).resolve().parent if FROZEN else Path(__file__).resolve().parent.parent
BASE_DIR       = Path(getattr(_sys, "_MEIPASS", APP_DIR))          # Programmteile (Code, resources/)
PORTABLE       = FROZEN and (APP_DIR / "portable.txt").exists()


def _user_dir():
    import os
    if os.environ.get("DGKN_USER_DIR"):
        return Path(os.environ["DGKN_USER_DIR"])
    if not FROZEN:
        return APP_DIR
    if PORTABLE:
        return APP_DIR / "UserData"
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / "DGKN-FileForensic"


USER_DIR       = _user_dir()
RESOURCE_DIR   = BASE_DIR / "resources"
REPORT_DIR     = USER_DIR / "reports"
CACHE_DIR      = USER_DIR / ".cache"
DATA_DIR       = USER_DIR / "data"
HISTORY_DB     = DATA_DIR / "sentinel_history.db"   # Analyse-Verlauf & Fälle (core/history.py)
for _d in (REPORT_DIR, CACHE_DIR):
    try:
        _d.mkdir(exist_ok=True, parents=True)
    except OSError:   # Sandbox-Worker (Low Integrity) darf hier nicht schreiben – braucht es auch nicht
        pass

# ─── External Services ────────────────────────────────────────────────────────
# Keys kommen aus Umgebungsvariablen oder config/local_secrets.py (gitignored).
import os as _os
def _load_secrets():
    if FROZEN:
        # Die EXE enthält nie Schlüssel: sie liegen in <Nutzerdaten>\local_secrets.py
        import types
        p = USER_DIR / "local_secrets.py"
        try:
            src = p.read_text(encoding="utf-8")
        except OSError:              # fehlt, oder im AppContainer-Worker bewusst nicht lesbar
            return None
        mod = types.ModuleType("local_secrets")
        try:
            exec(compile(src, str(p), "exec"), mod.__dict__)
        except Exception:
            return None
        return mod
    try:
        from config import local_secrets
        return local_secrets
    except (ImportError, OSError):   # OSError: im AppContainer-Worker bewusst nicht lesbar
        return None


_ls = _load_secrets()
CESIUM_ION_TOKEN  = _os.environ.get("DGKN_CESIUM_ION_TOKEN") or getattr(_ls, "CESIUM_ION_TOKEN", "")
MAPTILER_KEY      = _os.environ.get("DGKN_MAPTILER_KEY") or getattr(_ls, "MAPTILER_KEY", "")

# ─── Sandbox ──────────────────────────────────────────────────────────────────
# True: jede Datei wird in einem isolierten Low-Integrity-Prozess im Job Object
# analysiert (kann nichts starten, nichts schreiben, max. 2 GiB RAM).
# Nur zum Debuggen abschalten.
SANDBOX_ENABLED = True
# True: Worker läuft im AppContainer ohne Capabilities → kein Netzwerkzugriff (ohne Adminrechte).
# Scheitert die Einrichtung, fällt SENTINEL-F automatisch auf den Low-IL-Worker zurück (im Befund vermerkt).
SANDBOX_BLOCK_NETWORK = True

# ─── Berichte ─────────────────────────────────────────────────────────────────
REPORT_SIGN = True          # jeden Bericht mit dem Arbeitsplatz-Schlüssel (Ed25519) signieren → <bericht>.sig
# Optional: RFC-3161-Zeitstempeldienst (nur der SHA-256 des Berichts wird gesendet), z. B.
# "https://freetsa.org/tsr" – leer = aus
REPORT_TSA_URL = _os.environ.get("DGKN_TSA_URL", "")

# ─── Hash-Abfrage (Threat-Intel) ──────────────────────────────────────────────
# Aus = es wird nichts gesendet. An = nur der SHA-256 geht an CIRCL hashlookup (ohne Schlüssel) sowie
# VirusTotal / MalwareBazaar, falls VT_API_KEY / MB_AUTH_KEY in config/local_secrets.py stehen.
HASH_LOOKUP_ENABLED = _os.environ.get("DGKN_HASH_LOOKUP", "") == "1"

# ─── Ollama (Local AI) ────────────────────────────────────────────────────────
OLLAMA_HOST       = "http://127.0.0.1:11434"
OLLAMA_MODEL      = "phi3:3.8b-mini-4k-instruct-q4_K_M"
OLLAMA_TIMEOUT    = 120       # seconds
OLLAMA_TEMPERATURE = 0.2      # low for deterministic forensic analysis

# ─── Color Theme — CIA / Palantir Intelligence Aesthetic ──────────────────────
# Dominant: deep black/graphite. Accents: phosphor-green & cyan. Warnings: amber/red.
T = {
    # Base surfaces
    "bg":           "#05070a",   # near-black main
    "bg_alt":       "#0a0e14",   # slightly lifted
    "panel":        "#0d1218",   # panels
    "card":         "#10161e",   # cards / tiles
    "card_hover":   "#141b24",
    "border":       "#1a2430",
    "border_hot":   "#2a3b4f",   # highlighted borders
    "grid":         "#0f1620",   # background grid
    # Text
    "text":         "#c9d4dc",
    "text_dim":     "#7a8a98",
    "text_mute":    "#4a5868",
    "text_hot":     "#e8f1f6",
    # Primary brand — phosphor green (terminal / intel display)
    "accent":       "#35ff8a",
    "accent_dim":   "#1b9d55",
    "accent_glow":  "rgba(53,255,138,0.18)",
    # Secondary — cyan (data / telemetry)
    "cyan":         "#4de6ff",
    "cyan_dim":     "#2a8fa8",
    # Status palette
    "ok":           "#35ff8a",
    "info":         "#4de6ff",
    "warn":         "#ffb648",
    "err":          "#ff4d6d",
    "crit":         "#ff2a3f",
    # Score palette (0-100 risk gradient)
    "score_0":      "#35ff8a",    # 0-20 clean
    "score_1":      "#a8e95f",    # 20-40 low
    "score_2":      "#ffd93d",    # 40-60 medium
    "score_3":      "#ff8a3d",    # 60-80 high
    "score_4":      "#ff2a3f",    # 80-100 critical
}

# ─── Fonts ────────────────────────────────────────────────────────────────────
FONT_MONO      = "JetBrains Mono"
FONT_MONO_ALT  = "Consolas"          # Windows fallback
FONT_DISPLAY   = "JetBrains Mono"    # same — full monospaced aesthetic
FONT_UI        = "Segoe UI"

FONT_SIZE_XS   = 9
FONT_SIZE_SM   = 10
FONT_SIZE_MD   = 11
FONT_SIZE_LG   = 13
FONT_SIZE_XL   = 16
FONT_SIZE_XXL  = 22

# ─── Score Engine Thresholds ──────────────────────────────────────────────────
# Heuristic manipulation score 0-100
SCORE_WEIGHTS = {
    # Universal
    "hash_mismatch":          15,
    "metadata_stripped":       8,
    "metadata_inconsistent":  12,
    "timestamp_anomaly":       6,
    "entropy_suspicious":      8,
    # Image-specific
    "ela_high":               14,
    "jpeg_ghost":             12,
    "clone_detected":         16,
    "lsb_anomaly":             7,
    "thumbnail_mismatch":     10,
    # Document-specific
    "macro_present":          12,
    "macro_suspicious":       18,
    "hidden_content":         10,
    "embedded_objects":        6,
    "revision_history":        4,
    "external_relationship":   6,
    # PDF-specific
    "javascript":              8,
    "redactions":             10,
    "encryption_inconsistent": 6,
    "black_rectangles":        7,
    "unused_objects":          3,

    # ── Universelle Bedrohungsanalyse (engines/analyzers) ──────────────────
    # Faustregel: ein harter Einzeltreffer (CRIT ×1.3) erreicht allein HIGH RISK.
    # Datei / Tarnung
    "rtlo_filename":          55,
    "double_extension":       55,
    "disguised_executable":   55,
    "filename_padding":       20,
    "extension_mismatch":     12,
    "embedded_executable":    35,
    "nested_payload_critical": 50,     # eine extrahierte Stufe ist HIGH RISK/CRITICAL
    "nested_payload_suspicious": 20,   # eine extrahierte Stufe ist ELEVATED
    "payload_budget":          0,
    # Foto-Echtheit
    "ai_generated":           30,      # harte Generator-Spur (SD-Parameter, IPTC trainedAlgorithmicMedia …)
    "c2pa_ai_declared":       30,
    "ai_generated_hint":       4,
    "c2pa_present":            0,
    "base64_executable":      45,
    "polyglot":               15,
    "appended_data":          10,
    "network_iocs":            4,
    "tor_address":            15,
    "crypto_wallet":           6,
    "motw_internet":           3,
    "motw_present":            0,
    # Befehlsmuster
    "ransom_prep":            50,
    "defender_tamper":        45,
    "credential_access":      45,
    "reverse_shell":          50,
    "crypto_miner":           25,
    "lolbin":                 20,
    "encoded_powershell":     20,
    "persistence":            12,
    # Archive / Zipbomb / Bild-Bombe / Sandbox
    "zip_bomb":               65,
    "image_bomb":             60,
    "sandbox_violation":      60,
    "zip_overlap":            55,
    "nested_archives":        20,
    "path_traversal":         45,
    "archive_double_extension": 50,
    "container_executable":   40,
    "decompression_ratio_high": 15,
    "archive_size_mismatch":  15,
    "archive_too_many_entries": 12,
    "archive_symlink":        15,
    "archive_device_file":    10,
    "archive_setuid":         10,
    "archive_encrypted":      10,
    "archive_executable":     15,
    "archive_corrupt":         6,
    "archive_scan_incomplete": 0,
    # Windows-Programme
    "pe_injection_apis":      35,
    "pe_ransomware_combo":    25,
    "pe_dropper_combo":       20,
    "pe_keylogger_apis":      18,
    "pe_fake_vendor":         30,
    "pe_signed_appended":     25,
    "pe_packed":              15,
    "pe_entrypoint_anomaly":  15,
    "pe_malformed":           15,
    "pe_wx_section":          12,
    "pe_high_entropy_section": 10,
    "pe_antidebug":           10,
    "pe_tls_callback":         8,
    "pe_overlay":              8,
    "pe_timestamp_anomaly":    6,
    "pe_name_mismatch":        5,
    "pe_unsigned":             4,
    # Linux-Programme
    "elf_no_sections":        15,
    "elf_wx_segment":         12,
    "elf_static":              4,
    # Skripte
    "script_webshell":        55,
    "script_amsi_bypass":     45,
    "script_defense_evasion": 45,
    "script_ransom":          45,
    "script_credential":      40,
    "script_reflective_load": 40,
    "script_dropper":         40,
    "script_downloader":      20,
    "script_obfuscation":     18,
    "script_hidden_window":   15,
    "script_persistence":     15,
    "script_exec":            10,
    "script_execution_policy": 6,
    # Web / Phishing
    "html_smuggling":         50,
    "phishing_form":          45,
    "phishing_exfil":         45,
    "svg_script":             20,
    "hta_file":               20,
    "hidden_iframe":          15,
    "web_redirect":            4,
    # Verknüpfungen
    "lnk_icon_masquerade":    35,
    "lnk_command":            30,
    "lnk_padding":            20,
    "lnk_remote_target":      15,
    # RTF
    "rtf_equation_exploit":   55,
    "rtf_autoupdate":         30,
    "rtf_ole_object":         15,
    "rtf_obfuscation":        15,
    # E-Mail
    "email_dangerous_attachment": 45,
    "email_display_spoof":    35,
    "email_masked_link":      35,
    "email_auth_fail":        20,
    "email_risky_attachment": 15,
    "email_reply_mismatch":   12,
    "email_sender_mismatch":   4,
    # Datenbanken (forensische Hinweise, kein Risiko)
    "sqlite_deleted_data":     4,
    "sqlite_journal":          2,
    "sqlite_known_db":         0,
    "sqlite_unreadable":       0,
    # YARA
    "yara_match":             30,
    "yara_timeout":            0,
}

SCORE_LEVELS = [
    (0,   "CLEAN",         "score_0"),
    (20,  "LOW RISK",      "score_1"),
    (40,  "ELEVATED",      "score_2"),
    (60,  "HIGH RISK",     "score_3"),
    (80,  "CRITICAL",      "score_4"),
]

# ─── Supported File Types ─────────────────────────────────────────────────────
EXT_IMAGE   = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"}
EXT_PDF     = {".pdf"}
EXT_DOC_OOX = {".docx", ".xlsx", ".pptx"}
EXT_DOC_OLE = {".doc", ".xls", ".ppt"}
EXT_ALL     = EXT_IMAGE | EXT_PDF | EXT_DOC_OOX | EXT_DOC_OLE
# Seit der universellen Analyse wird JEDE Datei untersucht; EXT_* steuern nur noch
# die Vorschau und die Tiefenanalyse der klassischen Engines.
