"""
MITRE ATT&CK®-Zuordnung der SENTINEL-F-Signale (Enterprise-Matrix).

Jeder Finding-Code wird – nur wo die Zuordnung eindeutig ist – auf Techniken
abgebildet. Reine Kontext-Signale (Hashes, Metadaten, Entropie …) bekommen
bewusst keine Technik, damit die Matrix nichts vortäuscht.

map_result(result) liefert:
  {"techniques": [{id, name, tactics, url, codes, severity}], "tactics": {tactic: n}}
INFO-Signale erscheinen in der Liste, zählen aber nicht zur Taktik-Heatmap.
"""

# Taktiken in Matrix-Reihenfolge (Kill-Chain)
TACTICS = [
    ("TA0001", "Initial Access"), ("TA0002", "Execution"), ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"), ("TA0005", "Defense Evasion"), ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"), ("TA0009", "Collection"), ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]
TACTIC_NAMES = [n for _, n in TACTICS]

IA, EX, PE_, PR, DE, CA, DI, CO, C2, EF, IM = TACTIC_NAMES

# Technik-ID → (Name, Taktiken)
TECHNIQUES = {
    "T1566.001": ("Phishing: Spearphishing Attachment", [IA]),
    "T1566.002": ("Phishing: Spearphishing Link", [IA]),
    "T1189":     ("Drive-by Compromise", [IA]),
    "T1204.002": ("User Execution: Malicious File", [EX]),
    "T1203":     ("Exploitation for Client Execution", [EX]),
    "T1059":     ("Command and Scripting Interpreter", [EX]),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", [EX]),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", [EX]),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", [EX]),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", [EX]),
    "T1218":     ("System Binary Proxy Execution", [DE]),
    "T1218.005": ("System Binary Proxy Execution: Mshta", [DE]),
    "T1547.001": ("Boot or Logon Autostart: Registry Run Keys / Startup Folder", [PE_, PR]),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", [EX, PE_, PR]),
    "T1505.003": ("Server Software Component: Web Shell", [PE_]),
    "T1055":     ("Process Injection", [DE, PR]),
    "T1027":     ("Obfuscated Files or Information", [DE]),
    "T1027.001": ("Obfuscated Files or Information: Binary Padding", [DE]),
    "T1027.002": ("Obfuscated Files or Information: Software Packing", [DE]),
    "T1027.006": ("Obfuscated Files or Information: HTML Smuggling", [DE]),
    "T1027.009": ("Obfuscated Files or Information: Embedded Payloads", [DE]),
    "T1027.012": ("Obfuscated Files or Information: LNK Icon Smuggling", [DE]),
    "T1027.013": ("Obfuscated Files or Information: Encrypted/Encoded File", [DE]),
    "T1140":     ("Deobfuscate/Decode Files or Information", [DE]),
    "T1036":     ("Masquerading", [DE]),
    "T1036.002": ("Masquerading: Right-to-Left Override", [DE]),
    "T1036.005": ("Masquerading: Match Legitimate Name or Location", [DE]),
    "T1036.007": ("Masquerading: Double File Extension", [DE]),
    "T1036.008": ("Masquerading: Masquerade File Type", [DE]),
    "T1070.006": ("Indicator Removal: Timestomp", [DE]),
    "T1221":     ("Template Injection", [DE]),
    "T1553.005": ("Subvert Trust Controls: Mark-of-the-Web Bypass", [DE]),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", [DE]),
    "T1564":     ("Hide Artifacts", [DE]),
    "T1564.003": ("Hide Artifacts: Hidden Window", [DE]),
    "T1620":     ("Reflective Code Loading", [DE]),
    "T1622":     ("Debugger Evasion", [DE, DI]),
    "T1656":     ("Impersonation", [DE]),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", [CA]),
    "T1555":     ("Credentials from Password Stores", [CA]),
    "T1056.001": ("Input Capture: Keylogging", [CO, CA]),
    "T1056.003": ("Input Capture: Web Portal Capture", [CO, CA]),
    "T1105":     ("Ingress Tool Transfer", [C2]),
    "T1090.003": ("Proxy: Multi-hop Proxy", [C2]),
    "T1095":     ("Non-Application Layer Protocol", [C2]),
    "T1102":     ("Web Service", [C2]),
    "T1567":     ("Exfiltration Over Web Service", [EF]),
    "T1486":     ("Data Encrypted for Impact", [IM]),
    "T1490":     ("Inhibit System Recovery", [IM]),
    "T1496":     ("Resource Hijacking", [IM]),
    "T1499":     ("Endpoint Denial of Service", [IM]),
}

# Finding-Code → Techniken
CODE_MAP = {
    # Tarnung / Dateityp
    "disguised_executable": ["T1036.008", "T1204.002"],
    "extension_mismatch": ["T1036.008"],
    "double_extension": ["T1036.007", "T1204.002"],
    "archive_double_extension": ["T1036.007"],
    "rtlo_filename": ["T1036.002"],
    "filename_padding": ["T1036"],
    "pe_fake_vendor": ["T1036.005"],
    "pe_name_mismatch": ["T1036.005"],
    "pe_timestamp_anomaly": ["T1070.006"],
    # Eingebettete / versteckte Nutzlast
    "embedded_executable": ["T1027.009"],
    "nested_payload_critical": ["T1027.009"],
    "appended_data": ["T1027.009"],
    "polyglot": ["T1027.009"],
    "pe_overlay": ["T1027.009"],
    "pe_signed_appended": ["T1027.009"],
    "base64_executable": ["T1027.013", "T1140"],
    "embedded_objects": ["T1027.009"],
    "container_executable": ["T1553.005", "T1204.002"],
    "archive_executable": ["T1204.002"],
    "archive_encrypted": ["T1027.013"],
    "nested_archives": ["T1027"],
    # Packer / Verschleierung
    "pe_packed": ["T1027.002"],
    "pe_high_entropy_section": ["T1027.002"],
    "pe_wx_section": ["T1027.002"],
    "elf_wx_segment": ["T1027.002"],
    "script_obfuscation": ["T1027"],
    "encoded_powershell": ["T1059.001", "T1027", "T1140"],
    "rtf_obfuscation": ["T1027"],
    "lnk_padding": ["T1027.001"],
    "lnk_icon_masquerade": ["T1027.012", "T1036"],
    "hidden_content": ["T1564"],
    # Programm-Fähigkeiten
    "pe_injection_apis": ["T1055"],
    "pe_keylogger_apis": ["T1056.001"],
    "pe_antidebug": ["T1622"],
    "pe_tls_callback": ["T1622"],
    "pe_dropper_combo": ["T1105"],
    "pe_ransomware_combo": ["T1486"],
    # Skripte / Ausführung
    "script_downloader": ["T1105"],
    "script_dropper": ["T1105"],
    "script_exec": ["T1059"],
    "script_execution_policy": ["T1059.001"],
    "script_hidden_window": ["T1564.003"],
    "script_amsi_bypass": ["T1562.001"],
    "script_defense_evasion": ["T1562.001"],
    "defender_tamper": ["T1562.001"],
    "script_persistence": ["T1547.001", "T1053.005"],
    "persistence": ["T1547.001", "T1053.005"],
    "script_webshell": ["T1505.003"],
    "script_credential": ["T1555"],
    "credential_access": ["T1003.001"],
    "script_reflective_load": ["T1620"],
    "script_ransom": ["T1486"],
    "ransom_prep": ["T1490"],
    "lolbin": ["T1218", "T1105"],
    "reverse_shell": ["T1059.004", "T1095"],
    "crypto_miner": ["T1496"],
    "hta_file": ["T1218.005"],
    "lnk_command": ["T1204.002", "T1059"],
    "lnk_remote_target": ["T1204.002"],
    "macro_present": ["T1059.005"],
    "macro_suspicious": ["T1059.005", "T1204.002"],
    "javascript": ["T1059.007"],
    "svg_script": ["T1059.007", "T1027.006"],
    # Exploits / Dokumente
    "rtf_equation_exploit": ["T1203"],
    "rtf_autoupdate": ["T1221"],
    "external_relationship": ["T1221"],
    "path_traversal": ["T1203"],
    # Web / Phishing / C2
    "html_smuggling": ["T1027.006"],
    "phishing_form": ["T1056.003", "T1566.002"],
    "phishing_exfil": ["T1567", "T1102"],
    "hidden_iframe": ["T1189"],
    "web_redirect": ["T1566.002"],
    "tor_address": ["T1090.003"],
    # E-Mail
    "email_display_spoof": ["T1656", "T1566.001"],
    "email_sender_mismatch": ["T1656"],
    "email_reply_mismatch": ["T1656"],
    "email_auth_fail": ["T1656"],
    "email_dangerous_attachment": ["T1566.001", "T1204.002"],
    "email_risky_attachment": ["T1566.001"],
    "email_masked_link": ["T1566.002"],
    # Bomben
    "zip_bomb": ["T1499"],
    "zip_overlap": ["T1499"],
    "decompression_ratio_high": ["T1499"],
    "image_bomb": ["T1499"],
}

SEV_RANK = {"INFO": 0, "WARN": 1, "CRIT": 2}


def technique_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def map_findings(findings):
    techs = {}
    for f in findings or []:
        sev = (f.get("severity") or "INFO").upper()
        for tid in CODE_MAP.get(f.get("code"), []):
            name, tactics = TECHNIQUES[tid]
            t = techs.setdefault(tid, {"id": tid, "name": name, "tactics": tactics, "url": technique_url(tid),
                                       "codes": [], "severity": "INFO"})
            if f["code"] not in t["codes"]:
                t["codes"].append(f["code"])
            if SEV_RANK.get(sev, 0) > SEV_RANK[t["severity"]]:
                t["severity"] = sev
    ordered = sorted(techs.values(), key=lambda t: (-SEV_RANK[t["severity"]],
                                                     TACTIC_NAMES.index(t["tactics"][0]), t["id"]))
    tactics = {n: 0 for n in TACTIC_NAMES}
    for t in ordered:
        if t["severity"] != "INFO":
            for tac in t["tactics"]:
                tactics[tac] += 1
    return {"techniques": ordered, "tactics": tactics}


def map_result(result):
    """ATT&CK-Sicht eines Ergebnisses (auch für ältere, gespeicherte Ergebnisse)."""
    if isinstance(result.get("attack"), dict):
        return result["attack"]
    return map_findings((result.get("score") or {}).get("findings"))
