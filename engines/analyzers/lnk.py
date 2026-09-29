"""
Windows-Verknüpfungen (.lnk): versteckte Befehle in den Argumenten,
Icon-Tarnung (Verknüpfung sieht aus wie PDF, startet aber PowerShell),
Padding, das den Befehl im Eigenschaften-Dialog verbirgt.
"""
import re

from .base import finding

LOLBINS = re.compile(r"\b(?:powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|"
                     r"msiexec|forfiles|conhost|curl|wmic|schtasks|explorer)(?:\.exe)?\b", re.I)
DOC_ICONS = re.compile(r"(?:\.pdf|\.docx?|\.xlsx?|\.jpe?g|\.png|\.txt|acrobat|winword|excel|imageres\.dll|shell32\.dll)", re.I)


class LnkAnalyzer:
    name = "lnk"

    def applies(self, ctx):
        return ctx.subtype == "lnk"

    def run(self, ctx):
        import LnkParse3
        with open(ctx.path, "rb") as f:
            j = LnkParse3.lnk_file(f).get_json()
        data = j.get("data") or {}
        info = j.get("link_info") or {}
        hdr = j.get("header") or {}
        target = (info.get("local_base_path") or info.get("common_path_suffix") or data.get("relative_path") or "")
        args = data.get("command_line_arguments") or ""
        icon = data.get("icon_location") or ""
        d = {
            "target": target, "arguments": args[:4000], "arguments_length": len(args),
            "working_dir": data.get("working_directory"), "icon": icon,
            "description": data.get("description"), "window_style": hdr.get("windowstyle"),
            "target_times": {k: hdr.get(k) for k in ("creation_time", "modified_time", "accessed_time")},
            "link_flags": hdr.get("link_flags"),
        }
        extra = j.get("extra") or {}
        tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK") if isinstance(extra, dict) else None
        if tracker:
            # Rechnername + MAC des Erstellers – forensisch wertvoll
            d["creator_machine"] = tracker.get("machine_identifier")
            d["creator_mac"] = tracker.get("droid_file_identifier") or tracker.get("mac_address")

        findings = []
        cmd = f"{target} {args}"
        lol = LOLBINS.search(cmd)
        suspicious_args = re.search(r"https?://|\s-e(?:nc?|ncodedcommand)?\s|\biex\b|invoke-expression|downloadstring|"
                                    r"frombase64|-w(?:indowstyle)?\s+h|\\\\[\w.]+\\|javascript:|vbscript:|%comspec%",
                                    args, re.I)
        if lol and suspicious_args:
            findings.append(finding("lnk_command", f"Verknüpfung startet {lol.group(0)} mit verdächtigen Argumenten: "
                                                   f"„{args.strip()[:90]}“", "CRIT"))
        elif lol and args.strip():
            # z. B. „Developer PowerShell“, „Eingabeaufforderung hier“ – legitim häufig
            findings.append(finding("lnk_command", f"Verknüpfung startet {lol.group(0)}: „{args.strip()[:90]}“", "INFO"))
        if len(args) > 260 or re.search(r"\s{50,}", args):
            findings.append(finding("lnk_padding", f"Argumente {len(args):,} Zeichen lang / mit Leerraum aufgefüllt – "
                                                   f"der Befehl ist im Eigenschaften-Dialog nicht sichtbar", "WARN"))
        if lol and DOC_ICONS.search(icon):
            findings.append(finding("lnk_icon_masquerade", f"Icon täuscht ein Dokument vor ({icon[:60]}), startet aber {lol.group(0)}", "CRIT"))
        if (hdr.get("windowstyle") or "").upper() in ("SW_SHOWMINNOACTIVE", "SW_HIDE", "SW_SHOWMINIMIZED") and lol:
            findings.append(finding("script_hidden_window", "Verknüpfung startet minimiert/unsichtbar", "WARN"))
        if re.search(r"^\\\\|https?://", target + args):
            findings.append(finding("lnk_remote_target", "Ziel liegt auf einem Netzwerkpfad/Server", "WARN"))
        return {"data": d, "findings": findings}
