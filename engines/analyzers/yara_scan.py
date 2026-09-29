"""
YARA-Scan mit den mitgelieferten Regeln (resources/yara/*.yar) und optional einem
eigenen Regelordner (Umgebungsvariable DGKN_YARA_DIR), z. B. für YARA-Forge-Pakete.
Jede Regeldatei wird einzeln kompiliert – eine fehlerhafte Datei legt nicht alles lahm.
"""
import os
import threading
from pathlib import Path

from config.settings import RESOURCE_DIR
from . import limits
from .base import finding

_lock = threading.Lock()
_cache = {"key": None, "rules": None, "errors": []}


def rule_dirs():
    from config.settings import DATA_DIR
    # data/yara_generated: aus eigenen Fällen erzeugte Regeln (core/intel.py)
    dirs = [RESOURCE_DIR / "yara", DATA_DIR / "yara_generated"]
    extra = os.environ.get("DGKN_YARA_DIR")
    if extra:
        dirs.append(Path(extra))
    return [d for d in dirs if d.is_dir()]


def _rule_files():
    files = []
    for d in rule_dirs():
        files += sorted(p for p in d.rglob("*") if p.suffix.lower() in (".yar", ".yara"))
    return files


def load_rules():
    import yara
    files = _rule_files()
    key = tuple((str(f), f.stat().st_mtime) for f in files)
    with _lock:
        if _cache["key"] == key:
            return _cache["rules"], _cache["errors"]
        good, errors = {}, []
        for i, f in enumerate(files):
            try:
                yara.compile(filepath=str(f))
                good[f"r{i}_{f.stem}"] = str(f)
            except yara.Error as e:
                errors.append(f"{f.name}: {e}")
        rules = yara.compile(filepaths=good) if good else None
        _cache.update(key=key, rules=rules, errors=errors)
        return rules, errors


SEV = {"critical": "CRIT", "high": "CRIT", "medium": "WARN", "low": "INFO", "info": "INFO"}


class YaraAnalyzer:
    name = "yara"

    def applies(self, ctx):
        try:
            import yara  # noqa: F401
        except ImportError:
            return False
        return bool(_rule_files())

    def run(self, ctx):
        rules, errors = load_rules()
        d = {"rule_files": len(_rule_files()), "compile_errors": errors, "matches": []}
        if rules is None:
            return {"data": d, "findings": []}
        import yara
        try:
            if ctx.truncated:
                matches = rules.match(data=ctx.data, timeout=limits.YARA_TIMEOUT)
            else:
                matches = rules.match(filepath=ctx.path, timeout=limits.YARA_TIMEOUT)
        except yara.TimeoutError:
            return {"data": d, "findings": [finding("yara_timeout", "YARA-Scan nach Zeitlimit abgebrochen", "INFO")]}
        findings = []
        for m in matches:
            meta = dict(m.meta)
            sev = SEV.get(str(meta.get("severity", "medium")).lower(), "WARN")
            desc = meta.get("description") or m.rule
            strings = []
            for s in m.strings[:5]:
                for inst in s.instances[:2]:
                    strings.append({"id": s.identifier, "offset": inst.offset,
                                    "data": bytes(inst.matched_data[:48]).decode("latin-1")})
            d["matches"].append({"rule": m.rule, "tags": list(m.tags), "meta": meta, "strings": strings})
            findings.append(finding("yara_match", f"YARA {m.rule}: {desc}", sev))
        return {"data": d, "findings": findings}
