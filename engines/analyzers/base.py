"""
Gerüst für die Analysatoren: Kontext, Findings, Registry und isolierte Ausführung.

Ein Analysator ist ein Objekt mit
    name: str
    applies(ctx) -> bool
    run(ctx) -> {"data": dict, "findings": [finding(...)]}
Er darf die Datei nur lesen und nie etwas ausführen oder entpacken.
"""
import time
from functools import cached_property
from pathlib import Path

from . import limits


def finding(code, desc, severity="WARN", **extra):
    f = {"code": code, "desc": desc, "severity": severity.upper()}
    f.update(extra)
    return f


class FileContext:
    """Gemeinsamer, lazily gelesener Zustand einer Datei."""

    def __init__(self, path, filetype):
        self.path = str(path)
        self.p = Path(path)
        self.filetype = filetype
        self.size = self.p.stat().st_size
        self.category = filetype["category"]
        self.subtype = filetype["subtype"]
        self.ext = filetype["extension"]
        self.shared = {}   # Analysatoren können hier Ergebnisse teilen

    @cached_property
    def head(self):
        with open(self.path, "rb") as f:
            return f.read(64 * 1024)

    @cached_property
    def data(self):
        """Bis zu SCAN_WINDOW Bytes; bei größeren Dateien Kopf + Ende."""
        with open(self.path, "rb") as f:
            if self.size <= limits.SCAN_WINDOW:
                return f.read()
            head = f.read(limits.SCAN_WINDOW - limits.SCAN_TAIL)
            f.seek(self.size - limits.SCAN_TAIL)
            return head + f.read()

    @property
    def truncated(self):
        return self.size > limits.SCAN_WINDOW

    @cached_property
    def text(self):
        """Text-Dekodierung für Skript-/Web-/Mail-Analysatoren."""
        raw = self.data
        if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
            return raw.decode("utf-16", "replace")
        if len(raw) > 4 and raw[1:2] == b"\x00" and raw[3:4] == b"\x00":
            return raw.decode("utf-16-le", "replace")
        return raw.decode("utf-8", "replace").lstrip("﻿")


def json_safe(obj, depth=0):
    """Macht Analysator-Ausgaben JSON-serialisierbar (für Export + GUI)."""
    if depth > 12:
        return str(obj)
    if isinstance(obj, dict):
        return {str(k): json_safe(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [json_safe(v, depth + 1) for v in obj]
    if isinstance(obj, bytes):
        return obj[:256].hex() + ("…" if len(obj) > 256 else "")
    if isinstance(obj, float):
        return round(obj, 4)
    if obj is None or isinstance(obj, (str, int, bool)):
        return obj
    return str(obj)


def run_all(ctx, analyzers, log=None, progress=None, start=20, end=95):
    """Führt alle zuständigen Analysatoren isoliert aus."""
    log = log or (lambda *a, **k: None)
    data, findings = {}, []
    todo = []
    for a in analyzers:
        try:
            if a.applies(ctx):
                todo.append(a)
        except Exception as e:  # applies() selbst darf nie den Lauf stoppen
            data[a.name] = {"_error": f"applies: {type(e).__name__}: {e}"}
    for i, a in enumerate(todo):
        if progress:
            progress(f"Analyzer: {a.name}", int(start + (end - start) * i / max(1, len(todo))))
        t0 = time.perf_counter()
        try:
            res = a.run(ctx) or {}
            d = res.get("data") or {}
            fs = res.get("findings") or []
        except Exception as e:
            d, fs = {"_error": f"{type(e).__name__}: {e}"}, []
            log(f"Analyzer {a.name} failed: {e}", "WARN")
        d["_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        data[a.name] = json_safe(d)
        for f in fs:
            f.setdefault("source", a.name)
        findings.extend(json_safe(fs))
        if fs:
            log(f"{a.name}: {len(fs)} signal(s)", "WARN" if any(f["severity"] != "INFO" for f in fs) else "INFO")
    return data, findings
