"""
Payload-Kette: versteckte Inhalte extrahieren und rekursiv analysieren.

Aus einer Datei werden im Speicher die „nächsten Stufen“ gelöst:
  Archiv-Einträge (ZIP/TAR/GZ/BZ2/XZ) · E-Mail-Anhänge · PDF-Anhänge ·
  VBA-Makros · PowerShell -EncodedCommand / FromBase64String · große
  Base64-Blöcke mit Datei-Signatur (HTML-Smuggling) · eingebettete PE-Programme ·
  Daten hinter dem Dateiende · LNK-Befehlszeilen
Jede Stufe durchläuft die komplette Analyse erneut (bis MAX_DEPTH). Ausgeführt
wird nichts. Zum Analysieren wird eine Stufe kurz in einen privaten Temp-Ordner
geschrieben – im Sandbox-Betrieb liegt der im abgeschotteten Job-Ordner – und
sofort wieder gelöscht.

Ergebnis: ein Baum result['payloads'] und Findings für den Elternteil, wenn eine
Stufe gefährlich ist (die Gefahr „erbt“ nach oben).
"""
import base64
import bz2
import gzip
import hashlib
import lzma
import os
import re
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

from .analyzers.base import finding

MAX_DEPTH = 3
MAX_NODES = 25                   # Stufen je Wurzeldatei insgesamt
MAX_CHILDREN = 12                # je Elternteil
MAX_CHILD_BYTES = 32 << 20
MAX_TOTAL_BYTES = 128 << 20
TIME_BUDGET = 150.0              # Sekunden – der Sandbox-Worker hat 300 s Wanduhr
DECOMP_CAP = 64 << 20

# Dateien, deren Inhalt es lohnt (Archiv-Einträge): aktiv, Container oder Dokument
INTERESTING_EXT = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".msi", ".msp", ".jar", ".apk",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".bat", ".cmd", ".py", ".sh",
    ".lnk", ".url", ".iso", ".img", ".vhd", ".vhdx", ".zip", ".7z", ".rar", ".gz", ".tgz", ".tar", ".bz2",
    ".xz", ".cab", ".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".xlsb", ".ppt", ".pptm", ".pptx",
    ".rtf", ".pdf", ".one", ".html", ".htm", ".svg", ".xhtml", ".eml", ".msg", ".chm", ".reg", ".php",
}
MAGIC_INTERESTING = (b"MZ", b"PK\x03\x04", b"\xd0\xcf\x11\xe0", b"%PDF", b"{\\rt", b"\x7fELF", b"Rar!",
                     b"7z\xbc\xaf", b"L\x00\x00\x00", b"<html", b"<!DOCTYPE html", b"<svg", b"#!")
FILE_MAGIC = ((b"MZ", ".exe"), (b"PK\x03\x04", ".zip"), (b"\xd0\xcf\x11\xe0", ".doc"), (b"%PDF", ".pdf"),
              (b"{\\rt", ".rtf"), (b"\x7fELF", ".elf"), (b"Rar!", ".rar"), (b"7z\xbc\xaf", ".7z"),
              (b"\x1f\x8b", ".gz"), (b"L\x00\x00\x00", ".lnk"))

ENC_CMD = re.compile(r"-e(?:c|nc|nco|ncod|ncode|ncodedcommand)?\s+([A-Za-z0-9+/=]{40,})", re.I)
B64_CALL = re.compile(r"FromBase64String\s*\(\s*['\"]([A-Za-z0-9+/=]{40,})['\"]", re.I)
B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{400,}={0,2}")

LEVEL_RANK = {"CLEAN": 0, "LOW RISK": 1, "ELEVATED": 2, "HIGH RISK": 3, "CRITICAL": 4}


class Budget:
    def __init__(self):
        self.nodes = 0
        self.bytes = 0
        self.deadline = time.monotonic() + TIME_BUDGET
        self.skipped = 0

    def take(self, n):
        if self.nodes >= MAX_NODES or self.bytes + n > MAX_TOTAL_BYTES or time.monotonic() > self.deadline:
            self.skipped += 1
            return False
        self.nodes += 1
        self.bytes += n
        return True


def _safe_name(name, fallback):
    base = os.path.basename(str(name or "").replace("\\", "/")) or fallback
    base = re.sub(r"[^\w.\- ]", "_", base)[:80].strip(" .") or fallback
    return base


def _ext_for(data, default=".bin"):
    for sig, ext in FILE_MAGIC:
        if data.startswith(sig):
            return ext
    return default


def _interesting(name, head):
    ext = os.path.splitext(name.lower())[1]
    return ext in INTERESTING_EXT or any(head.startswith(m) for m in MAGIC_INTERESTING)


def _read_capped(fh, cap=MAX_CHILD_BYTES):
    buf = fh.read(cap + 1)
    return None if len(buf) > cap else buf


# ── Extraktoren: jeder liefert [(quelle, name, bytes)] ──────────────────────
def _from_zip(path):
    out = []
    try:
        with zipfile.ZipFile(path) as z:
            for zi in z.infolist():
                if len(out) >= MAX_CHILDREN:
                    break
                if zi.is_dir() or zi.flag_bits & 0x1 or zi.file_size > MAX_CHILD_BYTES:
                    continue
                with z.open(zi) as fh:
                    head = fh.read(64)
                if not _interesting(zi.filename, head):
                    continue
                with z.open(zi) as fh:
                    data = _read_capped(fh)
                if data:
                    out.append(("archive entry", zi.filename, data))
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError):
        pass
    return out


def _from_tar(path):
    out = []
    try:
        with tarfile.open(path) as t:
            for m in t:
                if len(out) >= MAX_CHILDREN:
                    break
                if not m.isreg() or m.size > MAX_CHILD_BYTES:
                    continue
                fh = t.extractfile(m)
                if fh is None:
                    continue
                data = fh.read()
                if _interesting(m.name, data[:64]):
                    out.append(("archive entry", m.name, data))
    except (tarfile.TarError, OSError, EOFError):
        pass
    return out


def _from_stream(path, opener, suffix):
    try:
        with opener(path) as fh:
            data = _read_capped(fh, DECOMP_CAP)
    except (OSError, EOFError, lzma.LZMAError, ValueError):
        return []
    if not data:
        return []
    name = Path(path).name
    inner = name[: -len(suffix)] if name.lower().endswith(suffix) else name + ".out"
    if inner.lower().endswith(".tgz"):
        inner = inner[:-4] + ".tar"
    return [("decompressed", inner, data)] if len(data) <= MAX_CHILD_BYTES else []


def _from_email(path):
    import email
    import email.policy
    out = []
    try:
        msg = email.message_from_bytes(Path(path).read_bytes()[:64 << 20], policy=email.policy.default)
    except Exception:
        return out
    for part in msg.walk():
        fn = part.get_filename()
        if not fn and part.get_content_disposition() != "attachment":
            continue
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            continue
        if data and len(data) <= MAX_CHILD_BYTES:
            out.append(("e-mail attachment", fn or "attachment.bin", data))
        if len(out) >= MAX_CHILDREN:
            break
    return out


def _from_pdf(path):
    out = []
    try:
        import pikepdf
        with pikepdf.open(path) as pdf:
            for name, spec in list(pdf.attachments.items())[:MAX_CHILDREN]:
                data = spec.get_file().read_bytes()
                if data and len(data) <= MAX_CHILD_BYTES:
                    out.append(("PDF attachment", name, data))
    except Exception:
        pass
    return out


def _from_macros(path):
    out = []
    try:
        from oletools.olevba import VBA_Parser
        vp = VBA_Parser(path)
        try:
            if vp.detect_vba_macros():
                for _f, _s, vba_name, code in vp.extract_macros():
                    if code and code.strip() and len(out) < MAX_CHILDREN:
                        stem = os.path.splitext(_safe_name(vba_name, "macro"))[0]
                        out.append(("VBA macro", f"{stem}.vbs", code.encode("utf-8", "replace")))
        finally:
            vp.close()
    except Exception:
        pass
    return out


def _decode_b64(raw):
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False)
    except Exception:
        return None


def _from_script_text(text):
    out = []
    for m in ENC_CMD.finditer(text):
        dec = _decode_b64(m.group(1))
        if dec:
            out.append(("PowerShell -EncodedCommand", "encoded_command.ps1",
                        dec.decode("utf-16-le", "replace").encode("utf-8")))
    for m in B64_CALL.finditer(text):
        dec = _decode_b64(m.group(1))
        if dec and len(dec) >= 16:
            if dec.startswith(b"MZ") or any(dec.startswith(s) for s, _ in FILE_MAGIC):
                out.append(("FromBase64String", "decoded" + _ext_for(dec), dec))
            else:
                out.append(("FromBase64String", "decoded.ps1", dec))
        if len(out) >= MAX_CHILDREN:
            break
    return out[:MAX_CHILDREN]


def _from_b64_blobs(data):
    """Große Base64-Blöcke (HTML-Smuggling, eingebettete Programme) mit echter Datei-Signatur."""
    out, seen = [], set()
    for m in B64_BLOB.finditer(data):
        raw = m.group(0)
        dec = _decode_b64(raw.decode("ascii"))
        if not dec or len(dec) < 64 or len(dec) > MAX_CHILD_BYTES:
            continue
        ext = _ext_for(dec, None)
        if ext is None:
            continue
        h = hashlib.sha256(dec).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        out.append(("Base64 blob", f"blob_{len(out) + 1}{ext}", dec))
        if len(out) >= 5:
            break
    return out


def _pe_size(buf):
    try:
        import pefile
        pe = pefile.PE(data=buf[:MAX_CHILD_BYTES], fast_load=True)
        end = max((s.PointerToRawData + s.SizeOfRawData for s in pe.sections), default=0)
        return max(end, pe.OPTIONAL_HEADER.SizeOfHeaders) or None
    except Exception:
        return None


def _carve_pe(path, offsets):
    out = []
    with open(path, "rb") as f:
        for off in offsets[:5]:
            f.seek(off)
            buf = f.read(MAX_CHILD_BYTES)
            size = _pe_size(buf)
            if size:
                out.append(("embedded program", f"carved_0x{off:X}.exe", buf[:size]))
    return out


def _appended(path, offset, size):
    if not offset or size < 1024 or size > MAX_CHILD_BYTES:
        return []
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(size)
    return [("data after end of file", "appended" + _ext_for(data), data)]


def extract(path, ft, report):
    """Alle direkten Stufen einer Datei. → [(quelle, name, bytes)]"""
    cat, sub = ft.get("category"), ft.get("subtype")
    an = (report or {}).get("analyzers") or {}
    out = []
    if cat == "archive" and zipfile.is_zipfile(path) and sub not in ("docx", "xlsx", "pptx", "odf", "epub"):
        out += _from_zip(path)
    elif sub == "tar":
        out += _from_tar(path)
    elif sub == "gzip":
        out += _from_stream(path, gzip.open, ".gz")
    elif sub == "bzip2":
        out += _from_stream(path, bz2.open, ".bz2")
    elif sub == "xz":
        out += _from_stream(path, lzma.open, ".xz")
    if cat == "email" or (an.get("email") or {}).get("attachments"):
        out += _from_email(path)
    if cat == "pdf":
        out += _from_pdf(path)
    if cat in ("document", "ole") or sub in ("docx", "xlsx", "pptx"):
        out += _from_macros(path)
    sc = an.get("script") or {}
    if cat in ("script", "text", "web", "shortcut") or sc:
        try:
            text = Path(path).read_bytes()[:8 << 20].decode("utf-8", "replace")
        except OSError:
            text = ""
        out += _from_script_text(text)
    if cat in ("web", "text", "script", "email", "document", "rtf"):
        try:
            out += _from_b64_blobs(Path(path).read_bytes()[:16 << 20])
        except OSError:
            pass
    base = an.get("baseline") or {}
    if base.get("embedded_pe_offsets") and sub != "pe":
        out += _carve_pe(path, base["embedded_pe_offsets"])
    if base.get("appended_offset"):
        out += _appended(path, base["appended_offset"], base.get("appended_bytes") or 0)
    lnk = an.get("lnk") or {}
    if lnk.get("arguments") or lnk.get("target"):
        cmd = f"{lnk.get('target') or ''} {lnk.get('arguments') or ''}".strip()
        ext = ".ps1" if "powershell" in cmd.lower() else ".cmd"
        out.append(("shortcut command line", "lnk_command" + ext, cmd.encode("utf-8")))
    # gleiche Inhalte nur einmal
    uniq, seen = [], set()
    for src, name, data in out:
        h = hashlib.sha256(data).hexdigest()
        if h not in seen:
            seen.add(h)
            uniq.append((src, name, data))
    return uniq[:MAX_CHILDREN]


# ── Rekursion ────────────────────────────────────────────────────────────────
def _node(src, name, data, res):
    sc, th = res.get("score") or {}, res.get("threat") or {}
    base = (((res.get("report") or {}).get("analyzers") or {}).get("baseline") or {})
    top = sorted((f for f in sc.get("findings", []) if f.get("severity") in ("CRIT", "WARN")),
                 key=lambda f: -(f.get("weight") or 0))[:8]
    children = res.get("payloads") or []
    # Ursache: steckt die Gefahr in einer tieferen Stufe, deren Ursache + Pfad übernehmen
    worst = max(children, key=lambda c: (LEVEL_RANK.get(c.get("level"), 0), c.get("score") or 0), default=None)
    own_nested = bool(top) and str(top[0].get("code", "")).startswith("nested_payload")
    if worst and own_nested:
        cause, trail = worst.get("cause"), [name] + (worst.get("trail") or [])
    else:
        cause, trail = th.get("headline"), [name]
    return {
        "source": src, "name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "cause": cause, "trail": trail,
        "kind": res.get("kind"), "true_type": (res.get("filetype") or {}).get("description"),
        "ok": bool(res.get("ok")), "error": res.get("error"),
        "score": sc.get("score"), "level": sc.get("level"), "headline": th.get("headline"),
        "findings": [{"code": f.get("code"), "severity": f.get("severity"), "desc": f.get("desc")} for f in top],
        "attack": [t["id"] for t in (res.get("attack") or {}).get("techniques", []) if t["severity"] != "INFO"],
        "iocs": base.get("iocs") or {},
        "fingerprints": res.get("fingerprints") or {},
        "children": children,
    }


def expand(path, ft, report, depth, budget, analyze):
    """
    analyze(child_path, depth, budget) → Ergebnis wie run_forensic.
    → (baum, findings_für_elternteil, alle_findings_der_stufen)
    """
    if depth >= MAX_DEPTH:
        return [], [], []
    try:
        children = extract(path, ft, report)
    except Exception:
        return [], [], []
    tree, parent_findings, all_child_findings = [], [], []
    if not children:
        return tree, parent_findings, all_child_findings
    with tempfile.TemporaryDirectory(prefix="sentinel_payload_") as tmp:
        for i, (src, name, data) in enumerate(children):
            if not budget.take(len(data)):
                break
            fname = _safe_name(name, f"payload_{i}")
            child_path = os.path.join(tmp, f"{i:02d}_{fname}")
            try:
                with open(child_path, "wb") as f:
                    f.write(data)
                res = analyze(child_path, depth + 1, budget)
            except Exception as e:
                res = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            finally:
                try:
                    os.remove(child_path)          # sofort wieder weg
                except OSError:
                    pass
            node = _node(src, name, data, res)
            tree.append(node)
            all_child_findings += [dict(f, source=f.get("source") or "payload")
                                   for f in (res.get("score") or {}).get("findings", [])]
            all_child_findings += res.get("_payload_findings") or []
            rank = LEVEL_RANK.get(node["level"], 0)
            where = f"{src} › " + " › ".join(node["trail"])
            if rank >= 3:
                parent_findings.append(finding("nested_payload_critical",
                                               f"Versteckte Stufe {where} ist {node['level']}: {node['cause']}", "CRIT"))
            elif rank == 2:
                parent_findings.append(finding("nested_payload_suspicious",
                                               f"Versteckte Stufe {where} ist {node['level']}: {node['cause']}", "WARN"))
    if budget.skipped:
        parent_findings.append(finding("payload_budget", f"{budget.skipped} weitere Stufe(n) nicht analysiert "
                                                         "(Zeit-/Größenlimit)", "INFO"))
        budget.skipped = 0
    return tree, parent_findings, all_child_findings


def flatten(tree, depth=1):
    """Baum → Liste (depth, node) in Anzeige-Reihenfolge."""
    for n in tree or []:
        yield depth, n
        yield from flatten(n.get("children"), depth + 1)


def chain_iocs(tree):
    """Alle IOCs aller Stufen (für Verlauf/Graph)."""
    out = {}
    for _d, n in flatten(tree):
        for k, vals in (n.get("iocs") or {}).items():
            if isinstance(vals, list):
                out.setdefault(k, [])
                out[k] += [v for v in vals if isinstance(v, str) and v not in out[k]]
    return out
