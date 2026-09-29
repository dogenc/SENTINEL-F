"""
Archiv- und Zipbomb-Analyse — OHNE Entpacken auf die Platte.

Erkennt:
  * Zipbombs über drei unabhängige Wege:
      1. deklariertes Kompressionsverhältnis (Header)
      2. tatsächlich gestreamtes Verhältnis (gezählt, sofort verworfen, mit Obergrenze)
      3. überlappende Einträge (Fifield-Bombe: viele Einträge teilen sich einen Datenblock)
  * rekursive Bomben (42.zip-Stil): verschachtelte Archive, kumuliertes Verhältnis
  * lügende Header (deklarierte ≠ tatsächliche Größe)
  * Zip-Slip / Pfad-Traversal, absolute Pfade, Symlinks
  * verschlüsselte Einträge, ausführbare Dateien, Doppel-Endungen im Archiv
Formate: ZIP-Familie (inkl. JAR/APK/OOXML), TAR, GZIP, BZIP2, XZ, ZSTD, 7z, CAB, ISO, RAR (nur Header).
"""
import bz2
import gzip
import io
import lzma
import posixpath
import stat
import struct
import tarfile
import time
import zipfile

from core.filetype import DANGEROUS_EXTS
from . import limits
from .base import finding

ARCHIVE_MAGIC = [
    (b"PK\x03\x04", "zip"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"),
    (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"), (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"MSCF", "cab"),
]
DECOYS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".rtf", ".mp4", ".csv"}
OOXML = {"docx", "xlsx", "pptx", "odf", "epub"}


def _magic(head):
    for sig, kind in ARCHIVE_MAGIC:
        if head.startswith(sig):
            return kind
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    return None


def _size(n):
    return f"{n / limits.GiB:.2f} GiB" if n >= limits.GiB else f"{n / limits.MiB:,.0f} MiB"


def _ext(name):
    base = posixpath.basename(name.replace("\\", "/")).lower()
    return "." + base.rsplit(".", 1)[1] if "." in base else ""


class Budget:
    """Gemeinsames Limit über alle Verschachtelungsebenen hinweg."""

    def __init__(self):
        self.decompressed = 0
        self.deadline = time.monotonic() + limits.ARCHIVE_TIME_BUDGET
        self.exhausted = None

    def take(self, n):
        self.decompressed += n
        if self.decompressed > limits.DECOMP_CAP_TOTAL:
            self.exhausted = "size"
        elif time.monotonic() > self.deadline:
            self.exhausted = "time"
        return self.exhausted is None


def _stream_count(readable, budget, cap=None, keep_head=0):
    """Liest einen Strom in Blöcken, zählt Bytes, behält optional den Anfang."""
    cap = cap or limits.DECOMP_CAP_ENTRY
    total, head = 0, b""
    while True:
        chunk = readable.read(1 << 20)
        if not chunk:
            return total, head, False
        if len(head) < keep_head:
            head += chunk[:keep_head - len(head)]
        total += len(chunk)
        if total > cap or not budget.take(len(chunk)):
            return total, head, True


class ArchiveReport:
    def __init__(self):
        self.findings = []
        self.entries = []
        self.nested = []
        self.stats = {"entries": 0, "declared_uncompressed": 0, "compressed": 0,
                      "measured_uncompressed": 0, "measurement_complete": True,
                      "max_depth": 0, "encrypted": 0, "executables": 0, "dirs": 0}
        self._seen = set()

    def add(self, code, desc, severity):
        key = (code, desc)
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(finding(code, desc, severity))


def _check_name(rep, name, where, is_ooxml=False):
    n = name.replace("\\", "/")
    if n.startswith("/") or (len(n) > 1 and n[1] == ":") or n.startswith("//"):
        rep.add("path_traversal", f"Absoluter Pfad im Archiv{where}: {name[:100]}", "CRIT")
    elif ".." in n.split("/"):
        rep.add("path_traversal", f"Zip-Slip / Pfad-Traversal{where}: {name[:100]}", "CRIT")
    ext = _ext(n)
    if ext in DANGEROUS_EXTS and not is_ooxml:
        rep.stats["executables"] += 1
        base = posixpath.basename(n).lower()
        parts = base.split(".")
        if len(parts) >= 3 and "." + parts[-2] in DECOYS:
            rep.add("archive_double_extension", f"Getarnte Datei im Archiv{where}: {base[:80]}", "CRIT")
        else:
            rep.add("archive_executable", f"Ausführbare/aktive Datei im Archiv{where}: {base[:80]}", "WARN")
    if "‮" in name:
        rep.add("rtlo_filename", f"RTLO-Trick in Archiv-Dateiname{where}", "CRIT")


# ─── ZIP ────────────────────────────────────────────────────────────────────
def _zip_overlaps(fobj, infos):
    """Prüft, ob sich Datenbereiche von Einträgen überschneiden (Fifield-Zipbomb)."""
    spans = []
    for zi in infos:
        try:
            fobj.seek(zi.header_offset)
            lh = fobj.read(30)
            if len(lh) < 30 or lh[:4] != b"PK\x03\x04":
                continue
            nlen, xlen = struct.unpack("<HH", lh[26:30])
            start = zi.header_offset
            end = zi.header_offset + 30 + nlen + xlen + zi.compress_size
            spans.append((start, end, zi.filename))
        except Exception:
            continue
    spans.sort()
    overlaps, shared = 0, 0
    offsets = {}
    for s, e, n in spans:
        offsets[s] = offsets.get(s, 0) + 1
    shared = sum(c - 1 for c in offsets.values() if c > 1)
    for (s1, e1, _), (s2, _, _) in zip(spans, spans[1:]):
        if s2 < e1 and s2 != s1:
            overlaps += 1
    return overlaps, shared


def analyze_zip(fobj, rep, budget, depth, where, archive_size, subtype="zip"):
    is_ooxml = subtype in OOXML
    try:
        z = zipfile.ZipFile(fobj)
    except zipfile.BadZipFile as e:
        rep.add("archive_corrupt", f"ZIP nicht lesbar{where}: {e}", "WARN")
        return
    with z:
        infos = z.infolist()
        rep.stats["entries"] += len(infos)
        if len(infos) > limits.MAX_ENTRIES:
            rep.add("archive_too_many_entries", f"{len(infos):,} Einträge{where} (Ressourcen-Angriff?)", "WARN")
            infos_scan = infos[:limits.MAX_ENTRIES]
        else:
            infos_scan = infos

        declared = sum(zi.file_size for zi in infos)
        compressed = sum(zi.compress_size for zi in infos)
        if depth == 0:
            rep.stats["declared_uncompressed"] += declared
            rep.stats["compressed"] += compressed

        overlaps, shared = _zip_overlaps(fobj, infos_scan)
        if overlaps or shared:
            rep.add("zip_overlap",
                    f"Überlappende ZIP-Einträge{where}: {overlaps} Überlappungen, {shared} geteilte Datenblöcke "
                    f"– Merkmal einer Non-Recursive-Zipbomb", "CRIT")

        for zi in infos_scan:
            if zi.is_dir():
                rep.stats["dirs"] += 1
                continue
            _check_name(rep, zi.filename, where, is_ooxml)
            unix_mode = zi.external_attr >> 16
            if unix_mode and stat.S_ISLNK(unix_mode):
                rep.add("archive_symlink", f"Symlink im Archiv{where}: {zi.filename[:80]}", "WARN")
            enc = bool(zi.flag_bits & 0x1)
            ratio = zi.file_size / zi.compress_size if zi.compress_size else (float("inf") if zi.file_size else 0)
            entry = {"name": zi.filename[:200], "size": zi.file_size, "compressed": zi.compress_size,
                     "ratio": round(ratio, 1) if ratio != float("inf") else "inf", "encrypted": enc,
                     "method": zi.compress_type, "depth": depth, "crc": f"{zi.CRC:08x}"}
            if enc:
                rep.stats["encrypted"] += 1
            if len(rep.entries) < limits.MAX_LISTED_ENTRIES:
                rep.entries.append(entry)
            if enc or budget.exhausted:
                if budget.exhausted:
                    rep.stats["measurement_complete"] = False
                continue
            # Tatsächlich streamen & zählen
            try:
                with z.open(zi) as fh:
                    measured, head, capped = _stream_count(fh, budget, keep_head=512)
            except NotImplementedError:
                entry["note"] = "Kompressionsmethode nicht unterstützt"
                rep.stats["measurement_complete"] = False
                continue
            except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, ValueError, lzma.LZMAError) as e:
                msg = str(e)
                if "overlap" in msg.lower():
                    rep.add("zip_overlap", f"Überlappende Einträge{where} (von zipfile gemeldet)", "CRIT")
                elif "crc" in msg.lower():
                    rep.add("archive_size_mismatch",
                            f"Prüfsumme falsch{where}: „{zi.filename[:60]}“ – Header manipuliert oder Datei beschädigt", "WARN")
                entry["error"] = msg[:120]
                continue
            entry["measured"] = measured
            if depth == 0:
                rep.stats["measured_uncompressed"] += measured
            if capped:
                rep.stats["measurement_complete"] = False
                # Vom Gesamtbudget gestoppt → die Gesamtmeldung im Analysator sagt es bereits
                if not budget.exhausted:
                    rep.add("zip_bomb",
                            f"Eintrag „{zi.filename[:60]}“{where} entpackt über {_size(measured)} "
                            f"(abgebrochen) aus {zi.compress_size:,} Bytes", "CRIT")
            elif measured != zi.file_size:
                rep.add("archive_size_mismatch",
                        f"Header lügt{where}: „{zi.filename[:60]}“ deklariert {zi.file_size:,} B, "
                        f"tatsächlich {measured:,} B", "WARN")
            inner = _magic(head)
            if inner and not capped and depth < limits.MAX_NEST_DEPTH:
                _nested(z, zi, inner, rep, budget, depth, where)
            elif inner and depth >= limits.MAX_NEST_DEPTH:
                rep.add("nested_archives", f"Verschachtelung tiefer als {limits.MAX_NEST_DEPTH} Ebenen{where}", "CRIT")


def _nested(z, zi, inner, rep, budget, depth, where):
    rep.stats["max_depth"] = max(rep.stats["max_depth"], depth + 1)
    rep.nested.append({"name": zi.filename[:200], "type": inner, "depth": depth + 1})
    if zi.file_size > limits.NESTED_READ_CAP:
        rep.add("nested_archives", f"Großes inneres Archiv nicht geöffnet{where}: {zi.filename[:60]}", "INFO")
        return
    with z.open(zi) as fh:
        buf = fh.read(limits.NESTED_READ_CAP + 1)
    if len(buf) > limits.NESTED_READ_CAP:
        return
    sub_where = f"{where} › {posixpath.basename(zi.filename)[:40]}"
    analyze_blob(io.BytesIO(buf), inner, rep, budget, depth + 1, sub_where, len(buf))


def analyze_blob(fobj, kind, rep, budget, depth, where, size):
    if kind == "zip":
        analyze_zip(fobj, rep, budget, depth, where, size)
    elif kind in ("gzip", "bzip2", "xz", "zstd"):
        analyze_stream(fobj, kind, rep, budget, depth, where, size)
    elif kind == "tar":
        analyze_tar(fobj, rep, depth, where)
    else:
        rep.add("nested_archives", f"Inneres {kind.upper()}-Archiv{where} (nicht weiter geöffnet)", "INFO")


# ─── Einzelstrom-Kompression ────────────────────────────────────────────────
def _open_stream(fobj, kind):
    if kind == "gzip":
        return gzip.GzipFile(fileobj=fobj)
    if kind == "bzip2":
        return bz2.BZ2File(fobj)
    if kind == "xz":
        return lzma.LZMAFile(fobj)
    if kind == "zstd":
        from compression import zstd  # Python ≥ 3.14
        return zstd.ZstdFile(fobj)
    raise ValueError(kind)


def analyze_stream(fobj, kind, rep, budget, depth, where, size):
    fobj.seek(0)
    try:
        s = _open_stream(fobj, kind)
    except ImportError:
        rep.add("archive_scan_incomplete", f"{kind.upper()} kann nicht gelesen werden (Modul fehlt)", "INFO")
        return
    try:
        with s:
            measured, head, capped = _stream_count(s, budget, keep_head=4096)
    except (OSError, EOFError, lzma.LZMAError, ValueError) as e:
        rep.add("archive_corrupt", f"{kind.upper()}-Strom defekt{where}: {str(e)[:80]}", "WARN")
        return
    if depth == 0:
        rep.stats["compressed"] += size
        rep.stats["declared_uncompressed"] += measured
        rep.stats["measured_uncompressed"] += measured
        rep.stats["entries"] += 1
    rep.entries.append({"name": f"[{kind}-stream]", "size": measured, "compressed": size, "depth": depth,
                        "ratio": round(measured / size, 1) if size else 0})
    if capped:
        rep.stats["measurement_complete"] = False
        if not budget.exhausted:
            rep.add("zip_bomb", f"{kind.upper()}-Strom{where} entpackt über {_size(measured)} "
                                f"aus {size:,} Bytes (abgebrochen)", "CRIT")
        return
    inner = _magic(head)
    if inner == "tar":
        fobj.seek(0)
        with _open_stream(fobj, kind) as s2:
            analyze_tar(s2, rep, depth, where, streaming=True)
    elif inner and depth < limits.MAX_NEST_DEPTH and measured <= limits.NESTED_READ_CAP:
        fobj.seek(0)
        with _open_stream(fobj, kind) as s2:
            buf = s2.read(limits.NESTED_READ_CAP)
        rep.stats["max_depth"] = max(rep.stats["max_depth"], depth + 1)
        rep.nested.append({"name": f"[{kind}-inhalt]", "type": inner, "depth": depth + 1})
        analyze_blob(io.BytesIO(buf), inner, rep, budget, depth + 1, f"{where} › {kind}", len(buf))


# ─── TAR ────────────────────────────────────────────────────────────────────
def analyze_tar(fobj, rep, depth, where, streaming=False):
    try:
        tf = tarfile.open(fileobj=fobj, mode="r|" if streaming else "r:")
    except tarfile.TarError as e:
        rep.add("archive_corrupt", f"TAR nicht lesbar{where}: {e}", "WARN")
        return
    count = 0
    with tf:
        for m in tf:
            count += 1
            if count > limits.MAX_ENTRIES:
                rep.add("archive_too_many_entries", f"Mehr als {limits.MAX_ENTRIES:,} TAR-Einträge{where}", "WARN")
                break
            if m.isdir():
                rep.stats["dirs"] += 1
                continue
            _check_name(rep, m.name, where)
            if m.issym() or m.islnk():
                tgt = m.linkname.replace("\\", "/")
                bad = tgt.startswith("/") or ".." in tgt.split("/")
                rep.add("archive_symlink", f"{'Symlink' if m.issym() else 'Hardlink'}{where}: {m.name[:60]} → {tgt[:60]}",
                        "CRIT" if bad else "WARN")
            if m.isdev():
                rep.add("archive_device_file", f"Gerätedatei im TAR{where}: {m.name[:60]}", "WARN")
            if m.mode & (stat.S_ISUID | stat.S_ISGID):
                rep.add("archive_setuid", f"SetUID/SetGID-Datei{where}: {m.name[:60]}", "WARN")
            if len(rep.entries) < limits.MAX_LISTED_ENTRIES:
                rep.entries.append({"name": m.name[:200], "size": m.size, "depth": depth,
                                    "mode": oct(m.mode), "type": "link" if (m.issym() or m.islnk()) else "file"})
            if depth == 0 and not streaming:
                rep.stats["declared_uncompressed"] += m.size
    if depth == 0:
        rep.stats["entries"] += count


# ─── 7z ─────────────────────────────────────────────────────────────────────
def analyze_7z(path, rep, size):
    try:
        import py7zr
    except ImportError:
        rep.add("archive_scan_incomplete", "7z-Inhalt nicht prüfbar (py7zr fehlt)", "INFO")
        return
    try:
        with py7zr.SevenZipFile(path, mode="r") as z:
            if z.needs_password():
                rep.stats["encrypted"] += 1
                rep.add("archive_encrypted", "7z ist passwortgeschützt", "INFO")
            items = z.list()
    except py7zr.exceptions.PasswordRequired:
        rep.add("archive_encrypted", "7z mit verschlüsselten Dateinamen (Header-Verschlüsselung)", "WARN")
        return
    except Exception as e:
        rep.add("archive_corrupt", f"7z nicht lesbar: {str(e)[:100]}", "WARN")
        return
    rep.stats["entries"] = len(items)
    rep.stats["compressed"] = size
    rep.stats["measurement_complete"] = False   # 7z: nur deklarierte Größen
    for it in items:
        if it.is_directory:
            rep.stats["dirs"] += 1
            continue
        rep.stats["declared_uncompressed"] += it.uncompressed or 0
        _check_name(rep, it.filename, "")
        if len(rep.entries) < limits.MAX_LISTED_ENTRIES:
            rep.entries.append({"name": it.filename[:200], "size": it.uncompressed, "compressed": it.compressed,
                                "depth": 0})
        if _ext(it.filename) in {".zip", ".7z", ".rar", ".gz", ".xz", ".bz2", ".tar", ".cab"}:
            rep.nested.append({"name": it.filename[:200], "type": _ext(it.filename)[1:], "depth": 1})


# ─── CAB ────────────────────────────────────────────────────────────────────
def analyze_cab(path, rep, size):
    with open(path, "rb") as f:
        hdr = f.read(36)
        if len(hdr) < 36:
            return
        cb_cab, coff_files = struct.unpack_from("<I4xI", hdr, 8)
        n_folders, n_files, flags = struct.unpack_from("<HHH", hdr, 26)
        rep.stats["entries"] = n_files
        rep.stats["compressed"] = size
        rep.stats["measurement_complete"] = False
        f.seek(coff_files)
        for _ in range(min(n_files, limits.MAX_ENTRIES)):
            fh = f.read(16)
            if len(fh) < 16:
                break
            cb_file = struct.unpack_from("<I", fh, 0)[0]
            name = b""
            while len(name) < 512:
                c = f.read(1)
                if not c or c == b"\x00":
                    break
                name += c
            n = name.decode("latin-1")
            rep.stats["declared_uncompressed"] += cb_file
            _check_name(rep, n, "")
            if len(rep.entries) < limits.MAX_LISTED_ENTRIES:
                rep.entries.append({"name": n, "size": cb_file, "depth": 0})


# ─── ISO-9660 (nur Wurzelverzeichnis) ───────────────────────────────────────
def analyze_iso(path, rep, size):
    with open(path, "rb") as f:
        f.seek(0x8000)
        pvd = f.read(2048)
        if pvd[1:6] != b"CD001":
            return
        root = pvd[156:190]
        lba = struct.unpack_from("<I", root, 2)[0]
        length = struct.unpack_from("<I", root, 10)[0]
        f.seek(lba * 2048)
        buf = f.read(min(length, 1 << 20))
    pos, names = 0, []
    while pos < len(buf):
        rlen = buf[pos]
        if rlen == 0:
            pos = (pos // 2048 + 1) * 2048
            continue
        rec = buf[pos:pos + rlen]
        nlen = rec[32] if len(rec) > 32 else 0
        name = rec[33:33 + nlen]
        flags = rec[25] if len(rec) > 25 else 0
        fsize = struct.unpack_from("<I", rec, 10)[0] if len(rec) >= 14 else 0
        if name not in (b"\x00", b"\x01"):
            n = name.decode("latin-1").split(";")[0]
            names.append(n)
            if not flags & 0x02:
                _check_name(rep, n, " (ISO)")
                rep.entries.append({"name": n, "size": fsize, "depth": 0})
                rep.stats["declared_uncompressed"] += fsize
        pos += rlen
    rep.stats["entries"] = len(names)
    rep.stats["compressed"] = size
    rep.stats["measurement_complete"] = False
    if rep.stats["executables"]:
        rep.add("container_executable",
                "Disk-Image mit ausführbarem Inhalt – klassischer Trick, um Mark-of-the-Web zu umgehen", "CRIT")


# ─── Analysator ─────────────────────────────────────────────────────────────
class ArchiveAnalyzer:
    name = "archive"
    ZIP_SUBTYPES = {"zip", "jar", "apk", "appx", "vsix", "docx", "xlsx", "pptx", "odf", "epub"}

    def applies(self, ctx):
        return ctx.subtype in self.ZIP_SUBTYPES | {"tar", "gzip", "bzip2", "xz", "zstd", "7z", "rar", "rar5", "cab", "iso"}

    def run(self, ctx):
        rep, budget = ArchiveReport(), Budget()
        st = ctx.subtype
        if st in self.ZIP_SUBTYPES:
            with open(ctx.path, "rb") as f:
                analyze_zip(f, rep, budget, 0, "", ctx.size, st)
        elif st in ("gzip", "bzip2", "xz", "zstd"):
            with open(ctx.path, "rb") as f:
                analyze_stream(f, st, rep, budget, 0, "", ctx.size)
        elif st == "tar":
            with open(ctx.path, "rb") as f:
                analyze_tar(f, rep, 0, "")
        elif st == "7z":
            analyze_7z(ctx.path, rep, ctx.size)
        elif st == "cab":
            analyze_cab(ctx.path, rep, ctx.size)
        elif st == "iso":
            analyze_iso(ctx.path, rep, ctx.size)
        elif st in ("rar", "rar5"):
            rep.add("archive_scan_incomplete", "RAR-Inhalt wird nicht entpackt (nur Header erkannt)", "INFO")

        s = rep.stats
        comp = max(1, ctx.size)   # echte Bytes auf der Platte (geteilte Blöcke zählen nur einmal)
        s["declared_ratio"] = round(s["declared_uncompressed"] / comp, 1)
        s["measured_ratio"] = round(s["measured_uncompressed"] / comp, 1) if s["measured_uncompressed"] else None
        s["decompressed_total_scanned"] = budget.decompressed
        # kumuliert über alle Ebenen (42.zip-Stil: jede Ebene klein, zusammen riesig)
        s["cumulative_ratio"] = round(budget.decompressed / comp, 1)
        ratio = max(s["declared_ratio"], s["measured_ratio"] or 0, s["cumulative_ratio"])
        if budget.exhausted:
            s["measurement_complete"] = False
            s["stopped_because"] = budget.exhausted
            if budget.exhausted == "size":
                rep.add("zip_bomb", f"Entpackte Gesamtgröße überschreitet {limits.DECOMP_CAP_TOTAL // limits.GiB} GiB "
                                    f"(aus {ctx.size:,} Bytes) – Analyse sicher abgebrochen", "CRIT")
            else:
                rep.add("archive_scan_incomplete", "Zeitbudget erschöpft – Archiv nur teilweise geprüft", "INFO")

        is_doc = st in OOXML
        if s["declared_uncompressed"] >= limits.DECLARED_SIZE_CRIT:
            rep.add("zip_bomb", f"Header deklarieren {s['declared_uncompressed'] / limits.GiB:,.1f} GiB entpackt "
                                f"aus {ctx.size:,} Bytes", "CRIT")
        if ratio >= limits.RATIO_CRIT:
            rep.add("zip_bomb", f"Kompressionsverhältnis {ratio:,.0f}:1 – typische Zipbomb", "CRIT")
        elif ratio >= limits.RATIO_WARN and not is_doc:
            rep.add("decompression_ratio_high", f"Ungewöhnlich hohes Kompressionsverhältnis {ratio:,.0f}:1", "WARN")

        if s["max_depth"] >= 3:
            rep.add("nested_archives", f"{s['max_depth']} Ebenen verschachtelter Archive (rekursive Bombe / Verschleierung)", "CRIT")
        elif rep.nested:
            rep.add("nested_archives", f"{len(rep.nested)} verschachtelte(s) Archiv(e)", "INFO")

        if s["encrypted"]:
            sev = "WARN" if s["executables"] else "INFO"
            rep.add("archive_encrypted", f"{s['encrypted']} verschlüsselte(r) Eintrag/Einträge"
                                         + (" – zusammen mit ausführbaren Dateien (Malware-Zustellung?)" if s["executables"] else ""), sev)

        ctx.shared["archive_stats"] = s
        return {"data": {"stats": s, "entries": rep.entries, "nested": rep.nested}, "findings": rep.findings}
