"""
Core utilities — hashing, file-type detection, logger.
"""
import hashlib
import datetime
from pathlib import Path


# ─── Hashing ──────────────────────────────────────────────────────────────────
def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def md5_file(path, chunk=1 << 20):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def sha1_file(path, chunk=1 << 20):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            h.update(b)
    return h.hexdigest()


def all_hashes(path):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            md5.update(b)
            sha1.update(b)
            sha256.update(b)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


# ─── Human sizes ──────────────────────────────────────────────────────────────
def human_size(n):
    if n is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.2f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.2f} PB"


# ─── File type detection via magic bytes ──────────────────────────────────────
MAGIC_SIGNATURES = {
    b"\xFF\xD8\xFF":                     ("image", "jpeg"),
    b"\x89PNG\r\n\x1a\n":                ("image", "png"),
    b"GIF87a":                           ("image", "gif"),
    b"GIF89a":                           ("image", "gif"),
    b"BM":                               ("image", "bmp"),
    b"II*\x00":                          ("image", "tiff"),
    b"MM\x00*":                          ("image", "tiff"),
    b"RIFF":                             ("image", "webp_or_riff"),   # needs deeper check
    b"%PDF-":                            ("pdf",   "pdf"),
    b"PK\x03\x04":                       ("archive", "zip_or_ooxml"),  # docx/xlsx/pptx
    b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": ("ole",   "ole_compound"),
}


def detect_file_type(path):
    """
    Returns (category, subtype, magic_hex).
    category: 'image' | 'pdf' | 'archive' | 'ole' | 'unknown'
    """
    try:
        with open(path, "rb") as f:
            head = f.read(32)
    except Exception:
        return ("unknown", "unknown", "")

    magic_hex = " ".join(f"{b:02X}" for b in head[:16])

    # WEBP specific
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return ("image", "webp", magic_hex)

    for sig, (cat, sub) in MAGIC_SIGNATURES.items():
        if head.startswith(sig):
            # OOXML: differentiate docx/xlsx/pptx
            if cat == "archive":
                sub = _detect_ooxml_subtype(path) or "zip"
                if sub in ("docx", "xlsx", "pptx"):
                    return ("document", sub, magic_hex)
                return ("archive", sub, magic_hex)
            return (cat, sub, magic_hex)

    # Fallback — extension
    ext = Path(path).suffix.lower()
    if ext in {".doc", ".xls", ".ppt"}:
        return ("document", ext[1:], magic_hex)
    if ext in {".docx", ".xlsx", ".pptx"}:
        return ("document", ext[1:], magic_hex)
    return ("unknown", "unknown", magic_hex)


def _detect_ooxml_subtype(path):
    """Look inside the ZIP to identify OOXML subtype."""
    import zipfile
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if "word/document.xml" in names:
                return "docx"
            if "xl/workbook.xml" in names:
                return "xlsx"
            if "ppt/presentation.xml" in names:
                return "pptx"
    except Exception:
        pass
    return None


def route_file(path):
    """
    Decide which engine to run. Returns one of:
      'image' | 'pdf' | 'document' | 'unknown'
    """
    cat, sub, _ = detect_file_type(path)
    if cat == "image":
        return "image"
    if cat == "pdf":
        return "pdf"
    if cat == "document" or cat == "ole":
        return "document"
    # extension fallback
    ext = Path(path).suffix.lower()
    if ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp"}:
        return "image"
    if ext == ".pdf":
        return "pdf"
    if ext in {".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt"}:
        return "document"
    return "unknown"


# ─── File stat snapshot ───────────────────────────────────────────────────────
def file_stat_snapshot(path):
    p = Path(path)
    try:
        st = p.stat()
        return {
            "name":      p.name,
            "path":      str(p.resolve()),
            "size":      st.st_size,
            "size_h":    human_size(st.st_size),
            "modified":  datetime.datetime.fromtimestamp(st.st_mtime).isoformat(sep=" ", timespec="seconds"),
            "created":   datetime.datetime.fromtimestamp(st.st_ctime).isoformat(sep=" ", timespec="seconds"),
            "accessed":  datetime.datetime.fromtimestamp(st.st_atime).isoformat(sep=" ", timespec="seconds"),
            "extension": p.suffix.lower(),
        }
    except Exception as e:
        return {"name": p.name, "path": str(p), "error": str(e)}


# ─── Simple thread-safe logger ────────────────────────────────────────────────
class Logger:
    LEVELS = {"DEBUG": 0, "INFO": 1, "OK": 1, "WARN": 2, "ERR": 3, "CRIT": 4}
    def __init__(self):
        self._subs = []
    def subscribe(self, fn):
        self._subs.append(fn)
    def log(self, msg, level="INFO"):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        line = {"ts": ts, "level": level, "msg": msg}
        for fn in self._subs:
            try:
                fn(line)
            except Exception:
                pass

LOG = Logger()
