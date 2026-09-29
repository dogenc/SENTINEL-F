"""
Universelle Dateityp-Erkennung über Magic Bytes.

identify(path) liefert den *tatsächlichen* Typ einer Datei, unabhängig von
ihrer Endung, und prüft, ob die Endung dazu passt. Reine Lesefunktion.
"""
from pathlib import Path

# (offset, signatur, category, subtype, beschreibung, erwartete endungen)
# Reihenfolge = Priorität; spezifischere Signaturen zuerst.
SIGNATURES = [
    # ── Ausführbares ──────────────────────────────────────────────────────
    (0, b"MZ", "executable", "pe", "Windows PE (EXE/DLL/SYS)",
     {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".efi", ".mui", ".com", ".ax", ".node"}),
    (0, b"\x7fELF", "executable", "elf", "Linux/Unix ELF", {"", ".so", ".o", ".elf", ".bin", ".ko", ".axf"}),
    (0, b"\xcf\xfa\xed\xfe", "executable", "macho", "Mach-O 64-bit", {"", ".dylib", ".bundle"}),
    (0, b"\xce\xfa\xed\xfe", "executable", "macho", "Mach-O 32-bit", {"", ".dylib", ".bundle"}),
    (0, b"\xca\xfe\xba\xbe", "executable", "macho_fat", "Mach-O Universal / Java class",
     {"", ".class", ".dylib"}),
    (0, b"dex\n", "executable", "dex", "Android DEX", {".dex"}),
    (0, b"\x00asm", "executable", "wasm", "WebAssembly", {".wasm"}),

    # ── Dokumente ─────────────────────────────────────────────────────────
    (0, b"%PDF-", "pdf", "pdf", "PDF-Dokument", {".pdf", ".ai"}),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "ole_compound", "OLE Compound (DOC/XLS/PPT/MSG/MSI)",
     {".doc", ".xls", ".ppt", ".msg", ".msi", ".msp", ".dot", ".xlt", ".pot", ".vsd", ".pub", ".db", ".mst"}),
    (0, b"{\\rtf", "rtf", "rtf", "Rich Text Format", {".rtf", ".doc"}),
    (0, b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d", "document", "onenote", "OneNote", {".one"}),

    # ── Archive / Container ───────────────────────────────────────────────
    (0, b"PK\x03\x04", "archive", "zip", "ZIP-Container", None),   # Endungen: siehe _zip_family
    (0, b"PK\x05\x06", "archive", "zip", "ZIP (leer)", None),
    (0, b"PK\x07\x08", "archive", "zip", "ZIP (spanned)", None),
    (0, b"7z\xbc\xaf\x27\x1c", "archive", "7z", "7-Zip", {".7z"}),
    (0, b"Rar!\x1a\x07\x01\x00", "archive", "rar5", "RAR v5", {".rar"}),
    (0, b"Rar!\x1a\x07\x00", "archive", "rar", "RAR v4", {".rar"}),
    (0, b"\x1f\x8b", "archive", "gzip", "GZIP", {".gz", ".tgz", ".gzip"}),
    (0, b"BZh", "archive", "bzip2", "BZIP2", {".bz2", ".tbz", ".tbz2"}),
    (0, b"\xfd7zXZ\x00", "archive", "xz", "XZ", {".xz", ".txz"}),
    (0, b"\x28\xb5\x2f\xfd", "archive", "zstd", "Zstandard", {".zst"}),
    (0, b"MSCF", "archive", "cab", "Microsoft Cabinet", {".cab", ".msu"}),
    (257, b"ustar", "archive", "tar", "TAR", {".tar"}),
    (0x8001, b"CD001", "container", "iso", "ISO-9660 Image", {".iso", ".img"}),
    (0, b"conectix", "container", "vhd", "VHD Disk Image", {".vhd"}),
    (0, b"vhdxfile", "container", "vhdx", "VHDX Disk Image", {".vhdx"}),
    (0, b"KDMV", "container", "vmdk", "VMware Disk", {".vmdk"}),

    # ── Bilder ────────────────────────────────────────────────────────────
    (0, b"\xff\xd8\xff", "image", "jpeg", "JPEG", {".jpg", ".jpeg", ".jpe", ".jfif"}),
    (0, b"\x89PNG\r\n\x1a\n", "image", "png", "PNG", {".png"}),
    (0, b"GIF87a", "image", "gif", "GIF", {".gif"}),
    (0, b"GIF89a", "image", "gif", "GIF", {".gif"}),
    (0, b"II*\x00", "image", "tiff", "TIFF", {".tif", ".tiff", ".dng", ".nef", ".cr2", ".arw"}),
    (0, b"MM\x00*", "image", "tiff", "TIFF", {".tif", ".tiff", ".dng", ".nef"}),
    (0, b"\x00\x00\x01\x00", "image", "ico", "Windows Icon", {".ico"}),
    (0, b"8BPS", "image", "psd", "Photoshop", {".psd"}),
    (0, b"BM", "image", "bmp", "Bitmap", {".bmp", ".dib"}),

    # ── Audio / Video ─────────────────────────────────────────────────────
    (0, b"ID3", "media", "mp3", "MP3 (ID3)", {".mp3"}),
    (0, b"\xff\xfb", "media", "mp3", "MP3", {".mp3"}),
    (0, b"fLaC", "media", "flac", "FLAC", {".flac"}),
    (0, b"OggS", "media", "ogg", "Ogg", {".ogg", ".oga", ".ogv", ".opus"}),
    (0, b"\x1a\x45\xdf\xa3", "media", "mkv", "Matroska/WebM", {".mkv", ".webm", ".mka"}),
    (4, b"ftyp", "media", "mp4", "ISO-Media (MP4/MOV/HEIC)",
     {".mp4", ".m4a", ".m4v", ".mov", ".heic", ".heif", ".3gp", ".avif", ".m4b"}),
    (0, b"FLV", "media", "flv", "Flash Video", {".flv"}),
    (0, b"MThd", "media", "midi", "MIDI", {".mid", ".midi"}),

    # ── Datenbanken / System ──────────────────────────────────────────────
    (0, b"SQLite format 3\x00", "database", "sqlite", "SQLite-Datenbank",
     {".db", ".sqlite", ".sqlite3", ".db3", ""}),
    (0, b"regf", "system", "registry_hive", "Windows Registry Hive", {"", ".dat", ".hve", ".hiv"}),
    (0, b"ElfFile\x00", "system", "evtx", "Windows Event Log", {".evtx"}),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "shortcut", "lnk", "Windows-Verknüpfung (LNK)", {".lnk"}),
    (0, b"MAM\x04", "system", "prefetch", "Prefetch (komprimiert)", {".pf"}),
    (4, b"SCCA", "system", "prefetch", "Prefetch", {".pf"}),
    (0, b"\xd4\xc3\xb2\xa1", "capture", "pcap", "PCAP", {".pcap", ".cap"}),
    (0, b"\xa1\xb2\xc3\xd4", "capture", "pcap", "PCAP", {".pcap", ".cap"}),
    (0, b"\x0a\x0d\x0d\x0a", "capture", "pcapng", "PCAPNG", {".pcapng"}),

    # ── Schriften / Sonstiges ─────────────────────────────────────────────
    (0, b"wOFF", "font", "woff", "WOFF", {".woff"}),
    (0, b"wOF2", "font", "woff2", "WOFF2", {".woff2"}),
    (0, b"\x00\x01\x00\x00\x00", "font", "ttf", "TrueType", {".ttf"}),
    (0, b"OTTO", "font", "otf", "OpenType", {".otf"}),
    (0, b"-----BEGIN PGP", "crypto", "pgp", "PGP", {".asc", ".gpg", ".pgp"}),
    (0, b"-----BEGIN ", "crypto", "pem", "PEM (Schlüssel/Zertifikat)", {".pem", ".crt", ".key", ".cer", ".pub"}),
]

# Textbasierte Typen – erkannt am Inhalt der ersten Bytes (Kleinbuchstaben)
TEXT_HINTS = [
    (b"<svg", "web", "svg", "SVG-Grafik", {".svg"}),
    (b"<hta:application", "web", "hta", "HTML-Application (HTA)", {".hta"}),
    (b"<!doctype html", "web", "html", "HTML", {".html", ".htm", ".xhtml", ".mht", ".hta"}),
    (b"<html", "web", "html", "HTML", {".html", ".htm", ".xhtml", ".hta"}),
    (b"<?php", "script", "php", "PHP", {".php", ".phtml", ".php5", ".inc"}),
    (b"<job", "script", "wsf", "Windows Script File", {".wsf"}),
    (b"<package", "script", "wsf", "Windows Script File", {".wsf"}),
    (b"<?xml", "text", "xml", "XML", {".xml", ".xsl", ".xslt", ".config", ".manifest", ".plist", ".svg",
                                       ".rss", ".kml", ".gpx", ".xaml", ".csproj", ".vcxproj", ".resx"}),
    (b"return-path:", "email", "eml", "E-Mail (RFC 822)", {".eml", ".msg", ".mht", ".txt"}),
    (b"received:", "email", "eml", "E-Mail (RFC 822)", {".eml", ".mht", ".txt"}),
    (b"mime-version:", "email", "eml", "E-Mail (MIME)", {".eml", ".mht", ".mhtml"}),
]

SCRIPT_EXTS = {
    ".ps1": "powershell", ".psm1": "powershell", ".psd1": "powershell",
    ".vbs": "vbscript", ".vbe": "vbscript", ".vba": "vbscript",
    ".js": "javascript", ".jse": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".bat": "batch", ".cmd": "batch",
    ".wsf": "wsf", ".wsh": "wsf", ".hta": "hta",
    ".py": "python", ".pyw": "python",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".php": "php", ".pl": "perl", ".rb": "ruby", ".lua": "lua",
    ".reg": "registry", ".inf": "inf", ".scf": "scf", ".url": "url", ".desktop": "desktop",
    ".applescript": "applescript", ".scpt": "applescript", ".jsp": "jsp", ".asp": "asp", ".aspx": "asp",
}

# Endungen, die Windows direkt ausführt / die als Tarnung dienen
DANGEROUS_EXTS = {
    ".exe", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".jar", ".dll", ".reg", ".iso", ".img", ".vhd",
    ".vhdx", ".appx", ".msix", ".application", ".gadget", ".inf", ".scf", ".url", ".chm", ".xll",
    ".sys", ".ocx", ".one", ".xlam", ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".ppam", ".sldm",
    ".website", ".settingcontent-ms", ".library-ms", ".search-ms", ".appref-ms", ".cab",
}

ZIP_FAMILY = {
    "docx": ("document", "Word (OOXML)", {".docx", ".docm", ".dotx", ".dotm"}),
    "xlsx": ("document", "Excel (OOXML)", {".xlsx", ".xlsm", ".xltx", ".xltm", ".xlam"}),
    "pptx": ("document", "PowerPoint (OOXML)", {".pptx", ".pptm", ".potx", ".ppsx", ".ppam", ".ppsm"}),
    "jar": ("archive", "Java-Archiv (JAR)", {".jar", ".war", ".ear"}),
    "apk": ("archive", "Android-Paket (APK)", {".apk", ".aab", ".xapk"}),
    "odf": ("document", "OpenDocument", {".odt", ".ods", ".odp", ".odg", ".ott"}),
    "epub": ("document", "EPUB", {".epub"}),
    "appx": ("archive", "Windows-App-Paket", {".appx", ".msix", ".appxbundle", ".msixbundle"}),
    "vsix": ("archive", "VS-Erweiterung", {".vsix", ".nupkg", ".xpi", ".crx", ".whl"}),
    "zip": ("archive", "ZIP-Archiv", {".zip", ".zipx", ".kmz", ".cbz", ".whl", ".nupkg", ".xpi",
                                      ".ipa", ".sketch", ".3mf", ".vsdx", ".xps", ".oxps"}),
}


def _read(path, n, offset=0):
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            return f.read(n)
    except OSError:
        return b""


def _zip_family(path):
    """Unterscheidet ZIP-basierte Formate anhand des Inhaltsverzeichnisses."""
    import zipfile
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist()[:5000])
            mimetype = b""
            if "mimetype" in names:
                info = z.getinfo("mimetype")
                if info.file_size < 200:
                    mimetype = z.read("mimetype")
    except Exception:
        return "zip"
    if "word/document.xml" in names:
        return "docx"
    if "xl/workbook.xml" in names:
        return "xlsx"
    if "ppt/presentation.xml" in names:
        return "pptx"
    if "AndroidManifest.xml" in names or "classes.dex" in names:
        return "apk"
    if "AppxManifest.xml" in names or "AppxMetadata/AppxBundleManifest.xml" in names:
        return "appx"
    if mimetype.startswith(b"application/epub"):
        return "epub"
    if mimetype.startswith(b"application/vnd.oasis.opendocument"):
        return "odf"
    if "META-INF/MANIFEST.MF" in names:
        return "jar"
    if "extension.vsixmanifest" in names:
        return "vsix"
    return "zip"


def _looks_text(buf):
    if not buf:
        return False
    if buf.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in buf[:4096]:
        return False
    printable = sum(1 for b in buf[:4096] if b in (9, 10, 13) or 32 <= b < 127 or b >= 0xC2)
    return printable / max(1, len(buf[:4096])) > 0.92


def identify(path, deep=True):
    """
    deep=False: nur Kopfbytes, ohne das ZIP-Inhaltsverzeichnis zu parsen
    (für den Notfallbericht, wenn der Sandbox-Worker gescheitert ist).
    Returns dict:
      category, subtype, description, expected_exts (sorted list),
      extension, extension_mismatch (bool), is_text (bool)
    """
    p = Path(path)
    ext = p.suffix.lower()
    head = _read(path, 4096)
    result = None

    for off, sig, cat, sub, desc, exts in SIGNATURES:
        if off < len(head):
            chunk = head[off:off + len(sig)]
        else:
            chunk = _read(path, len(sig), off)
        if chunk == sig:
            if sub == "bmp" and len(head) >= 14:
                # "BM" ist kurz → Plausibilität über Header-Größe prüfen
                import struct
                size = struct.unpack("<I", head[2:6])[0]
                if not (14 < size < 1 << 31):
                    continue
            if sub == "mp3" and sig == b"\xff\xfb" and ext not in {".mp3", ""}:
                continue
            if sub == "ttf" and ext not in {".ttf", ".ttc", ""}:
                continue
            if sub == "zip":
                fam = _zip_family(path) if deep else "zip"
                cat, desc, exts = ZIP_FAMILY[fam]
                sub = fam
            if sub == "macho_fat" and ext == ".class":
                cat, sub, desc = "executable", "java_class", "Java Class"
            result = {"category": cat, "subtype": sub, "description": desc, "expected_exts": exts}
            break

    is_text = False
    if result is None:
        is_text = _looks_text(head)
        low = head[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
        for sig, cat, sub, desc, exts in TEXT_HINTS:
            if low.startswith(sig) or (sub in ("html", "hta", "svg") and sig in low[:1024]):
                result = {"category": cat, "subtype": sub, "description": desc, "expected_exts": exts}
                break
        if result is None and head[:2] == b"#!":
            interp = head[2:80].split(b"\n")[0].decode("latin-1", "replace")
            lang = "python" if "python" in interp else "shell" if "sh" in interp else "script"
            result = {"category": "script", "subtype": lang, "description": f"Skript ({interp.strip()})",
                      "expected_exts": {"", ".sh", ".py", ".pl", ".rb", ".bash"}}
        if result is None and ext in SCRIPT_EXTS and is_text:
            lang = SCRIPT_EXTS[ext]
            result = {"category": "script", "subtype": lang, "description": f"Skript ({lang})",
                      "expected_exts": {e for e, l in SCRIPT_EXTS.items() if l == lang}}
        if result is None and is_text:
            result = {"category": "text", "subtype": "text", "description": "Textdatei",
                      "expected_exts": None}
        if result is None:
            result = {"category": "binary", "subtype": "unknown", "description": "Unbekanntes Binärformat",
                      "expected_exts": None}

    exts = result.pop("expected_exts")
    result["expected_exts"] = sorted(exts) if exts else []
    result["extension"] = ext
    result["is_text"] = is_text or result["category"] in ("script", "web", "text", "email", "rtf")
    result["extension_mismatch"] = bool(exts) and ext not in exts
    return result
