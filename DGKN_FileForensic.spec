# ═══════════════════════════════════════════════════════════════════════════════
#  DGKN@Labs-FileForensic  ·  PyInstaller Spec
#  Build command (Windows):
#     pyinstaller DGKN_FileForensic.spec --clean --noconfirm
#  Setup + Portable in einem Schritt:  powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
# ═══════════════════════════════════════════════════════════════════════════════
# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

block_cipher = None
PROJECT = Path(".").resolve()

# Data files bundled into the EXE
datas = [
    (str(PROJECT / "resources" / "cesium_globe.html"), "resources"),
    (str(PROJECT / "resources" / "yara"),              "resources/yara"),
    (str(PROJECT / "resources" / "sentinel.ico"),      "resources"),
    (str(PROJECT / "resources" / "sentinel.png"),      "resources"),
]

# Version aus config/settings.py → Windows-Dateieigenschaften der EXE
import re as _re
_ver = _re.search(r'APP_VERSION\s*=\s*"([^"]+)"', (PROJECT / "config" / "settings.py").read_text(encoding="utf-8")).group(1)
_vt = tuple(int(x) for x in (_ver.split(".") + ["0", "0", "0"])[:4])
_vfile = PROJECT / "build" / "version_info.txt"
_vfile.parent.mkdir(exist_ok=True)
_vfile.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={_vt}, prodvers={_vt}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1,
                    subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'DGKN@Labs'),
      StringStruct('FileDescription', 'SENTINEL-F File-Forensic Intelligence Suite'),
      StringStruct('FileVersion', '{_ver}'),
      StringStruct('InternalName', 'DGKN-FileForensic'),
      StringStruct('LegalCopyright', '(c) 2026 DGKN@Labs - GPL-3.0-or-later with attribution (see NOTICE)'),
      StringStruct('OriginalFilename', 'DGKN-FileForensic.exe'),
      StringStruct('ProductName', 'SENTINEL-F'),
      StringStruct('ProductVersion', '{_ver}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding="utf-8")

# Hidden imports — PyInstaller sometimes misses these
hiddenimports = [
    # Qt
    "PyQt6.sip",
    "PyQt6.QtCore",
    "PyQt6.QtGui",
    "PyQt6.QtWidgets",
    "PyQt6.QtWebEngineCore",
    "PyQt6.QtWebEngineWidgets",
    # Image
    "PIL._tkinter_finder",
    "PIL.ImageTk",
    "PIL.ExifTags",
    "piexif",
    "scipy",
    "scipy.ndimage",
    "scipy.signal",
    # PDF
    "pikepdf",
    "pdf2image",
    "pytesseract",
    # Document
    "docx",
    "openpyxl",
    "pptx",
    "olefile",
    "oletools",
    "oletools.olevba",
    "oletools.oleid",
    "oletools.oleobj",
    "lxml",
    "lxml.etree",
    # Threat analysis
    "pefile",
    "elftools.elf.elffile",
    "yara",
    "py7zr",
    "LnkParse3",
    "core.filetype",
    "engines.analyzers",
    # Project
    "config.settings",
    "core.utils",
    "engines.score_engine",
    "engines.ollama_client",
    "engines.image_engine",
    "engines.pdf_engine",
    "engines.document_engine",
    "gui.main_window",
    "gui.dashboard",
    "gui.analysis_view",
    "gui.ai_panel",
    "gui.splash",
    "gui.titlebar",
    "gui.widgets",
    "gui.styles",
    # Berichte (PDF-Druck), Signaturen, Postfächer
    "PyQt6.QtPrintSupport",
    "cryptography",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "extract_msg",      # optional: Outlook .msg
    "pypff",            # optional: Outlook .pst/.ost (libpff-python)
]
# Alle Projektmodule automatisch – neue Funktionen (Verlauf, Graph, Payload-Kette, Detektiv, …) fehlen so nie
from PyInstaller.utils.hooks import collect_submodules
for _pkg in ("config", "core", "engines", "gui"):
    hiddenimports += [m for m in collect_submodules(_pkg) if not m.endswith("local_secrets")]

a = Analysis(
    ["main.py"],
    pathex=[str(PROJECT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "matplotlib", "notebook", "IPython", "pytest",
        "config.local_secrets",           # Schlüssel NIE in die EXE – sie liegen in den Nutzerdaten
    ],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="DGKN-FileForensic",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,                        # windowed app, no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(PROJECT / "resources" / "sentinel.ico"),
    version=str(_vfile),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="DGKN-FileForensic",
)
