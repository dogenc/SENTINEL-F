"""
AppContainer für den Sandbox-Worker: KEIN Netzwerk, keine Nutzerdateien – ohne Adminrechte.

Ein AppContainer ohne Capabilities (insbesondere ohne internetClient) hat unter
Windows 8+ keinerlei Netzwerkzugriff (auch nicht Loopback) und sieht nur Objekte,
die ausdrücklich für seine SID freigegeben sind. Er läuft automatisch mit
Low Integrity; das Job Object (1 Prozess, RAM/CPU) bleibt zusätzlich bestehen.

Damit der Worker starten kann, bekommt die Container-SID einmalig Lese-/Ausführ-
rechte auf Python + Projekt und Schreibrechte auf den Job-Ordner (icacls, als
normaler Benutzer auf eigenen Ordnern erlaubt). Die zu prüfende Datei wird in
den Job-Ordner KOPIERT – die Rechte der Beweisdatei werden nie verändert.

Scheitert irgendein Schritt, fällt core/sandbox.py auf den Low-IL-Worker zurück
und vermerkt den Grund im Ergebnis.
"""
import ctypes
import json
import shutil
import subprocess
import sys
from pathlib import Path

NAME = "DGKN.Sentinel.Worker"
IS_WINDOWS = sys.platform == "win32"
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
HR_ALREADY_EXISTS = 0x800700B7

if IS_WINDOWS:
    from ctypes import wintypes
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)

    class SECURITY_CAPABILITIES(ctypes.Structure):
        _fields_ = [("AppContainerSid", ctypes.c_void_p), ("Capabilities", ctypes.c_void_p),
                    ("CapabilityCount", wintypes.DWORD), ("Reserved", wintypes.DWORD)]

    userenv.CreateAppContainerProfile.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                                  ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    userenv.CreateAppContainerProfile.restype = ctypes.c_long
    userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    adv.FreeSid.argtypes = [ctypes.c_void_p]
    k32.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                      ctypes.POINTER(ctypes.c_size_t)]
    k32.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
                                              ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
    k32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    k32.LocalFree.argtypes = [ctypes.c_void_p]


def supported():
    return IS_WINDOWS and hasattr(userenv, "CreateAppContainerProfile")


def profile_sid():
    """PSID des Worker-Containers (anlegen oder vorhandenen ableiten). Aufrufer gibt mit FreeSid frei."""
    sid = ctypes.c_void_p()
    hr = userenv.CreateAppContainerProfile(NAME, "SENTINEL-F worker", "Isolated file analysis without network",
                                           None, 0, ctypes.byref(sid))
    if (hr & 0xFFFFFFFF) == HR_ALREADY_EXISTS:           # Profil existiert schon (zweiter Start)
        hr = userenv.DeriveAppContainerSidFromAppContainerName(NAME, ctypes.byref(sid))
    if hr != 0 or not sid.value:
        raise OSError(hr & 0xFFFFFFFF, f"AppContainer-Profil nicht verfügbar (HRESULT 0x{hr & 0xFFFFFFFF:08X})")
    return sid


def sid_string(psid):
    s = wintypes.LPWSTR()
    if not adv.ConvertSidToStringSidW(psid, ctypes.byref(s)):
        raise OSError(ctypes.get_last_error(), "ConvertSidToStringSid fehlgeschlagen")
    try:
        return s.value
    finally:
        k32.LocalFree(s)


def _icacls(path, sid, rights):
    inherit = "(OI)(CI)" if Path(path).is_dir() else ""
    r = subprocess.run(["icacls", str(path), "/grant", f"*{sid}:{inherit}{rights}", "/Q"],
                       capture_output=True, text=True, timeout=600,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return r.returncode == 0, (r.stderr or r.stdout).strip()[:300]


# Programmteile, die der Worker braucht – bewusst NICHT data/ (Verlauf), reports/, .cache/ und die Schlüsseldatei
CODE_DIRS = ("core", "engines", "resources")


def read_paths():
    """Was der Worker lesen/ausführen muss: Python (Basis + venv + User-Site) und die Programm-Dateien."""
    import site
    paths = {Path(sys.base_prefix), Path(sys.prefix)}
    try:
        paths.add(Path(site.getusersitepackages()))
    except Exception:
        pass
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        paths |= {exe.parent, exe}                       # Ordner selbst ohne Vererbung (Portable: UserData\)
        paths.add(Path(getattr(sys, "_MEIPASS", exe.parent)))   # _internal\: Python, Code, resources
    else:
        root = Path(__file__).resolve().parent.parent
        paths.add(root)                                  # Wurzel selbst ohne Vererbung, s. _icacls_root
        paths |= {root / d for d in CODE_DIRS}
        paths |= {root / "main.py"}
        paths |= {p for p in (root / "config").glob("*.py") if p.name != "local_secrets.py"}
        paths.add(root / "config")
    return sorted(p for p in paths if p.exists())


def ensure_access(jobs_root, marker):
    """Einmalige Freigaben für die Container-SID. → (sid_string, [Hinweise])"""
    psid = profile_sid()
    try:
        sid = sid_string(psid)
    finally:
        adv.FreeSid(psid)
    marker = Path(marker)
    want = {"sid": sid, "read": [str(p) for p in read_paths()], "write": str(jobs_root)}
    try:
        if json.loads(marker.read_text(encoding="utf-8")) == want:
            return sid, []
    except (OSError, ValueError):
        pass
    notes = []
    if getattr(sys, "frozen", False):
        plain = {Path(sys.executable).resolve().parent}
    else:
        root = Path(__file__).resolve().parent.parent
        plain = {root, root / "config"}
    for p in want["read"]:
        if Path(p) in plain:
            ok, msg = _icacls_plain(p, sid, "(RX)")     # nur der Ordner selbst, nicht vererbt (data/, Schlüssel)
        else:
            ok, msg = _icacls(p, sid, "(RX)")
        if not ok:
            notes.append(f"read grant failed for {p}: {msg}")
    Path(jobs_root).mkdir(parents=True, exist_ok=True)
    ok, msg = _icacls(jobs_root, sid, "(M)")
    if not ok:
        raise OSError(5, f"write grant on job folder failed: {msg}")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(want), encoding="utf-8")
    return sid, notes


def _icacls_plain(path, sid, rights):
    r = subprocess.run(["icacls", str(path), "/grant", f"*{sid}:{rights}", "/Q"], capture_output=True, text=True,
                       timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return r.returncode == 0, (r.stderr or r.stdout).strip()[:300]


def stage_file(src, jobdir):
    """Beweisdatei in den Job-Ordner kopieren (inkl. Mark-of-the-Web) – die Rechte des Originals bleiben unberührt."""
    dst_dir = Path(jobdir) / "input"
    dst_dir.mkdir(exist_ok=True)
    dst = dst_dir / Path(src).name
    if Path(src).is_dir():                         # Postfach-Ordner (Thunderbird-Profil, EML-Sammlung)
        shutil.copytree(src, dst, symlinks=False, ignore_dangling_symlinks=True)
        return str(dst)
    shutil.copy2(src, dst)
    if IS_WINDOWS:
        try:
            with open(str(src) + ":Zone.Identifier", "rb") as f:
                zone = f.read(4096)
            with open(str(dst) + ":Zone.Identifier", "wb") as f:
                f.write(zone)
        except OSError:
            pass
    return str(dst)


def startup_attributes():
    """→ (attribute_list_buffer, security_capabilities, psid) – muss bis nach CreateProcess leben."""
    psid = profile_sid()
    caps = SECURITY_CAPABILITIES()
    caps.AppContainerSid = psid.value
    caps.Capabilities = None
    caps.CapabilityCount = 0                       # keine Capabilities → kein Netzwerk
    size = ctypes.c_size_t()
    k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if not k32.InitializeProcThreadAttributeList(ctypes.addressof(buf), 1, 0, ctypes.byref(size)):
        adv.FreeSid(psid)
        raise OSError(ctypes.get_last_error(), "InitializeProcThreadAttributeList fehlgeschlagen")
    if not k32.UpdateProcThreadAttribute(ctypes.addressof(buf), 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                         ctypes.addressof(caps), ctypes.sizeof(caps), None, None):
        k32.DeleteProcThreadAttributeList(buf)
        adv.FreeSid(psid)
        raise OSError(ctypes.get_last_error(), "UpdateProcThreadAttribute fehlgeschlagen")
    return buf, caps, psid


def release(buf, psid):
    try:
        k32.DeleteProcThreadAttributeList(ctypes.addressof(buf))
    finally:
        adv.FreeSid(psid)
