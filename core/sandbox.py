"""
Analyse-Sandbox für Windows – jede Datei wird in einem abgeschotteten Prozess untersucht.

Schutzschichten (alle mit Windows-Bordmitteln, keine Admin-Rechte nötig):
  1. Eigener Worker-Prozess      → Absturz/Exploit eines Parsers trifft nie die App
  2. Low Integrity Level          → Worker kann nichts in Benutzerdateien, Programme
                                    oder die Registry schreiben (wie die Browser-Sandbox)
  3. Job Object                   → max. 1 aktiver Prozess (kann NICHTS starten),
                                    RAM-Obergrenze, CPU-Zeitlimit, Kill beim Schließen,
                                    kein Zugriff auf Zwischenablage/Desktop/Systemeinstellungen
  4. Wanduhr-Timeout              → hängende Analysen werden beendet

Der Worker schreibt nur in einen eigenen Ordner unter %LOCALAPPDATA%Low.
Sprengt eine Datei die Sandbox (Speicher, Zeit, Absturz), ist das selbst ein Befund.
"""
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from ctypes import wintypes
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"

# ─── Grenzwerte ──────────────────────────────────────────────────────────────
MEMORY_LIMIT = 2 << 30          # 2 GiB pro Worker
CPU_TIME_LIMIT = 240            # Sekunden reine CPU-Zeit
WALL_TIMEOUT = 300              # Sekunden Wanduhr
JOB_MAX_AGE = 24 * 3600         # alte Job-Ordner werden danach aufgeräumt

WORKER_FLAG = "--sentinel-worker"
SELFTEST_FLAG = "--sentinel-selftest"
DIFF_FLAG = "--sentinel-diff"
MAILBOX_FLAG = "--sentinel-mailbox"


def jobs_root():
    base = os.environ.get("LOCALAPPDATA")
    root = Path(base + "Low") if base else Path.home() / "AppData" / "LocalLow"
    return root / "DGKN_Sentinel" / "jobs"


def worker_command(*args):
    """Kommandozeile für den Worker – im Quellcode-Betrieb und als gebaute EXE."""
    if getattr(sys, "frozen", False):
        return [sys.executable, *args]
    main = Path(__file__).resolve().parent.parent / "main.py"
    # -B: keine .pyc schreiben (Low-IL darf dort ohnehin nicht schreiben), -X utf8: stabile Kodierung
    return [sys.executable, "-B", "-X", "utf8", str(main), *args]


# ─── Win32-Strukturen ────────────────────────────────────────────────────────
if IS_WINDOWS:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    class STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    class TOKEN_MANDATORY_LABEL(ctypes.Structure):
        _fields_ = [("Label", SID_AND_ATTRIBUTES)]

    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.ResumeThread.argtypes = [wintypes.HANDLE]
    k32.ResumeThread.restype = wintypes.DWORD
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                                   wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                                   ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]
    k32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                              wintypes.DWORD, ctypes.c_void_p]
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.DuplicateTokenEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int,
                                     ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
    adv.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    adv.GetLengthSid.argtypes = [ctypes.c_void_p]
    adv.GetLengthSid.restype = wintypes.DWORD
    adv.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    adv.CreateProcessAsUserW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
                                         ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p,
                                         wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
                                         ctypes.POINTER(PROCESS_INFORMATION)]

# Konstanten
CREATE_SUSPENDED = 0x4
CREATE_UNICODE_ENVIRONMENT = 0x400
CREATE_NO_WINDOW = 0x08000000
BELOW_NORMAL_PRIORITY_CLASS = 0x4000
JOB_LIMIT_PROCESS_TIME = 0x2
JOB_LIMIT_ACTIVE_PROCESS = 0x8
JOB_LIMIT_PRIORITY_CLASS = 0x20
JOB_LIMIT_PROCESS_MEMORY = 0x100
JOB_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x400
JOB_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_UI_ALL = 0xFF   # Handles, Clipboard lesen/schreiben, Systemparameter, Anzeige, Atome, Desktop, Abmelden
LOW_INTEGRITY_SID = "S-1-16-4096"


def _err(what):
    return OSError(ctypes.get_last_error(), f"{what} fehlgeschlagen")


def _create_job():
    job = k32.CreateJobObjectW(None, None)
    if not job:
        raise _err("CreateJobObject")
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    b = info.BasicLimitInformation
    b.LimitFlags = (JOB_LIMIT_ACTIVE_PROCESS | JOB_LIMIT_PROCESS_MEMORY | JOB_LIMIT_PROCESS_TIME |
                    JOB_LIMIT_KILL_ON_JOB_CLOSE | JOB_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
                    JOB_LIMIT_PRIORITY_CLASS)
    b.ActiveProcessLimit = 1
    b.PerProcessUserTimeLimit = CPU_TIME_LIMIT * 10_000_000   # 100-ns-Einheiten
    b.PriorityClass = BELOW_NORMAL_PRIORITY_CLASS
    info.ProcessMemoryLimit = MEMORY_LIMIT
    if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        k32.CloseHandle(job)
        raise _err("SetInformationJobObject(limits)")
    ui = wintypes.DWORD(JOB_UI_ALL)
    k32.SetInformationJobObject(job, 4, ctypes.byref(ui), ctypes.sizeof(ui))
    return job


def _low_integrity_token():
    """Kopie des eigenen Tokens, herabgestuft auf Low Integrity."""
    tok, dup, sid = wintypes.HANDLE(), wintypes.HANDLE(), ctypes.c_void_p()
    # TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x2 | 0x8 | 0x1 | 0x80, ctypes.byref(tok)):
        raise _err("OpenProcessToken")
    try:
        if not adv.DuplicateTokenEx(tok, 0x02000000, None, 2, 1, ctypes.byref(dup)):   # MAXIMUM_ALLOWED, primary
            raise _err("DuplicateTokenEx")
        if not adv.ConvertStringSidToSidW(LOW_INTEGRITY_SID, ctypes.byref(sid)):
            raise _err("ConvertStringSidToSid")
        tml = TOKEN_MANDATORY_LABEL()
        tml.Label.Sid = sid
        tml.Label.Attributes = 0x20   # SE_GROUP_INTEGRITY
        size = ctypes.sizeof(tml) + adv.GetLengthSid(sid)
        if not adv.SetTokenInformation(dup, 25, ctypes.byref(tml), size):   # TokenIntegrityLevel
            raise _err("SetTokenInformation")
        return dup
    finally:
        k32.CloseHandle(tok)
        if sid:
            k32.LocalFree(sid)


def _env_block(env):
    s = "".join(f"{k}={v}\0" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper())) + "\0"
    return ctypes.create_unicode_buffer(s)


def _spawn_appcontainer(cmdline, flags, block, jobdir, job):
    """Worker im AppContainer ohne Capabilities starten (kein Netz). → PROCESS_INFORMATION"""
    from core import appcontainer as ac
    buf, caps, psid = ac.startup_attributes()
    try:
        six = STARTUPINFOEXW()
        six.StartupInfo.cb = ctypes.sizeof(six)
        six.lpAttributeList = ctypes.addressof(buf)
        pi = PROCESS_INFORMATION()
        ok = k32.CreateProcessW(None, cmdline, None, None, False, flags | ac.EXTENDED_STARTUPINFO_PRESENT,
                                block, str(jobdir), ctypes.cast(ctypes.pointer(six), ctypes.POINTER(STARTUPINFOW)),
                                ctypes.byref(pi))
        if not ok:
            raise _err("CreateProcess(AppContainer)")
        return pi
    finally:
        ac.release(buf, psid)
        del caps


def _spawn(cmd, jobdir, low_integrity=True, appcontainer=False):
    """Startet den Worker angehalten, steckt ihn ins Job Object, lässt ihn dann laufen."""
    env = dict(os.environ)
    tmp = str(jobdir / "tmp")
    os.makedirs(tmp, exist_ok=True)
    env.update(TEMP=tmp, TMP=tmp, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8",
               QT_QPA_PLATFORM="offscreen")
    block = _env_block(env)
    cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(cmd))
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW
    job = _create_job()
    integrity = "medium"
    token = None
    try:
        if appcontainer:
            pi = _spawn_appcontainer(cmdline, flags, block, jobdir, job)
            if not k32.AssignProcessToJobObject(job, pi.hProcess):
                e = _err("AssignProcessToJobObject")
                k32.TerminateProcess(pi.hProcess, 1)
                raise e
            k32.ResumeThread(pi.hThread)
            k32.CloseHandle(pi.hThread)
            return job, pi.hProcess, "appcontainer"
        if low_integrity:
            try:
                token = _low_integrity_token()
            except OSError:
                token = None
        if token:
            ok = adv.CreateProcessAsUserW(token, None, cmdline, None, None, False, flags, block,
                                          str(jobdir), ctypes.byref(si), ctypes.byref(pi))
            integrity = "low" if ok else integrity
        else:
            ok = False
        if not ok:
            ok = k32.CreateProcessW(None, cmdline, None, None, False, flags, block, str(jobdir),
                                    ctypes.byref(si), ctypes.byref(pi))
            integrity = "medium"
        if not ok:
            raise _err("CreateProcess")
        if not k32.AssignProcessToJobObject(job, pi.hProcess):
            e = _err("AssignProcessToJobObject")
            k32.TerminateProcess(pi.hProcess, 1)
            raise e
        k32.ResumeThread(pi.hThread)
        k32.CloseHandle(pi.hThread)
        return job, pi.hProcess, integrity
    except Exception:
        k32.CloseHandle(job)
        raise
    finally:
        if token:
            k32.CloseHandle(token)


def _peak_memory(job):
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    if k32.QueryInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info), None):
        return info.PeakProcessMemoryUsed
    return None


class SandboxRun:
    """Ergebnis eines Sandbox-Laufs (roh)."""

    def __init__(self):
        self.exit_code = None
        self.timed_out = False
        self.integrity = None
        self.peak_memory = None
        self.seconds = 0.0
        self.jobdir = None
        self.staged = {}               # Originalpfad → Kopie im Job-Ordner (AppContainer)


def run_worker(args, progress_fn=None, timeout=WALL_TIMEOUT, low_integrity=True, appcontainer=False, stage=()):
    """
    Startet main.py im Worker-Modus in der Sandbox und wartet auf das Ende.
    appcontainer=True: ohne Netzwerk; die Argumente an den Positionen `stage` sind Dateien,
    die dafür in den Job-Ordner kopiert werden (der Container darf Nutzerdateien nicht lesen).
    """
    cleanup_old_jobs()
    jobdir = jobs_root() / uuid.uuid4().hex
    jobdir.mkdir(parents=True)
    run = SandboxRun()
    run.jobdir = jobdir
    args = list(args)
    run.staged = {}
    if appcontainer:
        from core import appcontainer as ac
        for i in stage:
            run.staged[args[i]] = ac.stage_file(args[i], jobdir)
            args[i] = run.staged[args[i]]
    cmd = worker_command(*args, str(jobdir))
    t0 = time.monotonic()
    job, proc, run.integrity = _spawn(cmd, jobdir, low_integrity, appcontainer)
    prog_file, prog_pos = jobdir / "progress.jsonl", 0
    try:
        while True:
            if k32.WaitForSingleObject(proc, 200) == 0:   # WAIT_OBJECT_0
                break
            if progress_fn and prog_file.exists():
                with open(prog_file, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(prog_pos)
                    for line in f:
                        try:
                            p = json.loads(line)
                            progress_fn(p["label"], p["value"])
                        except (ValueError, KeyError):
                            pass
                    prog_pos = f.tell()
            if time.monotonic() - t0 > timeout:
                run.timed_out = True
                k32.TerminateJobObject(job, 0xDEAD)
                k32.WaitForSingleObject(proc, 5000)
                break
        code = wintypes.DWORD()
        k32.GetExitCodeProcess(proc, ctypes.byref(code))
        run.exit_code = code.value
        run.peak_memory = _peak_memory(job)
    finally:
        k32.CloseHandle(proc)
        k32.CloseHandle(job)          # KILL_ON_JOB_CLOSE: nichts überlebt
        run.seconds = round(time.monotonic() - t0, 2)
    return run


def cleanup_old_jobs():
    root = jobs_root()
    if not root.is_dir():
        return
    now = time.time()
    for d in root.iterdir():
        try:
            if d.is_dir() and now - d.stat().st_mtime > JOB_MAX_AGE:
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass


def available():
    return IS_WINDOWS


# ─── Öffentliche API ─────────────────────────────────────────────────────────
def analyze_isolated(path, progress_fn=None, log_fn=None, timeout=WALL_TIMEOUT):
    """
    Wie engines.run_forensic(), aber vollständig im Sandbox-Worker.
    Liefert denselben Ergebnisvertrag plus result['sandbox'].
    """
    log = log_fn or (lambda m, l="INFO": None)
    path = str(Path(path).resolve())
    if not available():
        from engines import run_forensic
        log("Sandbox nur unter Windows verfügbar – Analyse läuft im App-Prozess", "WARN")
        res = run_forensic(path, progress_fn, log_fn)
        res["sandbox"] = {"isolated": False, "reason": "platform"}
        return res

    try:
        run, net = _run_best([WORKER_FLAG, path], [1], progress_fn, timeout, log)
    except OSError as e:
        log(f"Sandbox konnte nicht starten ({e}) – Analyse abgebrochen", "ERR")
        return _fallback_result(path, None, f"Sandbox-Start fehlgeschlagen: {e}")

    info = {"isolated": True, "integrity": run.integrity, "process_limit": 1,
            "memory_limit": MEMORY_LIMIT, "cpu_limit_s": CPU_TIME_LIMIT, "wall_limit_s": timeout,
            "peak_memory": run.peak_memory, "seconds": run.seconds, "exit_code": run.exit_code,
            "jobdir": str(run.jobdir), "network": net}
    result_file = run.jobdir / "result.json"
    res = None
    if result_file.exists() and not run.timed_out:
        try:
            res = json.loads(remap_paths(result_file.read_text(encoding="utf-8"), run.staged))
        except ValueError:
            res = None
        if res is not None and run.staged:
            from core.utils import file_stat_snapshot
            res["file"] = file_stat_snapshot(path)        # Zeiten des Originals, nicht der Kopie
    if res is None:
        return _fallback_result(path, info, _violation_reason(run, info))
    if isinstance(res.get("magic"), list):
        res["magic"] = tuple(res["magic"])
    prev = run.jobdir / "preview.png"
    info["preview_png"] = str(prev) if prev.exists() else None
    ptxt = run.jobdir / "preview.txt"
    info["preview_text"] = ptxt.read_text(encoding="utf-8", errors="replace")[:20000] if ptxt.exists() else None
    res["sandbox"] = info
    log(f"Sandbox beendet: {run.seconds}s · Integrität {run.integrity} · "
        f"Spitze {((run.peak_memory or 0) >> 20)} MiB", "OK")
    return res


def remap_paths(json_text, staged):
    """Pfade der Kopien im Job-Ordner im Ergebnis-JSON durch die Originalpfade ersetzen."""
    for orig, copy in staged.items():
        json_text = json_text.replace(json.dumps(copy)[1:-1], json.dumps(orig)[1:-1])
    return json_text


def _run_best(args, stage, progress_fn, timeout, log):
    """
    Bevorzugt AppContainer (kein Netz); fällt bei Einrichtungs-/Startproblemen auf den
    Low-IL-Worker zurück. → (SandboxRun, Netzwerk-Status-Text)
    """
    from config.settings import SANDBOX_BLOCK_NETWORK, DATA_DIR
    from core import appcontainer as ac
    reason = "disabled in settings" if not SANDBOX_BLOCK_NETWORK else "AppContainer not supported"
    if SANDBOX_BLOCK_NETWORK and ac.supported():
        try:
            _sid, notes = ac.ensure_access(jobs_root(), DATA_DIR / "appcontainer.json")
            for n in notes:
                log(f"AppContainer: {n}", "WARN")
            log("Starte isolierten Analyse-Prozess (AppContainer ohne Netzwerk · Job Object)", "INFO")
            run = run_worker(args, progress_fn=progress_fn, timeout=timeout, appcontainer=True, stage=stage)
            started = any((run.jobdir / n).exists() for n in
                          ("progress.jsonl", "result.json", "diff.json", "selftest.json", "mailbox.json", "worker.log"))
            if started or run.timed_out:
                return run, "blocked (AppContainer, no capabilities)"
            reason = f"worker did not start in AppContainer (exit 0x{(run.exit_code or 0):08X})"
        except OSError as e:
            reason = f"AppContainer setup failed: {e}"
        log(f"{reason} – falling back to Low-IL worker (network NOT blocked)", "WARN")
    else:
        log("Starte isolierten Analyse-Prozess (Low Integrity · Job Object)", "INFO")
    return run_worker(args, progress_fn=progress_fn, timeout=timeout), f"not blocked ({reason})"


def diff_isolated(a, b, timeout=WALL_TIMEOUT):
    """Inhaltsvergleich zweier Dateien im Sandbox-Worker. → (diff-dict, heatmap_png_pfad | None)"""
    a, b = str(Path(a).resolve()), str(Path(b).resolve())
    if not available():
        import tempfile
        from engines.diff import content_diff
        png = Path(tempfile.mkdtemp(prefix="sentinel_diff_")) / "diff.png"
        res = content_diff(a, b, out_png=str(png))
        res["sandbox"] = {"isolated": False, "reason": "platform"}
        return res, (str(png) if png.exists() else None)
    run, net = _run_best([DIFF_FLAG, a, b], [1, 2], None, timeout, lambda m, l="INFO": None)
    out = run.jobdir / "diff.json"
    if run.timed_out or not out.exists():
        return {"error": _violation_reason(run, {"wall_limit_s": timeout}),
                "sandbox": {"isolated": True, "violation": True}}, None
    res = json.loads(out.read_text(encoding="utf-8"))
    res["sandbox"] = {"isolated": True, "integrity": run.integrity, "seconds": run.seconds, "network": net}
    png = run.jobdir / "diff.png"
    return res, (str(png) if png.exists() else None)


def mailbox_isolated(path, dest_root, timeout=1800):
    """
    Postfach in .eml-Dateien zerlegen (Low-IL-Worker; das Zerlegen parst nicht vertrauenswürdigen
    Inhalt). Die Mails werden danach nach dest_root/<name>_<zeit>/ verschoben (bleiben erhalten).
    → (index-dict, ordner_der_mails)
    """
    import datetime as _dt
    path = str(Path(path).resolve())
    target = Path(dest_root) / f"{Path(path).stem[:40]}_{_dt.datetime.now():%Y%m%d_%H%M%S}"
    if not available():
        import tempfile
        from engines.mailbox_split import split
        tmp = Path(tempfile.mkdtemp(prefix="sentinel_mbox_"))
        res = split(path, tmp / "mails")
        res["sandbox"] = {"isolated": False, "reason": "platform"}
        src = tmp / "mails"
    else:
        # wie jede Analyse: bevorzugt AppContainer ohne Netz (Postfach wird in den Job-Ordner kopiert),
        # sonst Low-IL-Worker
        run, _net = _run_best([MAILBOX_FLAG, path], [1], None, timeout, lambda m, l="INFO": None)
        out = run.jobdir / "mailbox.json"
        if run.timed_out or not out.exists():
            return {"messages": [], "errors": [_violation_reason(run, {"wall_limit_s": timeout})
                                               + _worker_log_tail(run.jobdir)]}, None
        res = json.loads(out.read_text(encoding="utf-8"))
        res["sandbox"] = {"isolated": True, "integrity": run.integrity}
        src = run.jobdir / "mails"
    target.parent.mkdir(parents=True, exist_ok=True)
    if src.exists():
        shutil.move(str(src), str(target))
    return res, (str(target) if target.exists() else None)


def _worker_log_tail(jobdir, n=600):
    """Letzte Zeilen des Worker-Logs – damit ein Fehlschlag in der Sandbox einen Grund nennt."""
    try:
        tail = (Path(jobdir) / "worker.log").read_text(encoding="utf-8", errors="replace").strip()[-n:]
    except OSError:
        return ""
    return f"\n{tail}" if tail else ""


def _violation_reason(run, info):
    if run.timed_out:
        return f"Zeitlimit ({info['wall_limit_s']} s) überschritten – Analyse zwangsbeendet"
    peak = run.peak_memory or 0
    if peak >= MEMORY_LIMIT * 0.95:
        return f"Speicherlimit ({MEMORY_LIMIT >> 30} GiB) erreicht – Bombe/Speicherangriff?"
    if run.exit_code in (0xDEAD,):
        return "Worker wurde beendet"
    return f"Analyse-Prozess abgestürzt (Code 0x{(run.exit_code or 0):08X}) – präparierte Datei?"


def _fallback_result(path, info, reason):
    """Minimalbericht aus sicheren Operationen (Hash + Kopfbytes), wenn der Worker scheitert."""
    import datetime
    from core.utils import all_hashes, file_stat_snapshot
    from core.filetype import identify
    from engines.score_engine import ScoreEngine
    finding = {"code": "sandbox_violation", "desc": reason, "severity": "CRIT", "source": "sandbox"}
    score = ScoreEngine().score_findings([finding])
    ft = identify(path, deep=False)
    return {
        "ok": True, "kind": ft["category"], "file": file_stat_snapshot(path), "hashes": all_hashes(path),
        "magic": (ft["category"], ft["subtype"], ""), "filetype": ft,
        "report": {"sandbox_error": reason}, "score": score,
        "threat": {"verdict": score["level"], "score": score["score"], "critical": 1, "warnings": 0,
                   "families": ["Sandbox"], "headline": reason},
        "error": None, "timestamp": datetime.datetime.now().isoformat(sep=" ", timespec="seconds"),
        "sandbox": dict(info or {"isolated": True}, violation=reason),
    }
