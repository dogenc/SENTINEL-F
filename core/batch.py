"""
Stapel-/Ordneranalyse.

Sammelt Dateien (Ordner rekursiv oder eine Liste) und analysiert sie parallel.
Jede Datei läuft wie bei der Einzelanalyse in ihrem EIGENEN Sandbox-Worker
(core.sandbox.analyze_isolated); die Threads hier warten nur auf diese Prozesse.
Die App selbst liest die Dateien nicht – abgesehen vom Verzeichnis-Listing.
"""
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DEFAULT_MAX_FILES = 5000
# Ordner, die bei einem Laufwerks-Scan nur Lärm erzeugen
SKIP_DIRS = {".git", "__pycache__", "node_modules", "$Recycle.Bin", "System Volume Information"}


def default_workers():
    return max(1, min(4, (os.cpu_count() or 2) // 2))


def collect_files(paths, recursive=True, max_files=DEFAULT_MAX_FILES, skip_dirs=SKIP_DIRS):
    """
    Dateien aus Ordnern und Einzelpfaden einsammeln (ohne Symlinks, ohne Duplikate).
    → (dateien, abgeschnitten: bool)
    """
    out, seen = [], set()

    def add(p):
        key = os.path.normcase(str(p))
        if key in seen:
            return True
        seen.add(key)
        out.append(str(p))
        return len(out) < max_files

    for raw in paths:
        p = Path(raw)
        if p.is_symlink():
            continue
        if p.is_file():
            if not add(p.resolve()):
                return out, True
        elif p.is_dir():
            if recursive:
                walker = os.walk(p, followlinks=False)
            else:
                walker = [(str(p), [], [e.name for e in os.scandir(p) if e.is_file(follow_symlinks=False)])]
            for dirpath, dirnames, filenames in walker:
                dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs)
                for name in sorted(filenames):
                    f = Path(dirpath) / name
                    if f.is_symlink() or not f.is_file():
                        continue
                    if not add(f.resolve()):
                        return out, True
    return out, False


class BatchRunner:
    """
    Führt analyze_fn(path, progress_fn=None, log_fn=log_fn) für viele Dateien parallel aus.

    on_result(path, result) wird aus Worker-Threads aufgerufen (für Qt per Signal weiterreichen).
    on_finished(stats) genau einmal am Ende, auch nach cancel().
    """

    def __init__(self, files, analyze_fn, workers=None, on_result=None, on_finished=None, log_fn=None):
        self.files = list(files)
        self.analyze_fn = analyze_fn
        self.workers = max(1, int(workers or default_workers()))
        self.on_result = on_result or (lambda p, r: None)
        self.on_finished = on_finished or (lambda s: None)
        self.log = log_fn or (lambda m, l="INFO": None)
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self.stats = {"total": len(self.files), "done": 0, "errors": 0, "cancelled": False}
        self._thread = None

    @property
    def cancelled(self):
        return self._cancel.is_set()

    def cancel(self):
        self._cancel.set()

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="sentinel-batch")
        self._thread.start()
        return self

    def wait(self, timeout=None):
        if self._thread:
            self._thread.join(timeout)

    def _one(self, path):
        if self._cancel.is_set():
            return
        try:
            res = self.analyze_fn(path, progress_fn=None, log_fn=self.log)
        except Exception as e:                       # Worker darf den Stapel nie abbrechen
            res = {"ok": False, "error": f"{type(e).__name__}: {e}", "file": {"path": path,
                                                                              "name": Path(path).name}}
        with self._lock:
            self.stats["done"] += 1
            if not res.get("ok"):
                self.stats["errors"] += 1
        self.on_result(path, res)

    def _run(self):
        try:
            with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="sentinel-batch") as ex:
                for f in self.files:
                    ex.submit(self._one, f)
        finally:
            self.stats["cancelled"] = self._cancel.is_set()
            self.on_finished(dict(self.stats))
