"""
Watch-Folder: überwacht Ordner (z. B. Downloads) und prüft jede neue Datei.

Bewusst per Polling statt über Dateisystem-Events: funktioniert identisch auf
lokalen Platten, USB-Sticks und Netzlaufwerken und braucht keine Abhängigkeit.

Ablauf je Datei:
  1. neu oder verändert (Größe/mtime) → "pending"
  2. beim nächsten Durchlauf unverändert → gilt als fertig geschrieben
  3. Analyse (analyze_fn, standardmäßig im Sandbox-Worker) in EINEM Hintergrund-Thread
Halbfertige Downloads (.crdownload, .part …) werden ignoriert; Dateien, die beim
Start schon da waren, ebenfalls (nur NEUE Dateien sind interessant).
"""
import os
import queue
import threading
from pathlib import Path

# Temporäre Dateien von Browsern / Download-Managern / Office
PARTIAL_SUFFIXES = (".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload",
                    ".!ut", ".aria2", ".filepart")
PARTIAL_PREFIXES = ("~$", ".~lock")
MAX_QUEUE = 500


def _ignored(name):
    low = name.lower()
    return low.endswith(PARTIAL_SUFFIXES) or low.startswith(PARTIAL_PREFIXES) or low in ("desktop.ini", "thumbs.db")


def default_download_dir():
    p = Path.home() / "Downloads"
    return str(p) if p.is_dir() else str(Path.home())


class FolderWatcher:
    """
    paths:       zu überwachende Ordner
    analyze_fn:  wie engines.run_forensic / core.sandbox.analyze_isolated
    on_result:   (path, result) – aus dem Analyse-Thread aufgerufen
    on_event:    (kind, path) – "queued" | "skipped" (optional, für die Anzeige)
    """

    def __init__(self, paths, analyze_fn, on_result=None, on_event=None, interval=2.0,
                 recursive=False, log_fn=None):
        self.paths = [str(Path(p)) for p in paths]
        self.analyze_fn = analyze_fn
        self.on_result = on_result or (lambda p, r: None)
        self.on_event = on_event or (lambda k, p: None)
        self.interval = float(interval)
        self.recursive = recursive
        self.log = log_fn or (lambda m, l="INFO": None)
        self._known = {}         # path → (size, mtime) bereits erledigt/Ausgangsbestand
        self._pending = {}       # path → (size, mtime) wartet auf stabile Größe
        self._queue = queue.Queue(MAX_QUEUE)
        self._stop = threading.Event()
        self._threads = []
        self.analysed = 0

    # ── Dateisystem ───────────────────────────────────────────────────
    def _scan(self):
        found = {}
        for root in self.paths:
            if not os.path.isdir(root):
                continue
            stack = [root]
            while stack:
                d = stack.pop()
                try:
                    with os.scandir(d) as it:
                        for e in it:
                            try:
                                if e.is_symlink():
                                    continue
                                if e.is_dir():
                                    if self.recursive:
                                        stack.append(e.path)
                                    continue
                                if not e.is_file() or _ignored(e.name):
                                    continue
                                st = e.stat()
                                found[os.path.normcase(e.path)] = (e.path, (st.st_size, st.st_mtime_ns))
                            except OSError:
                                continue
                except OSError:
                    continue
        return found

    def prime(self):
        """Ausgangsbestand merken – vorhandene Dateien werden nicht analysiert."""
        self._known = {k: sig for k, (_, sig) in self._scan().items()}
        self._pending.clear()

    def poll_once(self):
        """Ein Durchlauf; liefert die Pfade, die jetzt zur Analyse eingereiht wurden."""
        ready = []
        current = self._scan()
        for key, (path, sig) in current.items():
            if self._known.get(key) == sig:
                continue
            if self._pending.get(key) == sig:      # seit dem letzten Durchlauf unverändert
                self._pending.pop(key, None)
                self._known[key] = sig
                if sig[0] == 0:                    # leere Platzhalter-Dateien überspringen
                    continue
                ready.append(path)
            else:
                self._pending[key] = sig
        # gelöschte Dateien vergessen, damit ein erneuter Download wieder geprüft wird
        for key in list(self._known):
            if key not in current:
                del self._known[key]
        for key in list(self._pending):
            if key not in current:
                del self._pending[key]
        for p in ready:
            try:
                self._queue.put_nowait(p)
                self.on_event("queued", p)
            except queue.Full:
                self.on_event("skipped", p)
                self.log(f"Watch: queue full – skipped {Path(p).name}", "WARN")
        return ready

    # ── Threads ───────────────────────────────────────────────────────
    @property
    def running(self):
        return any(t.is_alive() for t in self._threads)

    def start(self):
        if self.running:
            return self
        self._stop.clear()
        self.prime()
        self._threads = [threading.Thread(target=self._poll_loop, daemon=True, name="sentinel-watch-poll"),
                         threading.Thread(target=self._work_loop, daemon=True, name="sentinel-watch-work")]
        for t in self._threads:
            t.start()
        return self

    def stop(self, timeout=5):
        self._stop.set()
        self._queue.put(None)                       # Arbeits-Thread aufwecken
        for t in self._threads:
            t.join(timeout)
        self._threads = []

    def _poll_loop(self):
        while not self._stop.wait(self.interval):
            try:
                self.poll_once()
            except Exception as e:                  # Überwachung darf nie sterben
                self.log(f"Watch: scan error {e}", "WARN")

    def _work_loop(self):
        while not self._stop.is_set():
            path = self._queue.get()
            if path is None or self._stop.is_set():
                break
            if not os.path.isfile(path):            # inzwischen gelöscht/verschoben
                continue
            try:
                res = self.analyze_fn(path, progress_fn=None, log_fn=self.log)
            except Exception as e:
                res = {"ok": False, "error": f"{type(e).__name__}: {e}",
                       "file": {"path": path, "name": Path(path).name}}
            self.analysed += 1
            self.on_result(path, res)
