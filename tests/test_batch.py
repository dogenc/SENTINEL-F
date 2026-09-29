"""Ordner-/Stapelanalyse (core/batch.py) und die BATCH-SCAN-Ansicht."""
import csv
import os
import threading
import zipfile

import pytest

from core.batch import collect_files, BatchRunner
from engines import run_forensic


def _tree(tmp_path):
    (tmp_path / "sub" / "deep").mkdir(parents=True)
    (tmp_path / ".git").mkdir()
    (tmp_path / "a.txt").write_text("hallo")
    (tmp_path / "sub" / "b.txt").write_text("welt")
    (tmp_path / "sub" / "deep" / "c.txt").write_text("tief")
    (tmp_path / ".git" / "HEAD").write_text("ref")
    return tmp_path


def test_collect_recursive_skips_noise_dirs(tmp_path):
    files, cut = collect_files([_tree(tmp_path)])
    names = sorted(os.path.basename(f) for f in files)
    assert names == ["a.txt", "b.txt", "c.txt"] and not cut


def test_collect_flat_and_dedupe(tmp_path):
    root = _tree(tmp_path)
    files, _ = collect_files([root], recursive=False)
    assert [os.path.basename(f) for f in files] == ["a.txt"]
    files, _ = collect_files([root / "a.txt", root / "a.txt", root / "sub"], recursive=False)
    assert sorted(os.path.basename(f) for f in files) == ["a.txt", "b.txt"]


def test_collect_limit(tmp_path):
    for i in range(10):
        (tmp_path / f"f{i}.txt").write_text(str(i))
    files, cut = collect_files([tmp_path], max_files=4)
    assert len(files) == 4 and cut


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="keine Symlinks")
def test_collect_ignores_symlinks(tmp_path):
    (tmp_path / "real.txt").write_text("x")
    try:
        os.symlink(tmp_path / "real.txt", tmp_path / "link.txt")
    except OSError:
        pytest.skip("Symlinks nicht erlaubt")
    files, _ = collect_files([tmp_path])
    assert [os.path.basename(f) for f in files] == ["real.txt"]


def test_runner_reports_every_file_and_survives_errors(tmp_path):
    files = [str(tmp_path / f"{i}.txt") for i in range(6)]

    def fake(path, progress_fn=None, log_fn=None):
        if path.endswith("3.txt"):
            raise RuntimeError("kaputt")
        return {"ok": True, "file": {"path": path}}

    got, done = [], []
    r = BatchRunner(files, fake, workers=3, on_result=lambda p, res: got.append((p, res["ok"])),
                    on_finished=done.append).start()
    r.wait(10)
    assert sorted(p for p, _ in got) == sorted(files)
    assert sum(1 for _, ok in got if not ok) == 1
    assert done == [{"total": 6, "done": 6, "errors": 1, "cancelled": False}]


def test_runner_cancel_stops_queue(tmp_path):
    gate = threading.Event()
    files = [str(i) for i in range(20)]
    seen = []

    def slow(path, progress_fn=None, log_fn=None):
        gate.wait(5)
        return {"ok": True}

    done = []
    r = BatchRunner(files, slow, workers=2, on_result=lambda p, res: seen.append(p),
                    on_finished=done.append).start()
    r.cancel()
    gate.set()
    r.wait(10)
    assert len(seen) <= 2
    assert done and done[0]["cancelled"]


@pytest.fixture
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def _run_view(view, paths, qapp):
    view.start_scan([str(p) for p in paths])
    assert view.busy
    view._runner.wait(60)
    qapp.processEvents()
    assert not view.busy


def test_batch_view_scans_folder_into_new_case(tmp_path, qapp):
    from core.history import HistoryDB
    from gui.history_view import HistoryView
    from gui.batch_view import BatchView

    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "ok.txt").write_text("nur text")
    (scan / "kopie.txt").write_text("nur text")
    with zipfile.ZipFile(scan / "bomb.zip", "w", zipfile.ZIP_BZIP2) as z:
        z.writestr("a.bin", b"\x00" * (16 << 20))
    (scan / "=cmd.txt").write_text("formel im namen")

    db = HistoryDB(tmp_path / "h.db")
    hist = HistoryView(db=db)
    view = BatchView(analyze_fn=run_forensic, history=hist)
    _run_view(view, [scan], qapp)

    assert view.table.rowCount() == 4
    assert view.cards["done"].text() == "4"
    assert view.cards["dupes"].text() == "1"
    assert int(view.cards["critical"].text()) >= 1
    # höchstes Risiko steht oben
    assert view.table.item(0, 0).text() == "bomb.zip"

    cases = db.list_cases()
    assert len(cases) == 1 and cases[0]["analyses"] == 4 and cases[0]["name"].startswith("Scan · scan")
    assert hist.active_case_id() == cases[0]["id"]

    opened = []
    view.openRequested.connect(opened.append)
    view._open_row(view.table.model().index(0, 0))
    assert db.get_result(opened[0])["file"]["name"] == "bomb.zip"

    view.chk_flagged.setChecked(True)
    visible = [r for r in range(view.table.rowCount()) if not view.table.isRowHidden(r)]
    assert [view.table.item(r, 0).text() for r in visible] == ["bomb.zip"]

    out = tmp_path / "r.csv"
    view.export_csv(out)
    rows = list(csv.reader(out.open(encoding="utf-8-sig"), delimiter=";"))
    assert rows[0][0] == "path" and len(rows) == 5
    assert all(not c.startswith("=") for r in rows for c in r)

    # zweiter Scan: alles schon bekannt
    view.chk_new_case.setChecked(False)
    _run_view(view, [scan], qapp)
    assert view.cards["known"].text() == "3"      # die Kopie zählt als Duplikat


def test_main_window_routes_folders_to_batch(tmp_path, qapp, monkeypatch):
    import core.history as h
    monkeypatch.setattr(h, "_default", h.HistoryDB(tmp_path / "h.db"))
    from gui.main_window import MainWindow
    w = MainWindow()
    started = []
    monkeypatch.setattr(w.batch, "start_scan", started.append)
    w._load_file(str(tmp_path))
    assert started == [[str(tmp_path)]] and w.stack.currentWidget() is w.batch
