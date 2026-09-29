"""GPS-Bewegungsprofil (core/geo.py): Koordinaten, Route, unmögliche Etappen, Globus-Übergabe."""
import datetime
import os

import pytest

from core.geo import build_route, haversine_km, route_from_db, gps_from_result
from core.history import HistoryDB
from engines import run_forensic

BERLIN, MUNICH, NYC = (52.52, 13.405), (48.137, 11.575), (40.713, -74.006)


def _photo(path, lat, lon, when=None):
    import piexif
    from PIL import Image

    def dms(v):
        v = abs(v)
        d = int(v)
        m = int((v - d) * 60)
        s = round(((v - d) * 60 - m) * 60 * 100)
        return ((d, 1), (m, 1), (s, 100))
    gps = {piexif.GPSIFD.GPSLatitudeRef: b"N" if lat >= 0 else b"S", piexif.GPSIFD.GPSLatitude: dms(lat),
           piexif.GPSIFD.GPSLongitudeRef: b"E" if lon >= 0 else b"W", piexif.GPSIFD.GPSLongitude: dms(lon)}
    ex = {"GPS": gps, "Exif": {}}
    if when:
        ex["Exif"][piexif.ExifIFD.DateTimeOriginal] = when.encode()
    Image.new("RGB", (48, 48), (120, 90, 40)).save(path, exif=piexif.dump(ex))
    return path


def test_haversine():
    assert 500 < haversine_km(BERLIN, MUNICH) < 510
    assert 6300 < haversine_km(BERLIN, NYC) < 6400


def test_route_flags():
    t = datetime.datetime(2024, 5, 1, 10)
    pts = [{"id": 1, "name": "a.jpg", "lat": BERLIN[0], "lon": BERLIN[1], "ts": t},
           {"id": 2, "name": "b.jpg", "lat": MUNICH[0], "lon": MUNICH[1], "ts": t + datetime.timedelta(hours=5)},
           {"id": 3, "name": "c.jpg", "lat": NYC[0], "lon": NYC[1], "ts": t + datetime.timedelta(hours=6)},
           {"id": 4, "name": "d.jpg", "lat": BERLIN[0], "lon": BERLIN[1], "ts": t + datetime.timedelta(hours=14)},
           {"id": 5, "name": "e.jpg", "lat": 1.0, "lon": 1.0, "ts": None}]
    r = build_route(pts)
    assert [l["flag"] for l in r["legs"]] == [None, "impossible", "flight"]
    assert r["legs"][0]["speed_kmh"] == pytest.approx(101, abs=2)
    assert [a["severity"] for a in r["anomalies"]] == ["WARN", "INFO"]
    assert "physically impossible" in r["anomalies"][0]["desc"]
    assert [p["name"] for p in r["undated"]] == ["e.jpg"]
    assert r["total_km"] > 12000


def test_same_second_two_places_is_impossible():
    t = datetime.datetime(2024, 5, 1, 10)
    r = build_route([{"id": 1, "name": "x", "lat": 52.5, "lon": 13.4, "ts": t},
                     {"id": 2, "name": "y", "lat": 48.1, "lon": 11.6, "ts": t}])
    assert r["legs"][0]["flag"] == "impossible" and r["legs"][0]["speed_kmh"] is None


def test_route_from_history(tmp_path):
    db = HistoryDB(tmp_path / "h.db")
    cid = db.create_case("Reise")
    shots = [("1_berlin.jpg", BERLIN, "2024:05:01 10:00:00"), ("2_muenchen.jpg", MUNICH, "2024:05:01 16:00:00"),
             ("3_newyork.jpg", NYC, "2024:05:01 17:00:00"), ("4_ohne_zeit.jpg", BERLIN, None)]
    for name, (la, lo), when in shots:
        res = run_forensic(str(_photo(tmp_path / name, la, lo, when)))
        db.record(res, case_id=cid)
    assert gps_from_result(res) == pytest.approx(BERLIN, abs=1e-3)
    r = route_from_db(db, case_id=cid)
    assert [p["name"] for p in r["points"]] == ["1_berlin.jpg", "2_muenchen.jpg", "3_newyork.jpg"]
    assert r["legs"][1]["flag"] == "impossible" and len(r["undated"]) == 1


def test_route_dialog_and_globe_signal(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    QtWidgets = pytest.importorskip("PyQt6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])  # noqa: F841 – Referenz halten
    from gui.history_view import HistoryView
    db = HistoryDB(tmp_path / "h.db")
    for name, (la, lo), when in (("a.jpg", BERLIN, "2024:05:01 10:00:00"), ("b.jpg", NYC, "2024:05:01 11:00:00")):
        db.record(run_forensic(str(_photo(tmp_path / name, la, lo, when))))
    hv = HistoryView(db=db)
    dlg = hv.show_route(exec_dialog=False)
    assert dlg.table.rowCount() == 1 and dlg.table.item(0, 4).text() == "IMPOSSIBLE"
    assert "physically impossible" in dlg.lbl.text()
    got = []
    hv.routeOnGlobe.connect(got.append)
    dlg.btn_globe.click()
    assert got and len(got[0]["points"]) == 2
