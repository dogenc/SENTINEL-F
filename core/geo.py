"""
GPS-Bewegungsprofil: Foto-Standorte eines Falls als Route mit Plausibilitätsprüfung.

Jedes Foto mit GPS-EXIF und Aufnahmezeit wird ein Punkt; aufeinanderfolgende
Punkte bilden Etappen (Luftlinie, Zeit, Geschwindigkeit). Unmögliche Etappen
deuten auf gefälschte Koordinaten oder Zeitstempel hin.
"""
import math
import re

SPEED_IMPOSSIBLE = 1100.0     # km/h – schneller als ein Linienflug
SPEED_FLIGHT = 300.0          # km/h – nur per Flugzeug plausibel
SAME_TIME_KM = 2.0            # gleiche Sekunde, aber weiter entfernt → unmöglich


def _dms(s):
    if s is None:
        return None
    nums = re.findall(r"[-+]?\d*\.?\d+", str(s))
    if len(nums) >= 6 and "/" in str(s):           # ((52,1),(31,1),(1234,100)) – rationale Zahlen
        vals = [float(nums[i]) / (float(nums[i + 1]) or 1) for i in range(0, 6, 2)]
        return vals[0] + vals[1] / 60 + vals[2] / 3600
    if len(nums) >= 3:
        d, m, sec = (float(x) for x in nums[:3])
        return d + m / 60 + sec / 3600
    if len(nums) == 1:
        return float(nums[0])
    return None


def gps_from_result(result):
    """→ (lat, lon) oder None – aus den EXIF-Metadaten der Bild-Engine."""
    meta = ((result.get("report") or {}).get("metadata") or {})
    lat = _dms(meta.get("GPS.GPSLatitude") or meta.get("piexif.GPS.GPSLatitude"))
    lon = _dms(meta.get("GPS.GPSLongitude") or meta.get("piexif.GPS.GPSLongitude"))
    if lat is None or lon is None:
        return None
    lat_ref = str(meta.get("GPS.GPSLatitudeRef") or meta.get("piexif.GPS.GPSLatitudeRef") or "N").upper()
    lon_ref = str(meta.get("GPS.GPSLongitudeRef") or meta.get("piexif.GPS.GPSLongitudeRef") or "E").upper()
    lat = -abs(lat) if "S" in lat_ref else lat
    lon = -abs(lon) if "W" in lon_ref else lon
    if not (-90 <= lat <= 90 and -180 <= lon <= 180) or (lat == 0 and lon == 0):
        return None
    return round(lat, 6), round(lon, 6)


def capture_time(result):
    from engines.timeline import parse_ts
    meta = ((result.get("report") or {}).get("metadata") or {})
    for k in ("EXIF.DateTimeOriginal", "EXIF.DateTimeDigitized", "XMP.CreateDate", "EXIF.DateTime"):
        dt, _tz = parse_ts(meta.get(k))
        if dt:
            return dt
    return None


def haversine_km(a, b):
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * math.asin(min(1.0, math.sqrt(h)))


def build_route(points):
    """points: [{id, name, lat, lon, ts(datetime|None)}] → {'points', 'legs', 'anomalies', 'undated'}"""
    dated = sorted((p for p in points if p.get("ts")), key=lambda p: p["ts"])
    undated = [p for p in points if not p.get("ts")]
    legs, anomalies = [], []
    for a, b in zip(dated, dated[1:]):
        km = haversine_km((a["lat"], a["lon"]), (b["lat"], b["lon"]))
        hours = (b["ts"] - a["ts"]).total_seconds() / 3600
        speed = km / hours if hours > 0 else (math.inf if km > SAME_TIME_KM else 0.0)
        leg = {"from": a["name"], "to": b["name"], "from_id": a["id"], "to_id": b["id"], "km": round(km, 2),
               "hours": round(hours, 3), "speed_kmh": None if math.isinf(speed) else round(speed, 1), "flag": None}
        if math.isinf(speed) or speed > SPEED_IMPOSSIBLE:
            leg["flag"] = "impossible"
            anomalies.append({"severity": "WARN", "desc": f"{a['name']} → {b['name']}: {km:,.0f} km in "
                                                         f"{_dur(hours)} ({'∞' if math.isinf(speed) else f'{speed:,.0f}'} km/h) "
                                                         "– physically impossible, GPS or time was altered"})
        elif speed > SPEED_FLIGHT:
            leg["flag"] = "flight"
            anomalies.append({"severity": "INFO", "desc": f"{a['name']} → {b['name']}: {km:,.0f} km in {_dur(hours)} "
                                                         f"({speed:,.0f} km/h) – only plausible by plane"})
        legs.append(leg)
    for p in dated:
        p["ts"] = p["ts"].isoformat(sep=" ", timespec="seconds")
    return {"points": dated, "legs": legs, "anomalies": anomalies, "undated": undated,
            "total_km": round(sum(l["km"] for l in legs), 1)}


def _dur(hours):
    if hours < 1 / 60:
        return f"{hours * 3600:.0f} s"
    if hours < 1:
        return f"{hours * 60:.0f} min"
    return f"{hours:.1f} h"


def route_from_db(db, case_id=None):
    pts, seen = [], set()
    for r in db.list_analyses(case_id=case_id, limit=5000):
        if r["kind"] != "image" or r["sha256"] in seen:
            continue
        res = db.get_result(r["id"]) or {}
        g = gps_from_result(res)
        if not g:
            continue
        seen.add(r["sha256"])
        pts.append({"id": r["id"], "name": r["name"], "lat": g[0], "lon": g[1], "ts": capture_time(res)})
    return build_route(pts)
