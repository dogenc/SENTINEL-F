"""
Hash-Abfrage bei Threat-Intel-Diensten – opt-in, es verlassen NUR Hashes den Rechner.

* CIRCL hashlookup  – ohne Schlüssel; kennt Millionen BEKANNT GUTER Dateien (NSRL u. a.)
* VirusTotal (v3)   – mit eigenem API-Schlüssel; Erkennungen der AV-Engines
* MalwareBazaar     – mit abuse.ch Auth-Key; bekannte Malware-Samples + Familie/Tags

Die Dateien selbst werden nie hochgeladen. Ergebnisse werden im Verlauf
zwischengespeichert (Rate-Limits, z. B. VirusTotal free: 4/min).
"""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

CIRCL_URL = "https://hashlookup.circl.lu/lookup/sha256/{h}"
VT_URL = "https://www.virustotal.com/api/v3/files/{h}"
MB_URL = "https://mb-api.abuse.ch/api/v1/"
TIMEOUT = 12
CACHE_MAX_AGE = 7 * 86400


def settings():
    from config import settings as cs
    ls = getattr(cs, "_ls", None)
    return {
        "enabled": bool(getattr(cs, "HASH_LOOKUP_ENABLED", False)),
        "vt_key": os.environ.get("DGKN_VT_API_KEY") or getattr(ls, "VT_API_KEY", ""),
        "mb_key": os.environ.get("DGKN_MB_AUTH_KEY") or getattr(ls, "MB_AUTH_KEY", ""),
    }


def _get(url, headers=None, data=None):
    req = urllib.request.Request(url, data=data, headers=dict(headers or {}, **{"User-Agent": "SENTINEL-F"}))
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, json.loads(r.read(2 << 20).decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read(1 << 16).decode("utf-8", "replace") or "{}")
        except ValueError:
            body = {}
        return e.code, body


def circl(sha256):
    code, body = _get(CIRCL_URL.format(h=sha256))
    if code == 404:
        return {"status": "unknown", "detail": "not in the known-files database"}
    if code != 200:
        return {"status": "error", "detail": f"HTTP {code}"}
    src = body.get("source") or body.get("db") or "hashlookup"
    name = body.get("FileName") or body.get("filename") or ""
    prod = body.get("ProductName") or (body.get("KnownMalicious") and "KNOWN MALICIOUS") or ""
    if body.get("KnownMalicious"):
        return {"status": "malicious", "detail": f"CIRCL flags it as known malicious ({body['KnownMalicious']})"}
    return {"status": "known_good", "detail": f"known file {name} {prod} (source {src})".strip(),
            "link": f"https://hashlookup.circl.lu/lookup/sha256/{sha256}"}


def virustotal(sha256, key):
    code, body = _get(VT_URL.format(h=sha256), headers={"x-apikey": key})
    link = f"https://www.virustotal.com/gui/file/{sha256}"
    if code == 404:
        return {"status": "unknown", "detail": "not known to VirusTotal (never uploaded)", "link": link}
    if code == 429:
        return {"status": "error", "detail": "rate limit reached – try again in a minute"}
    if code != 200:
        return {"status": "error", "detail": f"HTTP {code}: {(body.get('error') or {}).get('message', '')}"[:200]}
    attr = (body.get("data") or {}).get("attributes") or {}
    st = attr.get("last_analysis_stats") or {}
    mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
    total = sum(v for v in st.values() if isinstance(v, int))
    label = ((attr.get("popular_threat_classification") or {}).get("suggested_threat_label")) or ""
    status = "malicious" if mal >= 3 else "suspicious" if mal + sus >= 1 else "clean"
    return {"status": status, "detections": f"{mal}/{total}", "link": link,
            "detail": f"{mal} of {total} engines detect it" + (f" · {label}" if label else "")
                      + (f" · first seen {time.strftime('%Y-%m-%d', time.gmtime(attr['first_submission_date']))}"
                         if attr.get("first_submission_date") else ""),
            "names": (attr.get("names") or [])[:5]}


def malwarebazaar(sha256, key):
    data = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
    code, body = _get(MB_URL, headers={"Auth-Key": key}, data=data)
    if code != 200:
        return {"status": "error", "detail": f"HTTP {code}"}
    qs = body.get("query_status")
    if qs in ("hash_not_found", "no_results"):
        return {"status": "unknown", "detail": "not a known MalwareBazaar sample"}
    if qs != "ok":
        return {"status": "error", "detail": str(qs)}
    d = (body.get("data") or [{}])[0]
    return {"status": "malicious", "detail": f"known sample · family {d.get('signature') or '?'} · tags "
                                             f"{', '.join(d.get('tags') or []) or '—'} · first seen {d.get('first_seen')}",
            "link": f"https://bazaar.abuse.ch/sample/{sha256}/", "family": d.get("signature")}


def lookup(sha256, providers=None, cfg=None):
    """→ {provider: result}. Nur konfigurierte Dienste; Fehler je Dienst getrennt."""
    cfg = cfg or settings()
    sha256 = (sha256 or "").lower()
    out = {}
    wanted = providers or ("circl", "virustotal", "malwarebazaar")
    for p in wanted:
        try:
            if p == "circl":
                out[p] = circl(sha256)
            elif p == "virustotal":
                out[p] = virustotal(sha256, cfg["vt_key"]) if cfg.get("vt_key") else \
                    {"status": "skipped", "detail": "no VirusTotal API key configured"}
            elif p == "malwarebazaar":
                out[p] = malwarebazaar(sha256, cfg["mb_key"]) if cfg.get("mb_key") else \
                    {"status": "skipped", "detail": "no MalwareBazaar Auth-Key configured"}
        except (OSError, ValueError) as e:
            out[p] = {"status": "error", "detail": f"{type(e).__name__}: {e}"[:200]}
    return out


def summary(intel):
    """Kurzurteil über alle Dienste."""
    st = [r.get("status") for r in (intel or {}).values()]
    if "malicious" in st:
        return "malicious"
    if "suspicious" in st:
        return "suspicious"
    if "known_good" in st:
        return "known_good"
    if "clean" in st:
        return "clean"
    return "unknown"


# ── Zwischenspeicher im Verlauf ─────────────────────────────────────────────
def cached_lookup(db, sha256, force=False, cfg=None, providers=None):
    with db._lock, db._connect() as con:
        con.execute("CREATE TABLE IF NOT EXISTS intel_cache (sha256 TEXT PRIMARY KEY, fetched REAL, data TEXT)")
        row = con.execute("SELECT fetched, data FROM intel_cache WHERE sha256 = ?", (sha256.lower(),)).fetchone()
    if row and not force and time.time() - row[0] < CACHE_MAX_AGE:
        data = json.loads(row[1])
        data["_cached"] = True
        return data
    data = lookup(sha256, providers=providers, cfg=cfg)
    data["_fetched"] = time.strftime("%Y-%m-%d %H:%M:%S")
    if all(r.get("status") != "error" for k, r in data.items() if not k.startswith("_")):
        with db._lock, db._connect() as con:
            con.execute("INSERT OR REPLACE INTO intel_cache VALUES (?,?,?)",
                        (sha256.lower(), time.time(), json.dumps(data)))
    return data
