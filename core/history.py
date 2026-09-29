"""
Analyse-Verlauf & Fälle (lokale SQLite-Datenbank).

Jede abgeschlossene Analyse wird mit Hashes, Score und dem vollständigen
Ergebnis gespeichert. Damit lassen sich:
  * bereits gesehene Dateien am SHA-256 wiedererkennen,
  * Analysen zu Fällen (Cases) bündeln,
  * alle bisher gefundenen IOCs (URLs, IPs, Domains …) durchsuchen,
  * alte Ergebnisse ohne erneute Analyse wieder öffnen.

Die Datenbank liegt NUR in der App (nie im Sandbox-Worker) und enthält keine
Dateiinhalte, nur das Analyseergebnis.
"""
import datetime
import json
import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analyses (
    id          INTEGER PRIMARY KEY,
    case_id     INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    analyzed_at TEXT NOT NULL,
    path        TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL DEFAULT '',
    size        INTEGER,
    kind        TEXT NOT NULL DEFAULT '',
    md5         TEXT NOT NULL DEFAULT '',
    sha1        TEXT NOT NULL DEFAULT '',
    sha256      TEXT NOT NULL DEFAULT '',
    score       INTEGER,
    level       TEXT NOT NULL DEFAULT '',
    headline    TEXT NOT NULL DEFAULT '',
    families    TEXT NOT NULL DEFAULT '[]',
    result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_analyses_sha256 ON analyses(sha256);
CREATE INDEX IF NOT EXISTS ix_analyses_case   ON analyses(case_id);
CREATE TABLE IF NOT EXISTS iocs (
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_iocs_value ON iocs(value COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS fingerprints (
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,          -- tlsh | imphash | rich
    value       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_fp_kind_value ON fingerprints(kind, value);
"""
SCHEMA_VERSION = 3
# Ein Imphash, den mehr als so viele Dateien teilen, ist zu allgemein (Runtime-Stubs)
GENERIC_IMPHASH_LIMIT = 50

# Spalten der Übersicht (ohne das große result_json)
_ROW_COLS = ("a.id, a.case_id, c.name AS case_name, a.analyzed_at, a.path, a.name, a.size, a.kind, "
             "a.md5, a.sha1, a.sha256, a.score, a.level, a.headline, a.families")


def _now():
    return datetime.datetime.now().isoformat(sep=" ", timespec="seconds")


def _json_default(o):
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    if isinstance(o, (set, frozenset)):
        return sorted(o, key=str)
    return str(o)


def _fingerprints(result):
    from engines.similarity import fingerprints
    return fingerprints(result)


LINEAGE_KINDS = ("pdf_id0", "xmp_orig", "xmp_doc", "xmp_inst", "xmp_derived", "xmp_hist", "rsid_root", "rsids")


def _lineage_rows(result):
    """Herkunftsmerkmale (engines/analyzers/lineage.py) als (kind, value)-Zeilen."""
    lin = (((result.get("report") or {}).get("analyzers") or {}).get("lineage") or {})
    rows = []
    for k in LINEAGE_KINDS:
        v = lin.get(k)
        if not v:
            continue
        if k == "rsids":
            rows.append((k, ",".join(v)))
        elif isinstance(v, list):
            rows += [(k, x) for x in v]
        else:
            rows.append((k, str(v)))
    return rows


def extract_iocs(result):
    """(typ, wert)-Paare aus dem Baseline-Analysator; Base64-Blöcke werden übersprungen."""
    from engines.payloads import chain_iocs
    analyzers = ((result.get("report") or {}).get("analyzers") or {})
    iocs = dict((analyzers.get("baseline") or {}).get("iocs") or {})
    for k, vals in chain_iocs(result.get("payloads")).items():      # auch IOCs aus inneren Stufen
        iocs[k] = list(iocs.get(k) or []) + [v for v in vals if v not in (iocs.get(k) or [])]
    pairs, seen = [], set()
    for typ, values in iocs.items():
        if not isinstance(values, list):
            continue
        for v in values:
            if not isinstance(v, str) or not v:
                continue
            key = (typ, v.lower())
            if key not in seen:
                seen.add(key)
                pairs.append((typ, v))
    return pairs


class HistoryDB:
    """Dünne, threadsichere Hülle um die Verlaufsdatenbank."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as con:
            con.executescript(SCHEMA)
            if con.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
                self._backfill_fingerprints(con)
                con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @staticmethod
    def _backfill_fingerprints(con):
        """Ältere Einträge: Fingerabdrücke und Herkunftsmerkmale aus dem gespeicherten Ergebnis nachtragen."""
        from engines.similarity import fingerprints
        marks = ",".join("?" * len(LINEAGE_KINDS))
        have_fp = {r[0] for r in con.execute(
            f"SELECT DISTINCT analysis_id FROM fingerprints WHERE kind NOT IN ({marks})", LINEAGE_KINDS)}
        have_lin = {r[0] for r in con.execute(
            f"SELECT DISTINCT analysis_id FROM fingerprints WHERE kind IN ({marks})", LINEAGE_KINDS)}
        rows = []
        for aid, rj in con.execute("SELECT id, result_json FROM analyses"):
            if aid in have_fp and aid in have_lin:
                continue
            try:
                res = json.loads(rj)
            except ValueError:
                continue
            if aid not in have_fp:
                rows += [(aid, k, v) for k, v in fingerprints(res).items()]
            if aid not in have_lin:
                rows += [(aid, k, v) for k, v in _lineage_rows(res)]
        con.executemany("INSERT INTO fingerprints (analysis_id, kind, value) VALUES (?,?,?)", rows)

    def _connect(self):
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        return con

    def _query(self, sql, args=()):
        with self._lock, self._connect() as con:
            return [dict(r) for r in con.execute(sql, args).fetchall()]

    # ── Analysen ──────────────────────────────────────────────────────
    def record(self, result, case_id=None):
        """Speichert ein erfolgreiches Ergebnis von run_forensic()/analyze_isolated(). → id"""
        fi = result.get("file") or {}
        hs = result.get("hashes") or {}
        sc = result.get("score") or {}
        th = result.get("threat") or {}
        stored = {k: v for k, v in result.items() if k != "history"}
        row = (
            case_id, result.get("timestamp") or _now(), fi.get("path") or "", fi.get("name") or "",
            fi.get("size"), result.get("kind") or "",
            hs.get("md5") or "", hs.get("sha1") or "", (hs.get("sha256") or "").lower(),
            sc.get("score"), sc.get("level") or "", th.get("headline") or "",
            json.dumps(th.get("families") or [], ensure_ascii=False),
            json.dumps(stored, ensure_ascii=False, default=_json_default),
        )
        with self._lock, self._connect() as con:
            cur = con.execute(
                "INSERT INTO analyses (case_id, analyzed_at, path, name, size, kind, md5, sha1, sha256,"
                " score, level, headline, families, result_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
            aid = cur.lastrowid
            con.executemany("INSERT INTO iocs (analysis_id, type, value) VALUES (?,?,?)",
                            [(aid, t, v) for t, v in extract_iocs(result)])
            con.executemany("INSERT INTO fingerprints (analysis_id, kind, value) VALUES (?,?,?)",
                            [(aid, k, v) for k, v in _fingerprints(result).items()] +
                            [(aid, k, v) for k, v in _lineage_rows(result)])
        return aid

    def fingerprints_for(self, analysis_id):
        return {r["kind"]: r["value"] for r in self._query(
            "SELECT kind, value FROM fingerprints WHERE analysis_id = ? AND kind NOT IN "
            "('xmp_derived', 'xmp_hist')", (analysis_id,))}

    def lineage_for(self, analysis_id):
        """Alle Herkunftsmerkmale inkl. Mehrfachwerte → {kind: wert | [werte]}."""
        out = {}
        for r in self._query("SELECT kind, value FROM fingerprints WHERE analysis_id = ? AND kind IN (%s)"
                             % ",".join("?" * len(LINEAGE_KINDS)), (analysis_id, *LINEAGE_KINDS)):
            if r["kind"] in ("xmp_derived", "xmp_hist"):
                out.setdefault(r["kind"], []).append(r["value"])
            elif r["kind"] == "rsids":
                out["rsids"] = r["value"].split(",")
            else:
                out[r["kind"]] = r["value"]
        return out

    def similar(self, analysis_id=None, fp=None, sha256=None, max_distance=None, limit=20, use_prnu=True):
        """
        Ähnliche, aber NICHT identische Dateien (anderer SHA-256):
          * TLSH-Distanz ≤ max_distance (Standard 70)
          * gleicher Imphash (gleiche Import-Tabelle) – außer sehr häufige
          * gleicher Rich-Header-Hash (gleiche Build-Umgebung)
        Liefert Zeilen der Übersicht + 'match' (Liste der Gründe) + 'distance'.
        """
        from engines.similarity import tlsh_diff, SIMILAR_MAX
        max_distance = SIMILAR_MAX if max_distance is None else max_distance
        if analysis_id is not None:
            fp = self.fingerprints_for(analysis_id)
            if sha256 is None:
                r = self._query("SELECT sha256 FROM analyses WHERE id = ?", (analysis_id,))
                sha256 = r[0]["sha256"] if r else None
        fp = fp or {}
        if not fp:
            return []
        hits = {}                           # analysis_id → {"match": [...], "distance": d}

        def hit(aid, reason, dist=None):
            h = hits.setdefault(aid, {"match": [], "distance": None})
            if reason not in h["match"]:
                h["match"].append(reason)
            if dist is not None:
                h["distance"] = dist if h["distance"] is None else min(h["distance"], dist)

        for kind in ("imphash", "rich"):
            if fp.get(kind):
                rows = self._query("SELECT analysis_id FROM fingerprints WHERE kind = ? AND value = ?",
                                   (kind, fp[kind]))
                if kind == "imphash" and len(rows) > GENERIC_IMPHASH_LIMIT:
                    continue
                for r in rows:
                    hit(r["analysis_id"], kind)
        if use_prnu and fp.get("prnu"):              # teuer (147 KB je Foto) – im Batch abgeschaltet
            from engines.analyzers.photo import prnu_ncc, SAME_CAMERA_NCC
            res_prefix = fp["prnu"].split(":", 1)[0] + ":%"
            for r in self._query("SELECT analysis_id, value FROM fingerprints WHERE kind = 'prnu' AND value LIKE ?",
                                 (res_prefix,)):
                ncc = prnu_ncc(fp["prnu"], r["value"])
                if ncc is not None and ncc >= SAME_CAMERA_NCC:
                    hit(r["analysis_id"], "prnu")
                    hits[r["analysis_id"]]["ncc"] = round(ncc, 3)
        if fp.get("tlsh"):
            for r in self._query("SELECT analysis_id, value FROM fingerprints WHERE kind = 'tlsh'"):
                d = tlsh_diff(fp["tlsh"], r["value"])
                if d is not None and d <= max_distance:
                    hit(r["analysis_id"], "tlsh", d)
        hits.pop(analysis_id, None)
        if not hits:
            return []
        marks = ",".join("?" * len(hits))
        rows = self._query(f"SELECT {_ROW_COLS} FROM analyses a LEFT JOIN cases c ON c.id = a.case_id "
                           f"WHERE a.id IN ({marks}) ORDER BY a.analyzed_at DESC, a.id DESC", list(hits))
        out, seen = [], set()
        for row in rows:
            if row["sha256"] == (sha256 or "").lower() or row["sha256"] in seen:
                continue                     # gleiche Datei = "seen before", nicht "ähnlich"
            seen.add(row["sha256"])
            row.update(hits[row["id"]])
            out.append(row)
        out.sort(key=lambda r: (r["distance"] if r["distance"] is not None else 999, -len(r["match"])))
        return out[:limit]

    def update_result(self, analysis_id, result):
        """Gespeichertes Ergebnis ergänzen (z. B. Hash-Abfrage) – Kennzahlen bleiben unverändert."""
        stored = {k: v for k, v in result.items() if k != "history"}
        with self._lock, self._connect() as con:
            con.execute("UPDATE analyses SET result_json = ? WHERE id = ?",
                        (json.dumps(stored, ensure_ascii=False, default=_json_default), analysis_id))

    def previous(self, sha256, exclude_id=None):
        """Frühere Analysen derselben Datei (gleicher SHA-256), neueste zuerst."""
        if not sha256:
            return []
        return self._query(
            f"SELECT {_ROW_COLS} FROM analyses a LEFT JOIN cases c ON c.id = a.case_id "
            "WHERE a.sha256 = ? AND a.id != ? ORDER BY a.analyzed_at DESC, a.id DESC",
            (sha256.lower(), exclude_id or -1))

    def list_analyses(self, case_id=None, search="", limit=1000):
        """
        case_id: None = alle, 0 = ohne Fall, >0 = dieser Fall.
        search:  Teilstring in Dateiname/Pfad, Hash-Präfix, Headline oder einem gespeicherten IOC.
        """
        where, args = [], []
        if case_id == 0:
            where.append("a.case_id IS NULL")
        elif case_id:
            where.append("a.case_id = ?")
            args.append(case_id)
        s = (search or "").strip()
        if s:
            like = f"%{s}%"
            where.append("(a.name LIKE ? OR a.path LIKE ? OR a.headline LIKE ? OR a.md5 LIKE ? "
                         "OR a.sha1 LIKE ? OR a.sha256 LIKE ? OR EXISTS (SELECT 1 FROM iocs i "
                         "WHERE i.analysis_id = a.id AND i.value LIKE ?))")
            args += [like, like, like, s.lower() + "%", s.lower() + "%", s.lower() + "%", like]
        sql = f"SELECT {_ROW_COLS} FROM analyses a LEFT JOIN cases c ON c.id = a.case_id"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY a.analyzed_at DESC, a.id DESC LIMIT ?"
        return self._query(sql, args + [int(limit)])

    def get_result(self, analysis_id):
        """Vollständiges gespeichertes Ergebnis, markiert mit result['history']."""
        rows = self._query("SELECT id, case_id, analyzed_at, result_json FROM analyses WHERE id = ?",
                           (analysis_id,))
        if not rows:
            return None
        res = json.loads(rows[0]["result_json"])
        if isinstance(res.get("magic"), list):
            res["magic"] = tuple(res["magic"])
        res["history"] = {"id": rows[0]["id"], "case_id": rows[0]["case_id"],
                          "analyzed_at": rows[0]["analyzed_at"]}
        return res

    def iocs_for(self, analysis_id):
        return self._query("SELECT type, value FROM iocs WHERE analysis_id = ? ORDER BY type, value",
                           (analysis_id,))

    def search_ioc(self, value):
        """Analysen, in denen ein IOC vorkam (Teilstring, ohne Groß/Klein)."""
        return self._query(
            f"SELECT DISTINCT {_ROW_COLS}, i.type AS ioc_type, i.value AS ioc_value FROM iocs i "
            "JOIN analyses a ON a.id = i.analysis_id LEFT JOIN cases c ON c.id = a.case_id "
            "WHERE i.value LIKE ? ORDER BY a.analyzed_at DESC", (f"%{value}%",))

    def assign(self, analysis_ids, case_id):
        """Analysen einem Fall zuordnen (case_id=None löst die Zuordnung)."""
        ids = list(analysis_ids)
        with self._lock, self._connect() as con:
            con.executemany("UPDATE analyses SET case_id = ? WHERE id = ?", [(case_id, i) for i in ids])

    def delete_analyses(self, analysis_ids):
        with self._lock, self._connect() as con:
            con.executemany("DELETE FROM analyses WHERE id = ?", [(i,) for i in analysis_ids])

    # ── Fälle ─────────────────────────────────────────────────────────
    def create_case(self, name, description=""):
        name = (name or "").strip()
        if not name:
            raise ValueError("Fallname darf nicht leer sein")
        with self._lock, self._connect() as con:
            try:
                return con.execute("INSERT INTO cases (name, description, created_at) VALUES (?,?,?)",
                                   (name, description or "", _now())).lastrowid
            except sqlite3.IntegrityError:
                raise ValueError(f"Fall '{name}' existiert bereits") from None

    def list_cases(self):
        return self._query(
            "SELECT c.id, c.name, c.description, c.created_at, COUNT(a.id) AS analyses, "
            "MAX(a.score) AS max_score FROM cases c LEFT JOIN analyses a ON a.case_id = c.id "
            "GROUP BY c.id ORDER BY c.created_at DESC, c.id DESC")

    def delete_case(self, case_id):
        """Löscht den Fall; seine Analysen bleiben erhalten (ohne Fall)."""
        with self._lock, self._connect() as con:
            con.execute("DELETE FROM cases WHERE id = ?", (case_id,))

    def stats(self):
        r = self._query("SELECT COUNT(*) AS analyses, COUNT(DISTINCT sha256) AS files, "
                        "SUM(CASE WHEN level IN ('HIGH RISK','CRITICAL') THEN 1 ELSE 0 END) AS high "
                        "FROM analyses")[0]
        r["cases"] = self._query("SELECT COUNT(*) AS n FROM cases")[0]["n"]
        return r


_default = None


def default_db():
    """Gemeinsame Instanz unter config.settings.HISTORY_DB (lazy)."""
    global _default
    if _default is None:
        from config.settings import HISTORY_DB
        _default = HistoryDB(HISTORY_DB)
    return _default
