"""
IOC-Graph über den Verlauf: welche Dateien teilen sich Infrastruktur?

Knoten: Dateien (je SHA-256 einmal) und IOCs (Domain, IP, E-Mail, Wallet, Tor,
UNC-Pfad), die in MINDESTENS ZWEI verschiedenen Dateien vorkommen – einzelne
IOCs sind für Zusammenhänge wertlos und machen den Graphen nur unlesbar.
Zusätzlich optional Ähnlichkeitskanten (TLSH ≤ 30, gleicher Imphash/Rich).

Zusammenhängende Dateien bilden Cluster – Kandidaten für eine gemeinsame
Kampagne bzw. denselben Täter.
"""
import re

import numpy as np

GRAPH_TYPES = ("domain", "ipv4", "email", "onion", "btc", "xmr", "unc_path")
SIMILAR_EDGE_MAX = 30
_RX_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
MAX_FILES = 400


def _benign(value):
    from engines.analyzers.baseline import BENIGN_DOMAINS
    v = value.lower()
    return any(b in v for b in BENIGN_DOMAINS)


def build_graph(files, ioc_rows, similar_edges=(), min_shared=2):
    """
    files:         {sha256: {id, name, level, score, case_name, ...}}
    ioc_rows:      [(sha256, type, value)]
    similar_edges: [(sha_a, sha_b, reason)]
    """
    by_ioc = {}
    for sha, typ, value in ioc_rows:
        if sha not in files or typ not in GRAPH_TYPES or not value:
            continue
        v = value.strip().lower()
        if typ == "domain" and _RX_IP.match(v):             # URL mit IP statt Hostname
            typ = "ipv4"
        if typ in ("domain", "email") and _benign(v):
            continue
        by_ioc.setdefault((typ, v), set()).add(sha)
    iocs = [{"key": f"{t}:{v}", "type": t, "value": v, "files": sorted(s)}
            for (t, v), s in by_ioc.items() if len(s) >= min_shared]
    iocs.sort(key=lambda i: (-len(i["files"]), i["key"]))
    sims = [(a, b, r) for a, b, r in similar_edges if a in files and b in files and a != b]

    # Union-Find über Dateien
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for i in iocs:
        for s in i["files"][1:]:
            union(i["files"][0], s)
    for a, b, _ in sims:
        union(a, b)
    groups = {}
    for sha in parent:
        groups.setdefault(find(sha), set()).add(sha)
    clusters = []
    for members in groups.values():
        if len(members) < 2:
            continue
        cl_iocs = [i["key"] for i in iocs if members.intersection(i["files"])]
        scores = [files[s].get("score") or 0 for s in members]
        clusters.append({"files": sorted(members, key=lambda s: -(files[s].get("score") or 0)),
                         "iocs": cl_iocs, "max_score": max(scores),
                         "similar_links": sum(1 for a, b, _ in sims if a in members)})
    clusters.sort(key=lambda c: (-c["max_score"], -len(c["files"])))
    for n, c in enumerate(clusters, 1):
        c["name"] = f"Cluster {n}"
    used = set(parent)
    return {"files": {s: files[s] for s in used}, "iocs": iocs, "similar": sims, "clusters": clusters}


def _edges(graph):
    e = [(f"file:{s}", i["key"]) for i in graph["iocs"] for s in i["files"]]
    return e + [(f"file:{a}", f"file:{b}") for a, b, _ in graph["similar"]]


def layout(graph, iterations=250, seed=7):
    """
    Kräftebasiertes Layout je Cluster (Fruchterman-Reingold, numpy); die Cluster
    werden danach in einem Raster nebeneinander gepackt, damit getrennte Gruppen
    den Platz nicht verschwenden. → {node_key: (x, y)} in [-1, 1].
    """
    keys = [f"file:{s}" for s in graph["files"]] + [i["key"] for i in graph["iocs"]]
    if not keys:
        return {}
    edges = _edges(graph)
    parent = {k: k for k in keys}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for a, b in edges:
        parent[find(a)] = find(b)
    comps = {}
    for k in keys:
        comps.setdefault(find(k), []).append(k)
    comps = sorted(comps.values(), key=lambda c: (-len(c), sorted(c)[0]))
    cols = int(np.ceil(np.sqrt(len(comps))))
    out = {}
    for n, comp in enumerate(comps):
        sub = _fr(comp, [(a, b) for a, b in edges if a in set(comp)], iterations, seed)
        r = np.sqrt(len(comp)) * 0.5 + 0.5                     # große Cluster bekommen mehr Platz
        cx, cy = (n % cols) * 3.0, (n // cols) * 3.0
        for k, (x, y) in sub.items():
            out[k] = (cx + x * r, cy + y * r)
    arr = np.array(list(out.values()))
    arr -= (arr.max(axis=0) + arr.min(axis=0)) / 2
    span = np.abs(arr).max() or 1.0
    return {k: (float(x / span), float(y / span)) for k, (x, y) in zip(out, arr)}


def _fr(keys, edges, iterations, seed):
    n = len(keys)
    if n == 1:
        return {keys[0]: (0.0, 0.0)}
    idx = {k: i for i, k in enumerate(keys)}
    edges = [(idx[a], idx[b]) for a, b in edges]
    rng = np.random.default_rng(seed)
    pos = rng.uniform(-1, 1, (n, 2))
    k = np.sqrt(4.0 / n)
    temp = 0.2
    e = np.array(edges, dtype=int) if edges else np.zeros((0, 2), dtype=int)
    for _ in range(iterations):
        delta = pos[:, None, :] - pos[None, :, :]
        dist = np.linalg.norm(delta, axis=2) + 1e-6
        rep = (k * k / dist ** 2)[:, :, None] * delta           # Abstoßung
        disp = rep.sum(axis=1)
        if len(e):
            d = pos[e[:, 0]] - pos[e[:, 1]]
            dl = np.linalg.norm(d, axis=1)[:, None] + 1e-6
            f = d * dl / k                                       # Anziehung entlang der Kanten
            np.add.at(disp, e[:, 0], -f)
            np.add.at(disp, e[:, 1], f)
        disp -= pos * 0.05                                       # leichte Schwerkraft zur Mitte
        length = np.linalg.norm(disp, axis=1)[:, None] + 1e-6
        pos += disp / length * np.minimum(length, temp)
        temp *= 0.985
    pos -= pos.mean(axis=0)
    span = np.abs(pos).max() or 1.0
    pos /= span
    return {key: (float(pos[i, 0]), float(pos[i, 1])) for key, i in idx.items()}


def graph_from_db(db, case_id=None, include_similar=True, max_files=MAX_FILES):
    """Graph aus der Verlaufsdatenbank (case_id wie list_analyses: None=alle, 0=ohne Fall)."""
    from engines.similarity import tlsh_diff
    rows = db.list_analyses(case_id=case_id, limit=max_files)
    files = {}
    for r in rows:                                               # neueste Analyse je SHA-256
        if r["sha256"] and r["sha256"] not in files:
            files[r["sha256"]] = r
    ids = {r["id"]: r["sha256"] for r in files.values()}
    if not ids:
        return build_graph({}, [])
    marks = ",".join("?" * len(ids))
    ioc_rows = [(ids[r["analysis_id"]], r["type"], r["value"]) for r in db._query(
        f"SELECT analysis_id, type, value FROM iocs WHERE analysis_id IN ({marks})", list(ids))]
    sims = []
    if include_similar:
        fps = db._query(f"SELECT analysis_id, kind, value FROM fingerprints WHERE analysis_id IN ({marks})",
                        list(ids))
        by_val = {}
        tl = []
        for r in fps:
            sha = ids[r["analysis_id"]]
            if r["kind"] == "tlsh":
                tl.append((sha, r["value"]))
            else:
                by_val.setdefault((r["kind"], r["value"]), set()).add(sha)
        for (kind, _v), shas in by_val.items():
            shas = sorted(shas)
            if 1 < len(shas) <= 50:
                sims += [(shas[0], s, kind) for s in shas[1:]]
        for i in range(len(tl)):
            for j in range(i + 1, len(tl)):
                d = tlsh_diff(tl[i][1], tl[j][1])
                if d is not None and d <= SIMILAR_EDGE_MAX:
                    sims.append((tl[i][0], tl[j][0], f"tlsh {d}"))
    return build_graph(files, ioc_rows, sims)
