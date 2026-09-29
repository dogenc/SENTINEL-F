"""
Ähnlichkeit zwischen Dateien: Fuzzy-Hash (TLSH) + Programm-Fingerabdrücke.

* TLSH (Trend Micro Locality Sensitive Hash, Version T1 / 128 Buckets / 1-Byte-
  Prüfsumme) – hier in reinem Python/numpy, Byte für Byte identisch mit der
  Referenzbibliothek (py-tlsh), die unter Windows sonst einen C++-Compiler
  bräuchte. Hashes sind damit direkt mit VirusTotal/MalwareBazaar vergleichbar.
* Imphash (Import-Tabelle) und Rich-Header-Hash (Build-Umgebung) von PE-Dateien.

Distanz-Faustregel (TLSH): 0 = identisch, ≤ 30 nahezu gleich, ≤ 70 verwandt,
> 100 unabhängig.
"""
from bisect import bisect_left

import numpy as np

MIN_LEN = 50
MAX_LEN = 8 << 20                    # darüber kein TLSH (Laufzeit; Prüfsumme ist sequentiell)
SIMILAR_MAX = 70
CHUNK = 4 << 20

V_TABLE = bytes([
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
    14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
    110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
    25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
    97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
    174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
    132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
    119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
    138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
    125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
    118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
    27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
    233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
    140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
])
_V = np.frombuffer(V_TABLE, dtype=np.uint8)

# Obergrenzen der Längenklassen (l_capturing der Referenz)
TOPVAL = [
    1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854, 1110, 1443, 1876, 2439,
    3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157, 6772, 7450, 8195, 9014, 9916, 10907, 11998,
    13198, 14518, 15970, 17567, 19323, 21256, 23382, 25720, 28292, 31121, 34233, 37656, 41422,
    45564, 50121, 55133, 60646, 66711, 73382, 80721, 88793, 97672, 107439, 118183, 130002, 143002,
    157302, 173032, 190335, 209369, 230306, 253337, 278670, 306538, 337191, 370911, 408002, 448802,
    493682, 543050, 597356, 657091, 722800, 795081, 874589, 962048, 1058252, 1164078, 1280486,
    1408534, 1549388, 1704327, 1874759, 2062236, 2268459, 2495305, 2744836, 3019320, 3321252,
    3653374, 4018711, 4420582, 4862641, 5348905, 5883796, 6472176, 7119394, 7831333, 8614467,
    9475909, 10423501, 11465851, 12612437, 13873681, 15261050, 16787154, 18465870, 20312458,
    22343706, 24578077, 27035886, 29739474, 32713425, 35984770, 39583245, 43541573, 47895730,
    52685306, 57953837, 63749221, 70124148, 77136564, 84850228, 93335252, 102668779, 112935659,
    124229227, 136652151, 150317384, 165349128, 181884040, 200072456, 220079703, 242087671,
    266296456, 292926096, 322218735, 354440623, 389884688, 428873168, 471760495, 518936559,
    570830240, 627913311, 690704607, 759775136, 835752671, 919327967, 1011260767, 1112386880,
    1223623232, 1345985727, 1480584256, 1628642751, 1791507135, 1970657856, 2167723648, 2384496256,
    2622945920, 2885240448, 3173764736, 3491141248, 3840255616, 4224281216
]

# Salz → V_TABLE[salz] (Referenz: fast_b_mapping mit vorberechnetem ersten Schritt)
_TRIPLETS = ((49, 0, 1, 2), (12, 0, 1, 3), (178, 0, 2, 3), (166, 0, 2, 4), (84, 0, 1, 4), (230, 0, 3, 4))


def _swap(b):
    return ((b & 0xF0) >> 4) | ((b & 0x0F) << 4)


def tlsh_hash(data):
    """TLSH-Hash ('T1…', 72 Zeichen) oder None (zu kurz, zu gleichförmig, zu groß)."""
    n = len(data)
    if n < MIN_LEN or n > MAX_LEN:
        return None
    arr = np.frombuffer(bytes(data), dtype=np.uint8)
    buckets = np.zeros(256, dtype=np.int64)
    checksum = 0
    vt = V_TABLE
    # In Blöcken (mit 4 Byte Überlappung) – hält den Speicher klein
    for start in range(4, n, CHUNK):
        end = min(n, start + CHUNK)
        w = [arr[start - k:end - k] for k in range(5)]         # w[k] = Byte k Positionen zurück
        for ms, a, b, c in _TRIPLETS:
            buckets += np.bincount(_V[_V[_V[ms ^ w[a]] ^ w[b]] ^ w[c]], minlength=256)
        # Prüfsumme ist eine Kette – nur der letzte Schritt ist sequentiell
        pre = _V[_V[1 ^ w[0]] ^ w[1]].tobytes()
        for x in pre:
            checksum = vt[x ^ checksum]
    b128 = buckets[:128]
    q = np.sort(b128)
    q1, q2, q3 = int(q[31]), int(q[63]), int(q[95])
    if q3 == 0 or int(np.count_nonzero(b128)) <= 64:
        return None
    code = bytearray(32)
    for i in range(32):
        h = 0
        for j in range(4):
            k = int(b128[4 * i + j])
            if q3 < k:
                h += 3 << (j * 2)
            elif q2 < k:
                h += 2 << (j * 2)
            elif q1 < k:
                h += 1 << (j * 2)
        code[i] = h
    lvalue = bisect_left(TOPVAL, n) & 0xFF
    q1r = (q1 * 100 // q3) % 16
    q2r = (q2 * 100 // q3) % 16
    out = bytes([_swap(checksum), _swap(lvalue), _swap(q1r | (q2r << 4))]) + bytes(reversed(code))
    return "T1" + out.hex().upper()


# ── Distanz ─────────────────────────────────────────────────────────────────
def _pair_table():
    t = bytearray(65536)
    for x in range(256):
        for y in range(256):
            d = 0
            for s in range(0, 8, 2):
                diff = abs(((x >> s) & 3) - ((y >> s) & 3))
                d += 6 if diff == 3 else diff
            t[(x << 8) | y] = d
    return bytes(t)


_PAIRS = _pair_table()
_PARSED = {}


def _parse(h):
    p = _PARSED.get(h)
    if p is None:
        if not h or len(h) != 72 or not h.upper().startswith("T1"):
            return None
        try:
            raw = bytes.fromhex(h[2:])
        except ValueError:
            return None
        qb = _swap(raw[2])
        p = (raw[0], _swap(raw[1]), qb & 0x0F, qb >> 4, raw[3:])
        if len(_PARSED) > 50000:
            _PARSED.clear()
        _PARSED[h] = p
    return p


def _mod_diff(x, y, r):
    dl = abs(x - y)
    return min(dl, r - dl)


def tlsh_diff(a, b):
    """Referenz-Distanz (mit Längenanteil). None bei ungültigen Hashes."""
    pa, pb = _parse(a), _parse(b)
    if pa is None or pb is None:
        return None
    ck1, l1, q11, q21, c1 = pa
    ck2, l2, q12, q22, c2 = pb
    ld = _mod_diff(l1, l2, 256)
    diff = ld if ld <= 1 else ld * 12
    for x, y in ((q11, q12), (q21, q22)):
        qd = _mod_diff(x, y, 16)
        diff += qd if qd <= 1 else (qd - 1) * 12
    if ck1 != ck2:
        diff += 1
    pairs = _PAIRS
    return diff + sum(pairs[(x << 8) | y] for x, y in zip(c1, c2))


def label(distance):
    if distance is None:
        return ""
    if distance == 0:
        return "identical structure"
    if distance <= 30:
        return "near-identical"
    if distance <= SIMILAR_MAX:
        return "related"
    return "unrelated"


# ── Fingerabdrücke eines Ergebnisses ────────────────────────────────────────
def fingerprints(result):
    """{'tlsh', 'imphash', 'rich'} – nur Werte, die sinnvoll vergleichbar sind."""
    fp = dict(result.get("fingerprints") or {})
    pe = ((result.get("report") or {}).get("analyzers") or {}).get("pe") or {}
    if pe.get("imphash") and not pe.get("dotnet"):       # .NET: Imphash ist bei allen gleich
        fp.setdefault("imphash", pe["imphash"])
    if pe.get("rich_hash"):
        fp.setdefault("rich", pe["rich_hash"])
    return {k: v for k, v in fp.items() if v}


def compute(path, size=None):
    """TLSH der Datei (liest höchstens MAX_LEN Bytes)."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_LEN + 1)
    except OSError:
        return None
    return tlsh_hash(data)
