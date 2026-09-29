"""
Signierte Berichte: Ed25519-Signatur je Bericht + optionaler RFC-3161-Zeitstempel.

* Schlüssel je Arbeitsplatz in data/signing/ (Ed25519). Unter Windows wird der private
  Schlüssel mit DPAPI an das Windows-Konto gebunden (kein Passwort, aber nicht auf
  anderen Konten/Rechnern nutzbar); sonst Dateirechte 0600.
* <bericht>.sig (JSON): SHA-256 des Berichts, Zeitpunkt, Bearbeiter, öffentlicher
  Schlüssel + Fingerabdruck, Signatur über genau diese Angaben.
* <bericht>.tsr: Antwort eines RFC-3161-Zeitstempeldienstes (nur der Hash verlässt
  den Rechner; opt-in über REPORT_TSA_URL). Vollständige Prüfung inkl. TSA-Zertifikat:
  openssl ts -verify -data <bericht> -in <bericht>.tsr -CAfile <tsa-ca.pem>
"""
import base64
import datetime
import hashlib
import json
import os
import secrets
import sys
import urllib.request
from pathlib import Path

from config.settings import DATA_DIR

FORMAT = "SENTINEL-F-SIG-1"
KEY_DIR = DATA_DIR / "signing"
SHA256_OID = bytes.fromhex("0609608648016503040201")


# ── DPAPI (Windows) ──────────────────────────────────────────────────────────
def _dpapi(data, protect):
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32")
    buf = ctypes.create_string_buffer(data, len(data))
    inp, out = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), BLOB()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if protect:
        ok = fn(ctypes.byref(inp), "SENTINEL-F signing key", None, None, None, 0x1, ctypes.byref(out))
    else:
        ok = fn(ctypes.byref(inp), None, None, None, None, 0x1, ctypes.byref(out))
    if not ok:
        raise OSError(ctypes.get_last_error(), "DPAPI fehlgeschlagen")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        k32.LocalFree(out.pbData)


# ── Schlüssel ────────────────────────────────────────────────────────────────
def _paths(key_dir=None):
    d = Path(key_dir or KEY_DIR)
    return d, d / "ed25519_private.key", d / "ed25519_public.pem"


def load_or_create_key(key_dir=None):
    """→ Ed25519PrivateKey (legt beim ersten Aufruf ein Schlüsselpaar an)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    d, priv_path, pub_path = _paths(key_dir)
    if priv_path.exists():
        raw = priv_path.read_bytes()
        if raw.startswith(b"DPAPI:"):
            raw = _dpapi(base64.b64decode(raw[6:]), protect=False)
        return Ed25519PrivateKey.from_private_bytes(raw)
    d.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    if sys.platform == "win32":
        try:
            priv_path.write_bytes(b"DPAPI:" + base64.b64encode(_dpapi(raw, protect=True)))
        except OSError:
            priv_path.write_bytes(raw)
    else:
        priv_path.write_bytes(raw)
        os.chmod(priv_path, 0o600)
    pub_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def _pub_raw(pub):
    from cryptography.hazmat.primitives import serialization
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(pub_raw):
    h = hashlib.sha256(pub_raw).hexdigest()[:24].upper()
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))


def own_fingerprint(key_dir=None):
    return fingerprint(_pub_raw(load_or_create_key(key_dir).public_key()))


def _message(sha256_hex, signed_at, signer, file_name):
    return f"{FORMAT}\n{sha256_hex}\n{signed_at}\n{signer}\n{file_name}".encode("utf-8")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_file(path, signer="", key_dir=None):
    """Schreibt <datei>.sig. → dict der Signatur."""
    key = load_or_create_key(key_dir)
    path = Path(path)
    digest = sha256_file(path)
    signed_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    pub = _pub_raw(key.public_key())
    sig = key.sign(_message(digest, signed_at, signer, path.name))
    doc = {"format": FORMAT, "alg": "Ed25519", "file": path.name, "sha256": digest, "signed_at": signed_at,
           "signer": signer, "public_key": base64.b64encode(pub).decode(), "key_fingerprint": fingerprint(pub),
           "signature": base64.b64encode(sig).decode()}
    Path(str(path) + ".sig").write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    return doc


def verify_file(path, sig_path=None, key_dir=None):
    """→ {'valid', 'reason', 'signer', 'signed_at', 'key_fingerprint', 'own_key', 'timestamp'}"""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    path = Path(path)
    sig_path = Path(sig_path or str(path) + ".sig")
    out = {"valid": False, "reason": "", "signer": None, "signed_at": None, "key_fingerprint": None,
           "own_key": False, "timestamp": None}
    if not sig_path.exists():
        out["reason"] = "no signature file (.sig) next to the report"
        return out
    try:
        doc = json.loads(sig_path.read_text(encoding="utf-8"))
        pub_raw = base64.b64decode(doc["public_key"])
        sig = base64.b64decode(doc["signature"])
    except (ValueError, KeyError) as e:
        out["reason"] = f"signature file unreadable: {e}"
        return out
    out.update(signer=doc.get("signer"), signed_at=doc.get("signed_at"), key_fingerprint=fingerprint(pub_raw))
    try:
        out["own_key"] = fingerprint(pub_raw) == own_fingerprint(key_dir)
    except Exception:
        pass
    digest = sha256_file(path)
    if digest != doc.get("sha256"):
        out["reason"] = "REPORT WAS MODIFIED after signing (SHA-256 differs)"
        return out
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(
            sig, _message(doc["sha256"], doc["signed_at"], doc.get("signer", ""), doc.get("file", path.name)))
    except InvalidSignature:
        out["reason"] = "signature does not match its data (signature file was altered)"
        return out
    out["valid"] = True
    out["reason"] = "signature valid – report unchanged since signing"
    tsr = Path(str(path) + ".tsr")
    if tsr.exists():
        out["timestamp"] = parse_timestamp_response(tsr.read_bytes(), bytes.fromhex(digest))
    return out


# ── RFC 3161 (minimales DER, ohne Zusatzbibliothek) ─────────────────────────
def _tlv(tag, content):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


def _int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=False)
    return _tlv(0x02, b)


def timestamp_request(digest, nonce=None):
    """TimeStampReq (RFC 3161) für einen SHA-256-Hash → DER-Bytes."""
    alg = _tlv(0x30, SHA256_OID + b"\x05\x00")
    imprint = _tlv(0x30, alg + _tlv(0x04, digest))
    nonce = nonce if nonce is not None else secrets.randbits(63)
    return _tlv(0x30, _int(1) + imprint + _int(nonce) + b"\x01\x01\xff")      # certReq TRUE


def _read_tlv(data, pos):
    tag = data[pos]
    ln = data[pos + 1]
    pos += 2
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + k], "big")
        pos += k
    return tag, data[pos:pos + ln], pos + ln


def parse_timestamp_response(der, digest):
    """Status, Zeit und ob der Hash im Token steckt. (Kettenprüfung: openssl ts -verify)"""
    try:
        _tag, body, _ = _read_tlv(der, 0)
        _t, status_info, _ = _read_tlv(body, 0)
        _t2, status, _ = _read_tlv(status_info, 0)
        code = int.from_bytes(status, "big")
    except (IndexError, ValueError):
        return {"granted": False, "status": None, "gen_time": None, "hash_match": False, "error": "unparsable"}
    gen = None
    i = der.find(b"\x18")
    while i != -1:
        ln = der[i + 1] if i + 1 < len(der) else 0
        cand = der[i + 2:i + 2 + ln]
        if 15 <= ln <= 24 and cand[:2] in (b"19", b"20") and cand.endswith(b"Z"):
            gen = cand.decode("ascii")
            break
        i = der.find(b"\x18", i + 1)
    if gen:
        g = gen.rstrip("Z").split(".")[0]
        gen = f"{g[0:4]}-{g[4:6]}-{g[6:8]} {g[8:10]}:{g[10:12]}:{g[12:14]} UTC"
    return {"granted": code in (0, 1), "status": code, "gen_time": gen,
            "hash_match": (b"\x04\x20" + digest) in der}


def request_timestamp(path, tsa_url, timeout=20):
    """Fragt beim TSA einen Zeitstempel für den Bericht an und legt <bericht>.tsr ab."""
    digest = bytes.fromhex(sha256_file(path))
    req = urllib.request.Request(tsa_url, data=timestamp_request(digest),
                                 headers={"Content-Type": "application/timestamp-query"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        der = r.read(1 << 20)
    info = parse_timestamp_response(der, digest)
    if not info["granted"]:
        raise OSError(0, f"TSA refused the request (status {info['status']})")
    Path(str(path) + ".tsr").write_bytes(der)
    return info
