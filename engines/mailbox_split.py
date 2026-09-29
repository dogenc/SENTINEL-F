"""
Postfächer in einzelne .eml-Dateien zerlegen (läuft im Sandbox-Worker, Modus --sentinel-mailbox).

Unterstützt:
  * mbox (Thunderbird, Apple Mail-Export, Gmail-Takeout, Linux) – auch Thunderbird-
    Profilordner: jede Datei, die mit "From " beginnt, ist ein Postfach
  * Outlook .pst / .ost (libpff-python, optional) – Kopfzeilen, Text, HTML, Anhänge
  * Outlook .msg (extract-msg, optional)
  * Ordner mit .eml-Dateien
Die .eml-Dateien landen im Job-Ordner und werden danach wie jede Datei in der
Sandbox analysiert (Anhänge über die Payload-Kette).
"""
import email.policy
import mailbox
import os
import re
from email.message import EmailMessage
from pathlib import Path

MAX_MESSAGES = 5000
MAX_MESSAGE_BYTES = 64 << 20


def _is_mbox(path):
    try:
        with open(path, "rb") as f:
            return f.read(5) == b"From "
    except OSError:
        return False


def sources(path):
    """Postfach-Quellen in einem Pfad (Datei oder Ordner). → [(art, pfad)]"""
    p = Path(path)
    if p.is_file():
        ext = p.suffix.lower()
        if ext in (".pst", ".ost"):
            return [("pst", str(p))]
        if ext == ".msg":
            return [("msg", str(p))]
        if ext == ".eml":
            return [("eml", str(p))]
        return [("mbox", str(p))] if _is_mbox(p) else []
    out = []
    for dirpath, _dirs, files in os.walk(p):
        for n in sorted(files):
            f = Path(dirpath) / n
            ext = f.suffix.lower()
            if ext in (".msf", ".dat", ".json", ".sqlite", ".html", ".js"):
                continue
            if ext == ".eml":
                out.append(("eml", str(f)))
            elif ext in (".pst", ".ost"):
                out.append(("pst", str(f)))
            elif ext == ".msg":
                out.append(("msg", str(f)))
            elif _is_mbox(f):
                out.append(("mbox", str(f)))
    return out


def _safe(s, n=60):
    return re.sub(r"[^\w.\- ]", "_", str(s or ""))[:n].strip(" ._") or "mail"


def _write(outdir, idx, raw, meta, index):
    if len(raw) > MAX_MESSAGE_BYTES:
        index.append(dict(meta, skipped="too large"))
        return
    name = f"{idx:05d}_{_safe(meta.get('subject'), 40)}.eml"
    (Path(outdir) / name).write_bytes(raw)
    index.append(dict(meta, file=name))


def _meta(msg, source, folder=""):
    return {"source": source, "folder": folder, "subject": str(msg.get("Subject", ""))[:200],
            "from": str(msg.get("From", ""))[:200], "date": str(msg.get("Date", ""))[:80]}


def _mbox(path, outdir, index, start):
    n = start
    box = mailbox.mbox(path, create=False)
    try:
        for key in box.iterkeys():
            if n >= MAX_MESSAGES:
                break
            raw = box.get_bytes(key)
            msg = email.message_from_bytes(raw[:1 << 16], policy=email.policy.compat32)
            _write(outdir, n, raw, _meta(msg, Path(path).name, Path(path).name), index)
            n += 1
    finally:
        box.close()
    return n


def pst_message_to_eml(m):
    """pypff-Nachricht → RFC-822-Bytes (Kopfzeilen, Text/HTML, Anhänge)."""
    headers = (getattr(m, "transport_headers", None) or "").strip()
    msg = EmailMessage()
    if headers:
        parsed = email.message_from_string(headers + "\n\n", policy=email.policy.default)
        for k, v in parsed.items():
            if k.lower() not in ("content-type", "content-transfer-encoding", "mime-version"):
                try:
                    msg[k] = v
                except (ValueError, TypeError):
                    pass
    if "Subject" not in msg and getattr(m, "subject", None):
        msg["Subject"] = m.subject
    if "From" not in msg and getattr(m, "sender_name", None):
        msg["From"] = m.sender_name
    text = getattr(m, "plain_text_body", None) or b""
    html = getattr(m, "html_body", None) or b""
    text = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
    html = html.decode("utf-8", "replace") if isinstance(html, bytes) else str(html)
    msg.set_content(text or " ")
    if html:
        msg.add_alternative(html, subtype="html")
    for i in range(getattr(m, "number_of_attachments", 0) or 0):
        try:
            a = m.get_attachment(i)
            size = a.get_size() if hasattr(a, "get_size") else a.size
            data = a.read_buffer(size) if size else b""
            name = _attachment_name(a) or f"attachment_{i + 1}.bin"
            msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
        except Exception:
            continue
    return bytes(msg)


def _attachment_name(a):
    for attr in ("name", "long_filename", "filename"):
        v = getattr(a, attr, None)
        if v:
            return str(v)
    try:                                   # PR_ATTACH_LONG_FILENAME (0x3707) / PR_ATTACH_FILENAME (0x3704)
        rs = a.get_record_set(0)
        for j in range(rs.number_of_entries):
            e = rs.get_entry(j)
            if e.entry_type in (0x3707, 0x3704):
                return e.get_data_as_string()
    except Exception:
        pass
    return None


def _pst(path, outdir, index, start):
    import pypff
    n = start
    f = pypff.file()
    f.open(path)
    try:
        stack = [(f.get_root_folder(), "")]
        while stack and n < MAX_MESSAGES:
            folder, name = stack.pop()
            for i in range(folder.number_of_sub_folders):
                sub = folder.get_sub_folder(i)
                stack.append((sub, f"{name}/{sub.name or ''}"))
            for i in range(folder.number_of_sub_messages):
                if n >= MAX_MESSAGES:
                    break
                try:
                    m = folder.get_sub_message(i)
                    raw = pst_message_to_eml(m)
                except Exception as e:
                    index.append({"source": Path(path).name, "folder": name, "error": f"{type(e).__name__}: {e}"})
                    continue
                msg = email.message_from_bytes(raw[:1 << 16], policy=email.policy.compat32)
                _write(outdir, n, raw, _meta(msg, Path(path).name, name), index)
                n += 1
    finally:
        f.close()
    return n


def _msg(path, outdir, index, start):
    import extract_msg
    m = extract_msg.openMsg(path)
    try:
        em = EmailMessage()
        for k, v in (m.header.items() if m.header else []):
            if k.lower() not in ("content-type", "content-transfer-encoding", "mime-version"):
                try:
                    em[k] = v
                except (ValueError, TypeError):
                    pass
        if "Subject" not in em and m.subject:
            em["Subject"] = m.subject
        em.set_content(m.body or " ")
        for a in m.attachments:
            data = getattr(a, "data", None)
            if isinstance(data, bytes):
                em.add_attachment(data, maintype="application", subtype="octet-stream",
                                  filename=a.longFilename or a.shortFilename or "attachment.bin")
        raw = bytes(em)
    finally:
        m.close()
    msg = email.message_from_bytes(raw[:1 << 16], policy=email.policy.compat32)
    _write(outdir, start, raw, _meta(msg, Path(path).name), index)
    return start + 1


def split(path, outdir):
    """→ {'messages': [...], 'errors': [...], 'sources': n, 'truncated': bool}"""
    Path(outdir).mkdir(parents=True, exist_ok=True)
    index, errors, n = [], [], 0
    srcs = sources(path)
    for kind, src in srcs:
        if n >= MAX_MESSAGES:
            break
        try:
            if kind == "mbox":
                n = _mbox(src, outdir, index, n)
            elif kind == "pst":
                n = _pst(src, outdir, index, n)
            elif kind == "msg":
                n = _msg(src, outdir, index, n)
            elif kind == "eml":
                raw = Path(src).read_bytes()
                msg = email.message_from_bytes(raw[:1 << 16], policy=email.policy.compat32)
                _write(outdir, n, raw, _meta(msg, Path(src).name), index)
                n += 1
        except ImportError as e:
            errors.append(f"{Path(src).name}: support not installed ({e.name}) – "
                          + ("pip install libpff-python" if kind == "pst" else "pip install extract-msg"))
        except Exception as e:
            errors.append(f"{Path(src).name}: {type(e).__name__}: {e}")
    return {"messages": index, "errors": errors, "sources": len(srcs), "truncated": n >= MAX_MESSAGES}
