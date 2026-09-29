"""Archiv-/Zipbomb-Erkennung mit synthetischen, harmlosen Samples."""
import gzip
import io
import struct
import tarfile
import zipfile

from engines.analyzers import limits
from tests.helpers import analyze, codes


def _zip(path, files, method=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", method) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return path


def test_benign_zip_is_quiet(tmp_path):
    p = _zip(tmp_path / "ok.zip", {"a.txt": b"hallo welt " * 50, "b/c.txt": b"xyz"})
    data, f = analyze(p, only={"archive"})
    assert not codes(f) & {"zip_bomb", "zip_overlap", "path_traversal", "decompression_ratio_high"}
    assert data["archive"]["stats"]["entries"] == 2
    assert data["archive"]["stats"]["measurement_complete"]


def test_high_ratio_zip_is_bomb(tmp_path):
    p = tmp_path / "bomb.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_BZIP2) as z:
        with z.open("zeros.bin", "w") as fh:
            for _ in range(40):
                fh.write(b"\x00" * (1 << 20))
    data, f = analyze(p, only={"archive"})
    assert "zip_bomb" in codes(f)
    assert data["archive"]["stats"]["declared_ratio"] > 1000


def test_stream_cap_stops_bomb(tmp_path, monkeypatch):
    monkeypatch.setattr(limits, "DECOMP_CAP_ENTRY", 1 << 20)
    p = tmp_path / "big.gz"
    with gzip.open(p, "wb") as g:
        for _ in range(5):
            g.write(b"\x00" * (1 << 20))
    data, f = analyze(p, only={"archive"})
    assert "zip_bomb" in codes(f)
    assert data["archive"]["stats"]["measurement_complete"] is False


def test_total_budget_stops_analysis(tmp_path, monkeypatch):
    monkeypatch.setattr(limits, "DECOMP_CAP_TOTAL", 2 << 20)
    p = _zip(tmp_path / "many.zip", {f"f{i}.bin": b"\x00" * (1 << 20) for i in range(6)})
    data, f = analyze(p, only={"archive"})
    assert "zip_bomb" in codes(f)
    assert data["archive"]["stats"]["stopped_because"] == "size"


def _overlapping_zip(path, copies=20):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("k", b"\x00" * 100_000)
    raw = buf.getvalue()
    cd_off = raw.index(b"PK\x01\x02")
    eocd_off = raw.index(b"PK\x05\x06")
    cd = raw[cd_off:eocd_off]
    new_cd = b"".join(cd[:46] + bytes([65 + i % 26]) + cd[47:] for i in range(copies))
    eocd = bytearray(raw[eocd_off:])
    struct.pack_into("<HHI", eocd, 8, copies, copies, len(new_cd))
    path.write_bytes(raw[:cd_off] + new_cd + bytes(eocd))
    return path


def test_overlapping_entries_detected(tmp_path):
    p = _overlapping_zip(tmp_path / "overlap.zip")
    _, f = analyze(p, only={"archive"})
    assert "zip_overlap" in codes(f)


def test_zip_slip_detected(tmp_path):
    p = _zip(tmp_path / "slip.zip", {"../../Windows/evil.txt": b"x"})
    _, f = analyze(p, only={"archive"})
    assert "path_traversal" in codes(f)


def test_double_extension_inside_zip(tmp_path):
    p = _zip(tmp_path / "post.zip", {"Rechnung.pdf.exe": b"MZ" + b"\x00" * 100})
    _, f = analyze(p, only={"archive"})
    assert "archive_double_extension" in codes(f)


def test_recursive_nesting_detected(tmp_path):
    inner = b"payload"
    name = "x.txt"
    for level in range(4):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr(name, inner)
        inner, name = buf.getvalue(), f"level{level}.zip"
    p = tmp_path / "nested.zip"
    p.write_bytes(inner)
    data, f = analyze(p, only={"archive"})
    assert "nested_archives" in codes(f)
    assert data["archive"]["stats"]["max_depth"] >= 3
    assert any(x["severity"] == "CRIT" for x in f if x["code"] == "nested_archives")


def test_tar_symlink_escape(tmp_path):
    p = tmp_path / "t.tar"
    with tarfile.open(p, "w") as t:
        ti = tarfile.TarInfo("link")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "../../etc/passwd"
        t.addfile(ti)
    _, f = analyze(p, only={"archive"})
    sym = [x for x in f if x["code"] == "archive_symlink"]
    assert sym and sym[0]["severity"] == "CRIT"


def test_tar_gz_goes_through_stream_and_tar(tmp_path):
    p = tmp_path / "t.tar.gz"
    with tarfile.open(p, "w:gz") as t:
        data = b"hello"
        ti = tarfile.TarInfo("../escape.sh")
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    _, f = analyze(p, only={"archive"})
    assert "path_traversal" in codes(f)


def test_docx_not_flagged_as_bomb(docx_file):
    _, f = analyze(docx_file, only={"archive"})
    assert not codes(f) & {"zip_bomb", "decompression_ratio_high", "archive_executable"}


def test_corrupt_zip_does_not_crash(tmp_path):
    p = tmp_path / "broken.zip"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 50)
    data, f = analyze(p, only={"archive"})
    assert "_error" not in data["archive"]
