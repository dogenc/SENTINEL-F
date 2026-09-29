"""Setup-/Portable-Betrieb: Datenorte, Schlüssel außerhalb der EXE, Build-Dateien vollständig."""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PROBE = r"""
import json, sys
sys.frozen = True
sys.executable = {exe!r}
sys._MEIPASS = {meipass!r}
sys.path.insert(0, {root!r})
from config import settings as s
print(json.dumps({{"user": str(s.USER_DIR), "data": str(s.DATA_DIR), "res": str(s.RESOURCE_DIR),
                  "portable": s.PORTABLE, "cesium": s.CESIUM_ION_TOKEN}}))
"""


def _probe(tmp_path, portable=False, env_extra=None):
    app = tmp_path / "app"
    (app / "_internal").mkdir(parents=True)
    if portable:
        (app / "portable.txt").write_text("portable")
    code = PROBE.format(exe=str(app / "DGKN-FileForensic.exe"), meipass=str(app / "_internal"), root=str(ROOT))
    env = {"PATH": "", "LOCALAPPDATA": str(tmp_path / "lad"), **(env_extra or {})}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 0, out.stderr
    return app, json.loads(out.stdout.strip().splitlines()[-1])


def test_installed_uses_localappdata(tmp_path):
    app, r = _probe(tmp_path)
    assert Path(r["user"]) == tmp_path / "lad" / "DGKN-FileForensic"
    assert Path(r["data"]) == tmp_path / "lad" / "DGKN-FileForensic" / "data"
    assert Path(r["res"]) == app / "_internal" / "resources"
    assert r["portable"] is False


def test_portable_keeps_everything_next_to_exe(tmp_path):
    app, r = _probe(tmp_path, portable=True)
    assert Path(r["user"]) == app / "UserData"
    assert r["portable"] is True
    assert not (tmp_path / "lad").exists()                  # nichts in AppData


def test_user_dir_override(tmp_path):
    _, r = _probe(tmp_path, env_extra={"DGKN_USER_DIR": str(tmp_path / "custom")})
    assert Path(r["user"]) == tmp_path / "custom"


def test_frozen_reads_keys_from_user_dir(tmp_path):
    ud = tmp_path / "lad" / "DGKN-FileForensic"
    ud.mkdir(parents=True)
    (ud / "local_secrets.py").write_text('CESIUM_ION_TOKEN = "from-user-dir"\n')
    _, r = _probe(tmp_path)
    assert r["cesium"] == "from-user-dir"


def test_spec_never_bundles_secrets():
    spec = (ROOT / "DGKN_FileForensic.spec").read_text(encoding="utf-8")
    excludes = spec[spec.index("excludes=["):spec.index("]", spec.index("excludes=["))]
    assert '"config.local_secrets"' in excludes
    assert "local_secrets.py" not in spec.split("datas = [")[1].split("]")[0]


def test_installer_inputs_exist():
    iss = (ROOT / "installer" / "sentinel-f.iss").read_text(encoding="utf-8")
    for rel in re.findall(r'(?:Source|LicenseFile|SetupIconFile)\s*[:=]\s*"?\.\.\\([^"*\r\n]+?)"?[;\r\n]', iss):
        assert (ROOT / rel.replace("\\", "/")).exists(), rel
    assert (ROOT / "installer" / "portable.txt").exists()
    assert (ROOT / "resources" / "sentinel.ico").exists()
    assert (ROOT / "LICENSE").read_text(encoding="utf-8").lstrip().startswith("GNU GENERAL PUBLIC LICENSE")


def test_attribution_is_shipped_and_shown():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "DGKN@Labs" in notice and "section 7" in notice and "AI" in notice
    iss = (ROOT / "installer" / "sentinel-f.iss").read_text(encoding="utf-8")
    assert '"..\\NOTICE"' in iss
    assert "NOTICE" in (ROOT / "scripts" / "build_windows.ps1").read_text(encoding="utf-8")
    from gui.about import about_html
    html = about_html()
    assert "DGKN@Labs" in html and "GNU General Public License" in html and "no warranty" in html
