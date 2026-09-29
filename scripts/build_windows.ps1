# ═══════════════════════════════════════════════════════════════════════════════
#  SENTINEL-F · Windows-Build: Setup.exe + Portable-ZIP
#
#     powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
#
#  Ergebnis in dist\:
#     SENTINEL-F-<ver>-Setup-win64.exe      Installer (Startmenü, Kontextmenü, Deinstallation)
#     SENTINEL-F-<ver>-Portable-win64.zip   entpacken und starten, Daten bleiben im Ordner
#
#  Voraussetzungen: Python 3.12 (64 Bit), für das Setup zusätzlich Inno Setup 6
#  (https://jrsoftware.org/isdl.php). Ohne Inno Setup wird nur die Portable-Version gebaut.
# ═══════════════════════════════════════════════════════════════════════════════
param(
    [switch]$SkipInstall,     # Abhängigkeiten nicht (neu) installieren
    [switch]$PortableOnly     # kein Setup bauen
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Version = (Select-String -Path "config\settings.py" -Pattern 'APP_VERSION\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
Write-Host "== SENTINEL-F $Version ==" -ForegroundColor Green

if (Test-Path "config\local_secrets.py") {
    Write-Host "Hinweis: config\local_secrets.py wird NICHT in die EXE gepackt (Spec schließt sie aus)." -ForegroundColor Yellow
}

if (-not $SkipInstall) {
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt pyinstaller
    if ($LASTEXITCODE -ne 0) { throw "pip install fehlgeschlagen" }
}

# ── 1. PyInstaller ────────────────────────────────────────────────────────────
python -m PyInstaller DGKN_FileForensic.spec --clean --noconfirm
if ($LASTEXITCODE -ne 0) { throw "PyInstaller fehlgeschlagen" }
$App = "dist\DGKN-FileForensic"
Copy-Item LICENSE, NOTICE, THIRD_PARTY_NOTICES.md, README.md $App -Force

# Kurzer Rauchtest: der Sandbox-Worker der gebauten EXE muss eine Datei analysieren können
$job = Join-Path $env:TEMP ("sentinel_build_" + [guid]::NewGuid())
New-Item -ItemType Directory $job | Out-Null
Set-Content "$job\probe.txt" "hello"
& "$App\DGKN-FileForensic.exe" --sentinel-worker "$job\probe.txt" $job | Out-Null
if (-not (Test-Path "$job\result.json")) { throw "Rauchtest fehlgeschlagen: Worker hat kein Ergebnis geschrieben" }
Remove-Item $job -Recurse -Force
Write-Host "Rauchtest OK" -ForegroundColor Green

# ── 2. Portable ───────────────────────────────────────────────────────────────
$PortDir = "dist\portable\SENTINEL-F-Portable"
if (Test-Path "dist\portable") { Remove-Item "dist\portable" -Recurse -Force }
New-Item -ItemType Directory $PortDir | Out-Null
Copy-Item "$App\*" $PortDir -Recurse
Copy-Item "installer\portable.txt" $PortDir
$Zip = "dist\SENTINEL-F-$Version-Portable-win64.zip"
if (Test-Path $Zip) { Remove-Item $Zip }
Compress-Archive -Path $PortDir -DestinationPath $Zip -CompressionLevel Optimal
Write-Host "Portable: $Zip" -ForegroundColor Green

# ── 3. Setup ──────────────────────────────────────────────────────────────────
if (-not $PortableOnly) {
    $iscc = @(
        (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if ($iscc) {
        & $iscc "/DAppVersion=$Version" "installer\sentinel-f.iss"
        if ($LASTEXITCODE -ne 0) { throw "Inno Setup fehlgeschlagen" }
        Write-Host "Setup: dist\SENTINEL-F-$Version-Setup-win64.exe" -ForegroundColor Green
    } else {
        Write-Host "Inno Setup 6 nicht gefunden – nur Portable gebaut. Installieren: winget install JRSoftware.InnoSetup" -ForegroundColor Yellow
    }
}

# Prüfsummen für die Release-Seite
Get-ChildItem dist -File | Where-Object { $_.Name -like "SENTINEL-F-*" } |
    ForEach-Object { "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name } |
    Set-Content "dist\SHA256SUMS.txt" -Encoding ascii
Get-Content "dist\SHA256SUMS.txt"
