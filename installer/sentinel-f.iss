; ═══════════════════════════════════════════════════════════════════════════════
;  SENTINEL-F · Windows-Setup (Inno Setup 6)
;  Wird von scripts\build_windows.ps1 aufgerufen:
;     ISCC.exe /DAppVersion=1.0.0 installer\sentinel-f.iss
;  Erwartet den PyInstaller-Build in dist\DGKN-FileForensic\
; ═══════════════════════════════════════════════════════════════════════════════

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define AppName      "SENTINEL-F"
#define AppLongName  "SENTINEL-F File-Forensic Suite"
#define AppPublisher "DGKN@Labs"
#define AppURL       "https://github.com/dogenc/SENTINEL-F"
#define AppExe       "DGKN-FileForensic.exe"

[Setup]
AppId={{6F3C2A51-9D4E-4B7A-A1C8-5E2F0D9B7C31}
AppName={#AppLongName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
DefaultDirName={autopf}\DGKN-FileForensic
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist
OutputBaseFilename=SENTINEL-F-{#AppVersion}-Setup-win64
SetupIconFile=..\resources\sentinel.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppLongName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
; Ohne Adminrechte für den aktuellen Benutzer installierbar, mit Adminrechten für alle
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes

[Languages]
Name: "de"; MessagesFile: "compiler:Languages\German.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
de.ContextMenu=Im Explorer-Kontextmenü „Mit SENTINEL-F analysieren“ anzeigen
en.ContextMenu=Add "Analyze with SENTINEL-F" to the Explorer context menu
de.AnalyzeWith=Mit SENTINEL-F analysieren
en.AnalyzeWith=Analyze with SENTINEL-F
de.KeepData=Deine Analysen, Fälle, Berichte und dein Signaturschlüssel bleiben erhalten unter:%n%1
en.KeepData=Your analyses, cases, reports and signing key are kept in:%n%1

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "contextmenu"; Description: "{cm:ContextMenu}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\DGKN-FileForensic\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\NOTICE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
; Rechtsklick auf Datei oder Ordner → „Mit SENTINEL-F analysieren“ (pro Benutzer bzw. systemweit)
Root: HKA; Subkey: "Software\Classes\*\shell\SENTINEL-F"; ValueType: string; ValueName: ""; ValueData: "{cm:AnalyzeWith}"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\SENTINEL-F"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#AppExe}"",0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\SENTINEL-F\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\SENTINEL-F"; ValueType: string; ValueName: ""; ValueData: "{cm:AnalyzeWith}"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\SENTINEL-F"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#AppExe}"",0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\SENTINEL-F\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: contextmenu

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
// Beim Deinstallieren bleiben die Nutzerdaten (Verlauf, Fälle, Signaturschlüssel) bewusst erhalten.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and not UninstallSilent then
    MsgBox(FmtMessage(CustomMessage('KeepData'), [ExpandConstant('{localappdata}\DGKN-FileForensic')]),
           mbInformation, MB_OK);
end;
