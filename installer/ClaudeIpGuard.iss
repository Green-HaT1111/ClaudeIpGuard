; Inno Setup script for Claude IP Guard. Build with build.ps1 (it publishes the app first).
#define AppName "Claude IP Guard"
#define AppVersion "1.1.0"
#define AppExe "ClaudeIpGuard.exe"

[Setup]
AppId={{8C3F2A51-6B7D-4E2A-9C1F-3D5E7A9B1C24}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppName}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=ClaudeIpGuard-Setup-{#AppVersion}
SetupIconFile=..\src\ClaudeIpGuard\Assets\app.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 or newer
MinVersion=10.0
PrivilegesRequired=admin
; Setup and uninstall refuse to continue while the app is running (it must be exited with the password first).
AppMutex=ClaudeIpGuard_SingleInstance

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "service-permission.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; Let normal users stop Claude's background service (CoworkVMService), so the guard can close it
; without admin rights. Does nothing if users can already stop it or the service isn't installed.
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\service-permission.ps1"" -Action Grant"; StatusMsg: "Setting up permission to stop Claude's background service..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove only the permission that setup added.
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\service-permission.ps1"" -Action Revoke"; RunOnceId: "RevokeServicePermission"; Flags: runhidden waituntilterminated
