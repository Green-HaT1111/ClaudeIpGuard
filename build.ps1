# Builds Claude IP Guard and its installer.
#   .\build.ps1            -> publish\ (app files) and dist\ClaudeIpGuard-Setup-1.0.0.exe
#   .\build.ps1 -NoSetup   -> only publish the app
param([switch]$NoSetup)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if (-not $dotnet) { $dotnet = "$env:ProgramFiles\dotnet\dotnet.exe" }
if (-not (Test-Path $dotnet)) { throw ".NET 8 SDK not found. Install it from https://dotnet.microsoft.com/download/dotnet/8.0" }

if (-not (Test-Path "src\ClaudeIpGuard\Assets\app.ico")) { & "$PSScriptRoot\tools\make-icon.ps1" }

if (Test-Path publish) { Remove-Item publish -Recurse -Force }
& $dotnet publish src\ClaudeIpGuard\ClaudeIpGuard.csproj -c Release -r win-x64 --self-contained true -o publish -p:DebugType=None
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

if ($NoSetup) { return }

$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found. Install it from https://jrsoftware.org/isdl.php" }

& $iscc installer\ClaudeIpGuard.iss
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }
Write-Host "Installer ready in $PSScriptRoot\dist"
