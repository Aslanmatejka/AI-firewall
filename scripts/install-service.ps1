#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ServiceName = "AiShield"
$DisplayName = "AI Firewall Service"
$DotNet = "$env:ProgramFiles\dotnet\dotnet.exe"

Write-Host "=== AI Firewall Installer ===" -ForegroundColor Cyan

# 1. ProgramData layout
$DataDir = "$env:ProgramData\AiShield"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$ConfigSrc = Join-Path $Root "config\default.json"
$ConfigDest = Join-Path $DataDir "config.json"
if (-not (Test-Path $ConfigDest)) {
    Copy-Item $ConfigSrc $ConfigDest
    Write-Host "Installed config to $ConfigDest"
}

# 2. Python dependencies
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
pip install -r (Join-Path $Root "python\requirements.txt") -q

# 3. Build C# solution
if (-not (Test-Path $DotNet)) { throw ".NET SDK not found" }
& $DotNet build (Join-Path $Root "csharp\AiShield.sln") -c Release
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

$ServiceExe = Join-Path $Root "csharp\AiShield.Service\bin\Release\net8.0-windows\AiShield.Service.exe"
if (-not (Test-Path $ServiceExe)) { throw "Service exe not found: $ServiceExe" }

# 4. Register Windows Service
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -eq 'Running') { Stop-Service $ServiceName -Force }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

sc.exe create $ServiceName binPath= "`"$ServiceExe`"" start= auto DisplayName= "$DisplayName"
sc.exe description $ServiceName "AI Firewall — monitors AI processes and supervises the Python enforcement backend"
Write-Host "Registered Windows service: $ServiceName" -ForegroundColor Green

# 5. Start service
Start-Service $ServiceName
Write-Host ""
Write-Host "AI Firewall installed and started." -ForegroundColor Green
Write-Host "Dashboard: http://127.0.0.1:9470"
Write-Host "Launch desktop UI: .\scripts\launch-dashboard.ps1"
Write-Host ""
Write-Host "Optional: kernel minifilter  .\scripts\install-minifilter.ps1"
Write-Host "Optional: browser blocking  .\scripts\configure-browser-gpo.ps1"
