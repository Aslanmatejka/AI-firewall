#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$FilterRoot = Join-Path $Root "native\minifilter"
$ServiceName = "AiShieldMinifilter"

Write-Host "=== AI Firewall Minifilter Install ===" -ForegroundColor Cyan

$sys = Get-ChildItem -Path $FilterRoot -Recurse -Filter "aishield_minifilter.sys" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $sys) {
    Write-Host "Driver not built. Run: .\native\minifilter\build.ps1" -ForegroundColor Yellow
    exit 1
}

$staging = "$env:ProgramData\AiShield\driver"
New-Item -ItemType Directory -Force -Path $staging | Out-Null
Copy-Item $sys.FullName (Join-Path $staging "aishield_minifilter.sys") -Force
Copy-Item (Join-Path $FilterRoot "aishield_minifilter.inf") (Join-Path $staging "aishield_minifilter.inf") -Force

$testSigning = bcdedit /enum | Select-String "testsigning\s+Yes"
if (-not $testSigning) {
    Write-Host "WARNING: Test signing is not enabled. Driver load may fail on production systems." -ForegroundColor Yellow
    Write-Host "  Dev machines: bcdedit /set testsigning on  (reboot required)" -ForegroundColor Yellow
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -eq 'Running') { Stop-Service $ServiceName -Force }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

$binPath = Join-Path $staging "aishield_minifilter.sys"
sc.exe create $ServiceName type= filesys binPath= "$binPath" start= demand DisplayName= "AI Firewall Minifilter"
sc.exe description $ServiceName "AI Firewall kernel minifilter for protected folder enforcement"

Write-Host "Registering driver via pnputil..."
pnputil /add-driver (Join-Path $staging "aishield_minifilter.inf") /install

try {
    Start-Service $ServiceName -ErrorAction Stop
    Write-Host "Minifilter service started." -ForegroundColor Green
} catch {
    Write-Host "Service created but start failed (signing/WDK may be required): $_" -ForegroundColor Yellow
}

Write-Host "Done. Restart AI Firewall Python service to connect comm port."
