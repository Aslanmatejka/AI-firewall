$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
. (Join-Path $PSScriptRoot "lib\Find-DotNet.ps1")

$DotNet = Find-DotNet
if (-not $DotNet) {
    Write-Host "ERROR: .NET 10 SDK not found. Install it from https://dotnet.microsoft.com/download" -ForegroundColor Red
    exit 1
}

Write-Host "Building AI Firewall Dashboard..." -ForegroundColor Cyan
Push-Location $Root
try {
    & $DotNet build "csharp\AiShield.sln" -c Release -v q
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$Exe = Join-Path $Root "csharp\AiShield.Dashboard\bin\Release\net10.0-windows\AiShield.Dashboard.exe"
Write-Host "Launching dashboard..." -ForegroundColor Green
Start-Process $Exe
