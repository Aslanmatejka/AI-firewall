# Production readiness audit — run before release
# Usage: .\scripts\production-audit.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

Write-Host "AI Firewall Production Audit" -ForegroundColor Cyan

# Ensure service is running for runtime checks
$status = $null
try {
    $status = Invoke-RestMethod -Uri "http://127.0.0.1:9470/api/status" -TimeoutSec 2
} catch {}

if (-not $status) {
    Write-Host "Starting service for runtime audit..." -ForegroundColor Yellow
    & "$PSScriptRoot\start.ps1"
    Start-Sleep -Seconds 5
}

python "$Root\scripts\production-audit.py"
exit $LASTEXITCODE
