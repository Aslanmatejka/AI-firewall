$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
. (Join-Path $PSScriptRoot "lib\Find-DotNet.ps1")

Write-Host "=== AI Firewall Setup ===" -ForegroundColor Cyan

Write-Host "Installing Python dependencies..."
python -m pip install -r (Join-Path $Root "python\requirements-dev.txt")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running tests..."
Push-Location (Join-Path $Root "python")
try {
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

$DotNet = Find-DotNet
if ($DotNet) {
    Write-Host "Building C# solution..."
    Push-Location $Root
    try {
        & $DotNet build "csharp\AiShield.sln" -c Release
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }
} else {
    Write-Host ".NET 10 SDK not found, skipping the desktop app build." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Setup complete. Start with:" -ForegroundColor Green
Write-Host "  .\scripts\start.ps1"
Write-Host "  .\scripts\launch-dashboard.ps1"
