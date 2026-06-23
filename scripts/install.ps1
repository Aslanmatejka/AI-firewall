$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host "=== AI Firewall Setup ===" -ForegroundColor Cyan

# Config to ProgramData (non-admin friendly copy for user AppData too)
$UserData = Join-Path $env:APPDATA "AiShield"
New-Item -ItemType Directory -Force -Path $UserData | Out-Null

Write-Host "Installing Python dependencies..."
pip install -r (Join-Path $Root "python\requirements.txt")

Write-Host "Running tests..."
Push-Location (Join-Path $Root "python")
python -m unittest discover -s tests -v
Pop-Location

$DotNet = "$env:ProgramFiles\dotnet\dotnet.exe"
if (Test-Path $DotNet) {
    Write-Host "Building C# solution..."
    & $DotNet build (Join-Path $Root "csharp\AiShield.sln") -c Release
}

Write-Host ""
Write-Host "Setup complete. Start with:" -ForegroundColor Green
Write-Host "  .\scripts\start.ps1"
Write-Host "  .\scripts\launch-dashboard.ps1"
