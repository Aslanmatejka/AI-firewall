$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$DotNet = "$env:ProgramFiles\dotnet\dotnet.exe"

if (-not (Test-Path $DotNet)) {
    Write-Host "ERROR: .NET SDK not found. Install from https://dotnet.microsoft.com/download" -ForegroundColor Red
    exit 1
}

Write-Host "Building AI Firewall Dashboard..." -ForegroundColor Cyan
& $DotNet build "$Root\csharp\AiShield.sln" -c Release -v q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$Exe = "$Root\csharp\AiShield.Dashboard\bin\Release\net8.0-windows\AiShield.Dashboard.exe"
Write-Host "Launching dashboard..." -ForegroundColor Green
Start-Process $Exe
