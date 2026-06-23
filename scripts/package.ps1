#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Out = Join-Path $Root "dist\AiShield"
$Zip = Join-Path $Root "dist\AiShield-portable.zip"

Write-Host "=== AI Firewall Package Builder ===" -ForegroundColor Cyan

if (Test-Path $Out) { Remove-Item $Out -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Out | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $Out "scripts") | Out-Null

Copy-Item (Join-Path $Root "python\aishield") (Join-Path $Out "python\aishield") -Recurse
Copy-Item (Join-Path $Root "python\requirements.txt") (Join-Path $Out "python\requirements.txt")
Copy-Item (Join-Path $Root "config") (Join-Path $Out "config") -Recurse
Copy-Item (Join-Path $Root "scripts\*.ps1") (Join-Path $Out "scripts")

$DotNet = "$env:ProgramFiles\dotnet\dotnet.exe"
if (Test-Path $DotNet) {
    & $DotNet publish (Join-Path $Root "csharp\AiShield.Dashboard\AiShield.Dashboard.csproj") `
        -c Release -o (Join-Path $Out "dashboard") --self-contained false
    & $DotNet publish (Join-Path $Root "csharp\AiShield.Service\AiShield.Service.csproj") `
        -c Release -o (Join-Path $Out "service") --self-contained false
}

@"
AI Firewall Portable Package
============================
1. pip install -r python/requirements.txt
2. cd python && python -m aishield
3. Or run scripts/install-service.ps1 as Administrator
4. Dashboard: http://127.0.0.1:9470
"@ | Set-Content (Join-Path $Out "README.txt")

New-Item -ItemType Directory -Force -Path (Join-Path $Root "dist") | Out-Null
Compress-Archive -Path $Out -DestinationPath $Zip -Force
Write-Host "Created: $Zip" -ForegroundColor Green
Write-Host "Staged:  $Out"
