#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Proj = Join-Path $Root "aishield_minifilter.vcxproj"
$OutDir = Join-Path $Root "x64\Release"
$Sys = Join-Path $OutDir "aishield_minifilter.sys"
$Inf = Join-Path $Root "aishield_minifilter.inf"

Write-Host "=== AI Firewall Minifilter Build ===" -ForegroundColor Cyan

$msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2>$null | Select-Object -First 1

if (-not $msbuild) {
    Write-Host "MSBuild not found. Install Visual Studio + WDK." -ForegroundColor Red
    exit 1
}

& $msbuild $Proj /p:Configuration=Release /p:Platform=x64 /t:Build
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed. Ensure Windows Driver Kit (WDK) is installed." -ForegroundColor Red
    exit 1
}

if (Test-Path $Sys) {
    Write-Host "Built: $Sys" -ForegroundColor Green
} else {
    Write-Host "Build finished but .sys not found at $Sys" -ForegroundColor Yellow
    Get-ChildItem -Recurse $Root -Filter "*.sys" | ForEach-Object { Write-Host "  Found: $($_.FullName)" }
}
