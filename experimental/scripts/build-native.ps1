#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Native = Join-Path $Root "native\aishield-native"

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "Rust toolchain not found. Install from https://rustup.rs" -ForegroundColor Yellow
    exit 1
}

Write-Host "Building aishield-native..." -ForegroundColor Cyan
Push-Location $Native
cargo build --release
Pop-Location

$Dll = Join-Path $Native "target\release\aishield_native.dll"
if (Test-Path $Dll) {
    Write-Host "Built: $Dll" -ForegroundColor Green
} else {
    Write-Host "Build completed but DLL not found at expected path." -ForegroundColor Yellow
}
