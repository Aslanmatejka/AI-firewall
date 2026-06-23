#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ConfigPath = Join-Path $Root "config\default.json"
$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$Domains = $Config.ai_domains

Write-Host "=== AI Firewall Browser GPO Helper ===" -ForegroundColor Cyan
Write-Host "Blocks AI domains via Windows hosts file (machine-wide)."

$hostsPath = "$env:Windir\System32\drivers\etc\hosts"
$markerStart = "# AI-FIREWALL-START"
$markerEnd = "# AI-FIREWALL-END"

$content = Get-Content $hostsPath -ErrorAction SilentlyContinue
$filtered = @()
$skip = $false
foreach ($line in $content) {
    if ($line -eq $markerStart) { $skip = $true; continue }
    if ($line -eq $markerEnd) { $skip = $false; continue }
    if (-not $skip) { $filtered += $line }
}

$block = @($markerStart)
foreach ($d in $Domains) {
    $block += "0.0.0.0 $d"
    $block += "0.0.0.0 www.$d"
}
$block += $markerEnd

$filtered + $block | Set-Content $hostsPath -Encoding ASCII
Write-Host "Added $($Domains.Count) AI domains to hosts file." -ForegroundColor Green

Write-Host ""
Write-Host "Enterprise browser extension blocking (manual GPO):" -ForegroundColor Yellow
Write-Host "  Chrome:  Computer Config > Admin Templates > Google > Extensions > Configure extension install blocklist"
Write-Host "  Edge:    Computer Config > Admin Templates > Microsoft Edge > Extensions > Block extensions"
Write-Host "  Patterns from config ai_extension_patterns in $ConfigPath"

Write-Host ""
Write-Host "Optional Chrome blocklist JSON example:"
$patterns = $Config.ai_extension_patterns | ForEach-Object { "*$_*" }
$patterns | ConvertTo-Json | Write-Host
