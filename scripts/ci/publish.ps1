# Publishes the service, desktop app and secure prompt self-contained, in the installed folder layout.
# CiTesting builds include the hooks CI needs to answer the secure prompt, plus the tamper probe.
param(
    [Parameter(Mandatory)][ValidateSet('Release', 'CiTesting')][string]$Configuration,
    [Parameter(Mandatory)][string]$Output
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $Root 'scripts\lib\Find-DotNet.ps1')
$DotNet = Find-DotNet
if (-not $DotNet) { $DotNet = 'dotnet' }

if (Test-Path $Output) { Remove-Item $Output -Recurse -Force }

$apps = [ordered]@{ service = 'AiShield.Service'; dashboard = 'AiShield.Dashboard'; consent = 'AiShield.Consent' }
foreach ($folder in $apps.Keys) {
    $project = Join-Path $Root "csharp\$($apps[$folder])\$($apps[$folder]).csproj"
    & $DotNet publish $project -c $Configuration -r win-x64 --self-contained -o (Join-Path $Output $folder) -v quiet
    if ($LASTEXITCODE -ne 0) { throw "Publishing $($apps[$folder]) failed" }
}

New-Item -ItemType Directory -Force (Join-Path $Output 'config') | Out-Null
Copy-Item (Join-Path $Root 'config\default.json') (Join-Path $Output 'config\default.json')

if ($Configuration -eq 'CiTesting') {
    $probe = Join-Path $Root 'csharp\AiShield.TamperProbe\AiShield.TamperProbe.csproj'
    & $DotNet publish $probe -c $Configuration -r win-x64 -o (Join-Path $Output 'probe') -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Publishing the tamper probe failed' }
}
Write-Host "Published $Configuration build to $Output"
