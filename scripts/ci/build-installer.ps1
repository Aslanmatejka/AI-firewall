# Builds AiShield.msi from a folder published by publish.ps1.
param(
    [Parameter(Mandatory)][string]$Staging,
    [Parameter(Mandatory)][string]$Output,
    [string]$Version
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $Root 'scripts\lib\Find-DotNet.ps1')
$DotNet = Find-DotNet
if (-not $DotNet) { $DotNet = 'dotnet' }

if (-not $Version) {
    $props = [xml](Get-Content (Join-Path $Root 'csharp\Directory.Build.props') -Raw)
    $Version = ($props.Project.PropertyGroup | Where-Object { $_.Version } | Select-Object -First 1).Version
}

$project = Join-Path $Root 'installer\AiShield.Installer.wixproj'
$Staging = (Resolve-Path $Staging).Path
& $DotNet build $project -c Release "-p:StagingDir=$Staging" "-p:ProductVersion=$Version" -v quiet
if ($LASTEXITCODE -ne 0) { throw 'Building the installer failed' }

New-Item -ItemType Directory -Force $Output | Out-Null
$msi = Join-Path $Output "AiShield-$Version.msi"
Copy-Item (Join-Path $Root 'installer\bin\Release\AiShield.msi') $msi -Force
Write-Host "Built $msi ($([math]::Round((Get-Item $msi).Length / 1MB)) MB)"
