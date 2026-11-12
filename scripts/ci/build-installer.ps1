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
# Rebuild every time: the version is a property, and MSBuild doesn't notice when only that changes.
& $DotNet build $project -c Release -t:Rebuild "-p:StagingDir=$Staging" "-p:ProductVersion=$Version" -v quiet
if ($LASTEXITCODE -ne 0) { throw 'Building the installer failed' }

New-Item -ItemType Directory -Force $Output | Out-Null
$msi = Join-Path $Output "AiShield-$Version.msi"
Copy-Item (Join-Path $Root 'installer\bin\Release\AiShield.msi') $msi -Force

# Read the version back from the package, so a stale build can't pass as the requested one.
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($msi, 0))
$query = "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'ProductVersion'"
$view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, @($query))
$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
$record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
$built = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(1))
$view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)
[void][Runtime.InteropServices.Marshal]::ReleaseComObject($database)
if ($built -ne $Version) { throw "The installer says version $built, expected $Version" }
Write-Host "Built $msi ($([math]::Round((Get-Item $msi).Length / 1MB)) MB)"
