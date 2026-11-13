#Requires -RunAsAdministrator
# Installs a published build as the AiShield Windows service. For CI machines only: it replaces any
# existing installation. The real installer arrives in M3.
param(
    [Parameter(Mandatory)][string]$Staging,
    [string]$Install = (Join-Path $env:ProgramFiles 'AiShield')
)
$ErrorActionPreference = 'Stop'
if (-not $env:CI) { throw 'This script is for CI machines. Set CI=1 only if you really mean to install the service here.' }

& (Join-Path $PSScriptRoot 'uninstall-service.ps1') -Install $Install

# Program Files lets ordinary users read and run files but not change them. The service checks this.
Copy-Item $Staging $Install -Recurse
Remove-Item (Join-Path $Install 'probe') -Recurse -Force -ErrorAction SilentlyContinue

$binary = Join-Path $Install 'service\AiShield.Service.exe'
sc.exe create AiShield binPath= "`"$binary`"" start= auto obj= LocalSystem DisplayName= 'AI Firewall' | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Creating the service failed' }
sc.exe description AiShield 'Controls what AI software can access on this PC' | Out-Null
# Signed-in users may check whether the service is running, which the desktop app uses to spot an
# impostor pipe. Only SYSTEM and administrators may start, stop, change or delete it.
sc.exe sdset AiShield 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)' | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Setting service permissions failed' }
# Restart after a crash, including exits with an error code.
sc.exe failure AiShield reset= 86400 actions= restart/2000/restart/5000/restart/10000 | Out-Host
sc.exe failureflag AiShield 1 | Out-Host
# Only the privileges the service uses, as the MSI sets them.
sc.exe privs AiShield SeTcbPrivilege/SeAssignPrimaryTokenPrivilege/SeIncreaseQuotaPrivilege/SeChangeNotifyPrivilege/SeCreateGlobalPrivilege/SeSystemProfilePrivilege | Out-Host

Start-Service AiShield
(Get-Service AiShield).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Write-Host "AiShield service installed from $Install and running"
