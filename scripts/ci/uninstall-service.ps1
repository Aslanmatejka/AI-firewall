#Requires -RunAsAdministrator
# Removes the AiShield service and its files. Leaves the data folder unless -RemoveData is given.
param(
    [string]$Install = (Join-Path $env:ProgramFiles 'AiShield'),
    [switch]$RemoveData
)
$ErrorActionPreference = 'Stop'

if (Get-Service AiShield -ErrorAction SilentlyContinue) {
    Stop-Service AiShield -Force -ErrorAction SilentlyContinue
    (Get-Service AiShield).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    sc.exe delete AiShield | Out-Null
    for ($i = 0; $i -lt 20 -and (Get-Service AiShield -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
}

# The desktop app runs in each user's session, and the prompt may still be open.
Get-Process AiShield.Dashboard, AiShield.Consent -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

if (Test-Path $Install) { Remove-Item $Install -Recurse -Force }
if ($RemoveData) {
    Remove-Item 'HKLM:\SOFTWARE\AiShield' -Recurse -Force -ErrorAction SilentlyContinue
    $data = Join-Path $env:ProgramData 'AiShield'
    if (Test-Path $data) { Remove-Item $data -Recurse -Force }
}
Write-Host 'AiShield service removed'
