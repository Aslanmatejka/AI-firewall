# Opens the web dashboard with a fresh one-time sign-in link.
$ErrorActionPreference = "Stop"

$TokenFile = Join-Path $env:APPDATA "AiShield\api-token.json"
if (-not (Test-Path $TokenFile)) {
    Write-Host "AI Firewall isn't running. Start it with .\scripts\start.ps1" -ForegroundColor Red
    exit 1
}

$Session = Get-Content $TokenFile -Raw | ConvertFrom-Json
try {
    $Response = Invoke-RestMethod -Method Post `
        -Uri "http://127.0.0.1:$($Session.port)/api/login-code" `
        -Headers @{ Authorization = "Bearer $($Session.token)" }
} catch {
    Write-Host "AI Firewall isn't responding. Start it with .\scripts\start.ps1" -ForegroundColor Red
    exit 1
}
Start-Process $Response.url
