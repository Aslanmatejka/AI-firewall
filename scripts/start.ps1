$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

python -c "import fastapi, psutil, uvicorn" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Dependencies are missing. Run .\scripts\install.ps1 first." -ForegroundColor Red
    exit 1
}

Write-Host "Starting AI Firewall..."
Set-Location (Join-Path $Root "python")
python -m aishield --open @args
exit $LASTEXITCODE
