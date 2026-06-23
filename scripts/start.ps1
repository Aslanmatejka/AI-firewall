$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Host "Installing AI Firewall dependencies..."
pip install -r "$Root\python\requirements.txt" -q

# Stop stale instances that block port 9470 or hang the API
Get-CimInstance Win32_Process -Filter "name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*aishield*' } |
    ForEach-Object {
        Write-Host "Stopping existing AI Firewall (PID $($_.ProcessId))..."
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }

$portPid = (Get-NetTCPConnection -LocalPort 9470 -State Listen -ErrorAction SilentlyContinue |
    Select-Object -First 1).OwningProcess
if ($portPid) {
    Write-Host "Freeing port 9470 (PID $portPid)..."
    Stop-Process -Id $portPid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

Write-Host ""
Write-Host "Starting AI Firewall..."
Set-Location "$Root\python"
python -m aishield @args
