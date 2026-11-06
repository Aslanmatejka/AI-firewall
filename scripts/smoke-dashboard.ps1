# Launches the real desktop app and fails if it crashes, shows no window or logs an error.
param(
    [int]$Seconds = 30,
    [string]$Exe,
    [string]$ScreenshotPath
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
. (Join-Path $PSScriptRoot "lib\Find-DotNet.ps1")
$null = Find-DotNet

if (-not $Exe) {
    $Exe = Join-Path $Root "csharp\AiShield.Dashboard\bin\Release\net10.0-windows\AiShield.Dashboard.exe"
}

Add-Type -AssemblyName System.Drawing
Add-Type -Namespace Smoke -Name Native -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool PrintWindow(System.IntPtr hwnd, System.IntPtr hdc, uint flags);
[System.Runtime.InteropServices.DllImport("user32.dll")]
public static extern bool GetWindowRect(System.IntPtr hwnd, out RECT rect);
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct RECT { public int Left, Top, Right, Bottom; }
'@

# Captures only this app's window, never the rest of the screen.
function Save-WindowImage([System.IntPtr]$Handle, [string]$Path) {
    $rect = New-Object Smoke.Native+RECT
    [void][Smoke.Native]::GetWindowRect($Handle, [ref]$rect)
    $bitmap = New-Object System.Drawing.Bitmap ($rect.Right - $rect.Left), ($rect.Bottom - $rect.Top)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $hdc = $graphics.GetHdc()
    [void][Smoke.Native]::PrintWindow($Handle, $hdc, 2)
    $graphics.ReleaseHdc($hdc)
    $graphics.Dispose()
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    $bitmap.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bitmap.Dispose()
}

$LogFile = Join-Path $env:LOCALAPPDATA "AiShield\dashboard.log"
$LogBefore = if (Test-Path $LogFile) { (Get-Item $LogFile).Length } else { 0 }

$Process = Start-Process -FilePath $Exe -PassThru
try {
    Start-Sleep -Seconds $Seconds
    if ($Process.HasExited) { throw "The dashboard exited early with code $($Process.ExitCode)" }
    $Process.Refresh()
    if ($Process.MainWindowHandle -eq [System.IntPtr]::Zero) { throw "The dashboard is running but shows no window" }
    if ($ScreenshotPath) { Save-WindowImage $Process.MainWindowHandle $ScreenshotPath }
} finally {
    if (-not $Process.HasExited) {
        [void]$Process.CloseMainWindow()
        if (-not $Process.WaitForExit(5000)) { $Process.Kill() }
    }
}

if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt $LogBefore) {
    $stream = [System.IO.File]::OpenRead($LogFile)
    [void]$stream.Seek($LogBefore, [System.IO.SeekOrigin]::Begin)
    $reader = New-Object System.IO.StreamReader $stream
    $newErrors = $reader.ReadToEnd()
    $reader.Dispose()
    throw "The dashboard logged errors:`n$newErrors"
}
Write-Host "Dashboard ran for $Seconds seconds without a crash or logged error." -ForegroundColor Green
