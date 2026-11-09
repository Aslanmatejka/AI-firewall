# Finds a dotnet host that has the SDK pinned in global.json (per-user install first).
function Find-DotNet {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA "Microsoft\dotnet\dotnet.exe"),
        (Join-Path $env:ProgramFiles "dotnet\dotnet.exe")
    )
    foreach ($candidate in $candidates) {
        if (-not (Test-Path $candidate)) { continue }
        if (& $candidate --list-sdks | Where-Object { $_ -match '^10\.' }) {
            $env:DOTNET_ROOT = Split-Path -Parent $candidate
            return $candidate
        }
    }
    return $null
}
