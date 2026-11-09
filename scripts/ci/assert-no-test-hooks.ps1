# Fails if a Release build contains anything that lets a test answer the secure prompt.
param([Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'

$markers = 'TestHooks', 'consent-decision.txt', 'test-submit-request', 'AiShield.TamperProbe.exe', 'AISHIELD_TEST_HOOKS'
$files = Get-ChildItem $Path -Recurse -File -Include 'AiShield.*.dll', 'AiShield.*.exe'
if (-not $files) { throw "No AI Firewall binaries found in $Path" }

$hits = foreach ($file in $files) {
    $bytes = [IO.File]::ReadAllBytes($file.FullName)
    # Type names are UTF-8 in metadata; string literals are UTF-16 at either byte alignment.
    $views = @(
        [Text.Encoding]::UTF8.GetString($bytes),
        [Text.Encoding]::Unicode.GetString($bytes),
        [Text.Encoding]::Unicode.GetString($bytes, 1, $bytes.Length - 1)
    )
    foreach ($marker in $markers) {
        if ($views | Where-Object { $_.Contains($marker) }) { "$($file.Name): $marker" }
    }
}

if ($hits) { throw "Release build contains test hooks:`n$($hits -join "`n")" }
Write-Host "Checked $($files.Count) binaries: no test hooks"
