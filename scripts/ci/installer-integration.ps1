#Requires -RunAsAdministrator
# Checks the MSI end to end on a CI machine: install over what older versions and an attacker left
# behind, upgrade keeping policy, refuse a downgrade, and uninstall leaving nothing. CI machines only.
param(
    [Parameter(Mandatory)][string]$OldMsi,
    [Parameter(Mandatory)][string]$NewMsi,
    [Parameter(Mandatory)][string]$NewVersion,
    [Parameter(Mandatory)][string]$Probe,
    [Parameter(Mandatory)][string]$Artifacts
)
$ErrorActionPreference = 'Stop'
if (-not $env:CI) { throw 'This script is for CI machines.' }
New-Item -ItemType Directory -Force $Artifacts | Out-Null
$Artifacts = (Resolve-Path $Artifacts).Path
$OldMsi = (Resolve-Path $OldMsi).Path
$NewMsi = (Resolve-Path $NewMsi).Path
$Probe = (Resolve-Path $Probe).Path

$Install = Join-Path $env:ProgramFiles 'AiShield'
$Data = Join-Path $env:ProgramData 'AiShield'
$Database = Join-Path $Data 'policy.db'
$Shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\AI Firewall.lnk'
$Hosts = Join-Path $env:windir 'System32\drivers\etc\hosts'
$ExpectedImage = '"' + (Join-Path $Install 'service\AiShield.Service.exe') + '"'
$SquatTarget = Join-Path $env:TEMP 'aishield-squat-target'
$MySession = (Get-Process -Id $PID).SessionId
$Results = [System.Collections.Generic.List[object]]::new()

function Check([string]$Name, [scriptblock]$Test) {
    try {
        $detail = & $Test
        $Results.Add([pscustomobject]@{ Check = $Name; Result = 'PASS'; Detail = "$detail" })
        Write-Host "PASS  $Name  $detail" -ForegroundColor Green
    } catch {
        $Results.Add([pscustomobject]@{ Check = $Name; Result = 'FAIL'; Detail = "$_" })
        Write-Host "FAIL  $Name  $_" -ForegroundColor Red
    }
}

function Wait-Until([scriptblock]$Condition, [int]$Seconds, [string]$What) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $value = & $Condition
        if ($value) { return $value }
        Start-Sleep -Milliseconds 250
    }
    throw "Timed out after $Seconds s waiting for $What"
}

function Invoke-Msi([string[]]$Arguments, [string]$Log) {
    $process = Start-Process msiexec.exe -ArgumentList ($Arguments + @('/qn', '/l*v', "`"$(Join-Path $Artifacts $Log)`"")) -Wait -PassThru
    return $process.ExitCode
}

function Get-Product {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object DisplayName -eq 'AI Firewall'
}

function Get-ServiceInfo { Get-CimInstance Win32_Service -Filter "Name='AiShield'" }

# Admin-only SQL against the policy database, through Python's sqlite3, with the service stopped.
function Invoke-Sql([string]$Sql) {
    $script = "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchall(); c.commit(); print(r)"
    python -c $script $Database $Sql
}

function Test-LockedDown([string]$Path) {
    $item = Get-Item $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Path is a link" }
    $acl = Get-Acl $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin 'S-1-5-18', 'S-1-5-32-544') { throw "$Path is owned by $owner" }
    $who = $acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique
    $extra = $who | Where-Object { $_ -notin 'S-1-5-18', 'S-1-5-32-544' }
    if ($extra) { throw "$Path is also open to $($extra -join ', ')" }
}

$hostsBackup = Get-Content $Hosts -Raw
try {
    Write-Host '== What older versions and an attacker left behind'
    sc.exe create AiShield binPath= "$env:windir\System32\cmd.exe /c exit 0" start= demand DisplayName= 'Old AI Firewall' | Out-Host
    New-NetFirewallRule -DisplayName 'AiShield-Block-openai-com-1-2-3-4' -Direction Outbound -Action Block -RemoteAddress 1.2.3.4 | Out-Null
    Add-Content $Hosts "`r`n10.9.8.7 my-nas`r`n# AiShield blocked domains`r`n127.0.0.1 openai.com`r`n127.0.0.1 www.openai.com"
    & $Probe as-basic-user squat-junction $Data $SquatTarget | Out-Host
    if (-not ((Get-Item $Data -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Setup: the junction squat failed' }

    Write-Host '== Install the older version'
    Check 'installs over the leftovers' {
        $code = Invoke-Msi @('/i', "`"$OldMsi`"") 'install-old.log'
        if ($code -ne 0) { throw "msiexec exit code $code" }
        "installed $((Get-Product).DisplayVersion)"
    }

    Check 'service runs as LocalSystem from Program Files' {
        $service = Wait-Until { Get-ServiceInfo | Where-Object State -eq 'Running' } 30 'the service to run'
        if ($service.StartName -ne 'LocalSystem') { throw "runs as $($service.StartName)" }
        if ($service.PathName -ne $ExpectedImage) { throw "runs $($service.PathName)" }
        "PID $($service.ProcessId)"
    }

    Check 'service restarts after crashes and failed exits' {
        $failure = sc.exe qfailure AiShield | Out-String
        if (($failure | Select-String 'RESTART' -AllMatches).Matches.Count -lt 3) { throw "recovery actions: $failure" }
        $flag = Wait-Until { $f = sc.exe qfailureflag AiShield | Out-String; if ($f -match 'TRUE') { $f } } 30 'the failure flag'
        'three restart actions, failure flag on'
    }

    Check 'only administrators can control the service' {
        $sddl = (sc.exe sdshow AiShield | Out-String).Trim()
        # Only the access list matters here; the audit list after S: names Everyone by default.
        $dacl = ($sddl -split 'S:')[0]
        if ($dacl -notmatch '\(A;;CCLCSWLOCRRC;;;AU\)') { throw "unexpected permissions: $dacl" }
        if ($dacl -match ';;;(IU|WD|BU)\)') { throw "too open: $dacl" }
        $dacl
    }

    Check 'old service, firewall rule and hosts entries are gone' {
        if (Get-NetFirewallRule -DisplayName 'AiShield-Block-*' -ErrorAction SilentlyContinue) { throw 'old firewall rule still there' }
        $text = Get-Content $Hosts -Raw
        if ($text -match '(?m)^127\.0\.0\.1 (www\.)?openai\.com') { throw 'old hosts entries still there' }
        if ($text -notmatch '(?m)^10\.9\.8\.7 my-nas') { throw "the user's own hosts entry was removed" }
        'the user''s own hosts entry kept'
    }

    Check 'planted junction replaced, its target untouched' {
        Wait-Until { Test-Path $Database } 30 'the policy database' | Out-Null
        Test-LockedDown $Data
        if (Test-Path (Join-Path $SquatTarget 'policy.db')) { throw 'the service wrote through the junction' }
        if (-not (Test-Path (Join-Path $SquatTarget 'marker.txt'))) { throw 'the junction target was damaged' }
        'data folder is real and locked down'
    }

    Check 'service trusts its install folder' {
        $log = Join-Path $Data 'logs\service.log'
        if (Select-String -Path $log -Pattern 'Running from a folder ordinary users can change' -Quiet) { throw 'the service says its folder is unprotected' }
        if (Get-ChildItem $Install -Recurse -Filter *.pdb) { throw 'debug symbols were installed' }
        'no warning, no debug symbols'
    }

    Check 'desktop app starts and has a Start menu shortcut' {
        if (-not (Test-Path $Shortcut)) { throw 'no Start menu shortcut' }
        $app = Wait-Until { Get-Process AiShield.Dashboard -ErrorAction SilentlyContinue | Where-Object SessionId -eq $MySession } 30 'the desktop app'
        "PID $($app.Id)"
    }

    Check 'untrusted programs are refused' {
        $reply = & $Probe as-basic-user client status | ConvertFrom-Json
        if ($reply.error -ne 'untrusted-client') { throw "answered: $($reply | ConvertTo-Json -Compress)" }
        'refused'
    }

    Write-Host '== Change policy, then upgrade'
    Stop-Service AiShield
    Invoke-Sql "UPDATE settings SET value = 'block' WHERE key = 'camera_policy'" | Out-Null
    Invoke-Sql "INSERT OR REPLACE INTO app_policies (app_name, resource, action) VALUES ('Ollama', 'network', 'block')" | Out-Null
    Start-Service AiShield
    $oldPid = (Get-ServiceInfo).ProcessId

    Check 'upgrade installs the new version in place' {
        $code = Invoke-Msi @('/i', "`"$NewMsi`"") 'upgrade.log'
        if ($code -ne 0) { throw "msiexec exit code $code" }
        $products = @(Get-Product)
        if ($products.Count -ne 1) { throw "$($products.Count) AI Firewall entries in Apps" }
        if ($products[0].DisplayVersion -ne $NewVersion) { throw "version $($products[0].DisplayVersion)" }
        $service = Wait-Until { Get-ServiceInfo | Where-Object { $_.State -eq 'Running' -and $_.ProcessId -ne $oldPid } } 30 'the upgraded service'
        "now $NewVersion, PID $($service.ProcessId)"
    }

    Check 'upgrade keeps policy and data' {
        Stop-Service AiShield
        $camera = Invoke-Sql "SELECT value FROM settings WHERE key = 'camera_policy'"
        $app = Invoke-Sql "SELECT action FROM app_policies WHERE app_name = 'Ollama' AND resource = 'network'"
        Start-Service AiShield
        if ($camera -notmatch "'block'") { throw "camera policy is $camera" }
        if ($app -notmatch "'block'") { throw "Ollama rule is $app" }
        Test-LockedDown $Data
        'camera block and the Ollama rule survived'
    }

    Check 'desktop app comes back after the upgrade' {
        $app = Wait-Until { Get-Process AiShield.Dashboard -ErrorAction SilentlyContinue | Where-Object SessionId -eq $MySession } 30 'the desktop app'
        "PID $($app.Id)"
    }

    Check 'downgrade is refused' {
        $code = Invoke-Msi @('/i', "`"$OldMsi`"") 'downgrade.log'
        if ($code -eq 0) { throw 'the older version installed over the newer one' }
        if ((Get-Product).DisplayVersion -ne $NewVersion) { throw 'the installed version changed' }
        if ((Get-ServiceInfo).State -ne 'Running') { throw 'the service stopped' }
        "refused with exit code $code"
    }

    function Test-NothingLeft {
        if (Get-Service AiShield -ErrorAction SilentlyContinue) { throw 'service still registered' }
        if (Test-Path $Install) { throw 'install folder still there' }
        $leftover = Get-ChildItem $env:ProgramData -Directory -Filter 'AiShield*' -Force
        if ($leftover) { throw "still in ProgramData: $($leftover.Name -join ', ')" }
        if (Get-Process AiShield.* -ErrorAction SilentlyContinue) { throw 'AI Firewall processes still running' }
        if ((logman query -ets) -match 'AiShield') { throw 'event tracing session left behind' }
        if (Get-Product) { throw 'still listed in Apps' }
        if (Test-Path $Shortcut) { throw 'Start menu shortcut still there' }
        if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\AiShield') { throw 'event log source still registered' }
        if (Get-ChildItem 'C:\Users\*\AppData\Local\AiShield' -Directory -ErrorAction SilentlyContinue) { throw 'desktop app logs left in a profile' }
    }

    Write-Host '== Uninstall'
    Check 'uninstall leaves nothing behind' {
        $code = Invoke-Msi @('/x', "`"$NewMsi`"") 'uninstall.log'
        if ($code -ne 0) { throw "msiexec exit code $code" }
        Test-NothingLeft
        if (-not (Test-Path (Join-Path $SquatTarget 'marker.txt'))) { throw 'uninstall followed the old junction' }
        'clean'
    }

    Write-Host '== Install over a planted data folder'
    & $Probe as-basic-user squat-folder $Data | Out-Host
    Check 'planted folder moved aside, real data folder created' {
        $code = Invoke-Msi @('/i', "`"$NewMsi`"") 'install-over-squat.log'
        if ($code -ne 0) { throw "msiexec exit code $code" }
        Wait-Until { (Test-Path $Database) -and (Get-Item $Database).Length -gt 0 } 30 'the policy database' | Out-Null
        Test-LockedDown $Data
        # The service has the database open, so read it the way SQLite allows.
        $stream = [IO.File]::Open($Database, 'Open', 'Read', 'ReadWrite')
        try { $bytes = [byte[]]::new(15); [void]$stream.Read($bytes, 0, 15) } finally { $stream.Dispose() }
        $header = [Text.Encoding]::ASCII.GetString($bytes)
        if ($header -ne 'SQLite format 3') { throw "policy.db isn't the service's database" }
        $aside = Get-ChildItem $env:ProgramData -Directory -Filter 'AiShield.untrusted-*' -Force
        if (-not $aside) { throw 'the planted folder was not moved aside' }
        "moved aside to $($aside.Name)"
    }

    Check 'uninstall removes the planted folder too' {
        $code = Invoke-Msi @('/x', "`"$NewMsi`"") 'uninstall-after-squat.log'
        if ($code -ne 0) { throw "msiexec exit code $code" }
        Test-NothingLeft
        'clean'
    }
} finally {
    Set-Content $Hosts $hostsBackup -NoNewline
    Remove-Item $SquatTarget -Recurse -Force -ErrorAction SilentlyContinue
}

$Results | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Out-File (Join-Path $Artifacts 'results.txt')
$Results | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
$failed = @($Results | Where-Object Result -eq 'FAIL').Count
if ($failed) { throw "$failed check(s) failed" }
Write-Host "All $($Results.Count) checks passed" -ForegroundColor Green
