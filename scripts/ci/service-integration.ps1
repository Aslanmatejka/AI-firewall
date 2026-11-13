#Requires -RunAsAdministrator
# Installs the CiTesting build as a real SYSTEM service, attacks it from a non-admin token, checks every
# M2 exit criterion, then uninstalls it. For CI machines only.
param(
    [Parameter(Mandatory)][string]$Staging,
    [Parameter(Mandatory)][string]$Artifacts
)
$ErrorActionPreference = 'Stop'
$Staging = (Resolve-Path $Staging).Path
New-Item -ItemType Directory -Force $Artifacts | Out-Null
$Artifacts = (Resolve-Path $Artifacts).Path

$Install = Join-Path $env:ProgramFiles 'AiShield'
$Data = Join-Path $env:ProgramData 'AiShield'
$TestDir = Join-Path $Data 'test'
$Probe = Join-Path $Staging 'probe\AiShield.TamperProbe.exe'
$TrustedProbe = Join-Path $Install 'dashboard\AiShield.TamperProbe.exe'
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

# Runs one request as the trusted desktop app would: from the install folder, without admin rights.
function Invoke-Client([string]$Op, [hashtable]$Arguments) {
    $argv = @('as-basic-user', 'client', $Op)
    if ($Arguments) { $argv += ($Arguments | ConvertTo-Json -Compress) }
    $output = & $TrustedProbe @argv 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Client $Op got no answer (exit $LASTEXITCODE): $output" }
    return ($output | Select-Object -Last 1) | ConvertFrom-Json
}

# Sends a request that opens the secure prompt. After a refusal the service makes the next prompt wait,
# longer each time, and answers "busy" until then; that's a defense, so wait it out rather than fail.
function Invoke-Prompted([string]$Op, [hashtable]$Arguments) {
    $deadline = (Get-Date).AddSeconds(90)
    do {
        $reply = Invoke-Client $Op $Arguments
        if ($reply.consent -ne 'busy') { return $reply }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw "the service stayed busy for 90 s"
}

function Set-ConsentAnswer([string]$Answer) {
    New-Item -ItemType Directory -Force $TestDir | Out-Null
    Set-Content (Join-Path $TestDir 'consent-decision.txt') $Answer
}

function Get-Status { (Invoke-Client 'status').data }

Write-Host '== Environment'
Write-Host "Runner session: $MySession"
query user 2>&1 | Out-Host
whoami /groups | Select-String 'Mandatory' | Out-Host

Write-Host '== Install'
& (Join-Path $PSScriptRoot 'install-service.ps1') -Staging $Staging
Copy-Item $Probe $TrustedProbe

Check 'service runs as LocalSystem' {
    $service = Get-CimInstance Win32_Service -Filter "Name='AiShield'"
    if ($service.StartName -ne 'LocalSystem') { throw "runs as $($service.StartName)" }
    "PID $($service.ProcessId)"
}

Check 'service trusts its install folder' {
    $log = Join-Path $Data 'logs\service.log'
    Wait-Until { Test-Path $log } 20 'the service log' | Out-Null
    Start-Sleep -Seconds 2
    if (Select-String -Path $log -Pattern 'Running from a folder ordinary users can change' -Quiet) { throw 'the service says its folder is unprotected' }
    'no warning in the log'
}

Check 'data folder is SYSTEM and Administrators only' {
    $who = (Get-Acl $Data).Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique
    $unexpected = $who | Where-Object { $_ -notin 'S-1-5-18', 'S-1-5-32-544' }
    if ($unexpected) { throw "also open to $($unexpected -join ', ')" }
    $who -join ', '
}

Check 'desktop app starts in the signed-in session' {
    $app = Wait-Until { Get-Process AiShield.Dashboard -ErrorAction SilentlyContinue | Where-Object SessionId -eq $MySession } 30 'the desktop app'
    "PID $($app.Id) in session $MySession"
}

Check 'killed desktop app returns within 10 seconds' {
    $old = Get-Process AiShield.Dashboard | Where-Object SessionId -eq $MySession | Select-Object -First 1
    $timer = [Diagnostics.Stopwatch]::StartNew()
    Stop-Process -Id $old.Id -Force
    $new = Wait-Until { Get-Process AiShield.Dashboard -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $MySession -and $_.Id -ne $old.Id } } 15 'a restarted desktop app'
    if ($timer.Elapsed.TotalSeconds -gt 10) { throw "took $([int]$timer.Elapsed.TotalSeconds) s" }
    "back as PID $($new.Id) after $([math]::Round($timer.Elapsed.TotalSeconds, 1)) s"
}

Check 'probe really runs without admin rights' {
    $raw = & $Probe as-basic-user whoami 2>&1
    if ($LASTEXITCODE -ne 0) { throw "the probe failed: $raw" }
    $me = $raw | ConvertFrom-Json
    if ($me.admin -ne $false -or $me.integrity -ne 8192) { throw "admin=$($me.admin) integrity=$($me.integrity)" }
    "admin=$($me.admin), integrity=0x$('{0:x}' -f $me.integrity)"
}

Check 'every tamper attempt fails without admin rights' {
    Set-ConsentAnswer 'deny 3'
    $output = & $Probe as-basic-user attack $Install 2>&1
    $code = $LASTEXITCODE
    $output | Set-Content (Join-Path $Artifacts 'tamper-probe.txt')
    $output | Out-Host
    $blocked = @($output | Where-Object { $_ -like 'BLOCKED*' }).Count
    if ($code -ne 0 -or $blocked -lt 10) { throw "exit $code, $blocked blocked: $((@($output | Where-Object { $_ -notlike 'BLOCKED*' })) -join '; ')" }
    "$(@($output | Where-Object { $_ -like 'BLOCKED*' }).Count) attempts blocked"
}

Check 'process guard proves it is active' {
    $guard = Wait-Until { (Get-Status).guards | Where-Object { $_.name -eq 'AI apps' -and $_.state -eq 'active' } } 30 'the process guard to become active'
    $guard.reason
}

Check 'AI app detected by program name' {
    $folder = Join-Path $env:TEMP 'aishield-fake-ollama'
    New-Item -ItemType Directory -Force $folder | Out-Null
    $fake = Join-Path $folder 'ollama.exe'
    Copy-Item (Join-Path $env:windir 'System32\PING.EXE') $fake -Force
    $process = Start-Process $fake -ArgumentList '-n', '60', '127.0.0.1' -WindowStyle Hidden -PassThru
    try {
        $found = Wait-Until { (Get-Status).ai_processes | Where-Object { $_.ai_type -eq 'Ollama' -and $_.pid -eq $process.Id } } 20 'Ollama in the status'
        "PID $($found.pid), $($found.detected_by)"
    } finally { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
}

Check 'command-line agent detected through node' {
    $folder = Join-Path $env:TEMP 'aishield-agent\node_modules\@anthropic-ai\claude-code'
    New-Item -ItemType Directory -Force $folder | Out-Null
    $script = Join-Path $folder 'cli.js'
    Set-Content $script 'setTimeout(() => {}, 60000);'
    $process = Start-Process node -ArgumentList "`"$script`"" -WindowStyle Hidden -PassThru
    try {
        $found = Wait-Until { (Get-Status).ai_processes | Where-Object { $_.ai_type -eq 'Claude Code' } } 20 'Claude Code in the status'
        "PID $($found.pid), $($found.detected_by)"
    } finally { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
}

Check 'tightening applies without a prompt' {
    $reply = Invoke-Client 'set-global-policy' @{ key = 'camera_policy'; value = 'block' }
    if (-not $reply.ok -or $reply.consent -ne 'not-needed') { throw "ok=$($reply.ok) consent=$($reply.consent)" }
    if ((Invoke-Client 'config').data.camera_policy -ne 'block') { throw 'camera policy unchanged' }
    'camera blocked with no prompt'
}

Check 'weakening needs the secure prompt, and a refusal changes nothing' {
    Set-ConsentAnswer 'deny 3'
    $reply = Invoke-Prompted 'set-global-policy' @{ key = 'network_policy'; value = 'allow' }
    if ($reply.ok -or $reply.consent -ne 'denied') { throw "ok=$($reply.ok) consent=$($reply.consent)" }
    $policy = (Invoke-Client 'config').data.network_policy
    if ($policy -eq 'allow') { throw 'network policy was relaxed anyway' }
    Start-Sleep -Seconds 4
    "refused, network policy still $policy"
}

Check 'allowing a request needs the secure prompt' {
    $submitted = Invoke-Client 'test-submit-request' @{ app_name = 'ProbeAI'; resource_type = 'network'; target = 'probe.example' }
    $id = $submitted.data.id
    Set-ConsentAnswer 'deny 3'
    $refused = Invoke-Prompted 'review' @{ id = $id }
    if ($refused.ok) { throw 'allowed without confirmation' }
    if (-not ((Get-Status).pending_requests | Where-Object id -eq $id)) { throw 'request vanished after a refusal' }
    Start-Sleep -Seconds 4
    Set-ConsentAnswer 'allow 3'
    $allowed = Invoke-Prompted 'review' @{ id = $id }
    if (-not $allowed.ok -or $allowed.consent -ne 'approved') { throw "ok=$($allowed.ok) consent=$($allowed.consent)" }
    if ((Get-Status).pending_requests | Where-Object id -eq $id) { throw 'still pending after approval' }
    "request $id refused, then approved on the prompt"
}

Check 'secure prompt is out of reach of the user''s programs' {
    Start-Sleep -Seconds 4
    Invoke-Client 'lockdown-on' | Out-Null
    Remove-Item (Join-Path $TestDir 'consent-shown.txt') -ErrorAction SilentlyContinue
    Set-ConsentAnswer 'deny 20'
    $out = Join-Path $Artifacts 'lockdown-off.txt'
    $pending = Start-Process $TrustedProbe -ArgumentList 'as-basic-user', 'client', 'lockdown-off' -PassThru -NoNewWindow -RedirectStandardOutput $out
    $shown = Wait-Until { Get-Content (Join-Path $TestDir 'consent-shown.txt') -ErrorAction SilentlyContinue } 30 'the secure prompt'
    $desktop = $shown[0]
    Start-Sleep -Seconds 2
    $isolation = & $Probe as-basic-user consent-isolation $desktop 2>&1
    $isolation | Set-Content (Join-Path $Artifacts 'consent-isolation.txt')
    $isolation | Out-Host
    $isolated = $LASTEXITCODE -eq 0
    $pending.WaitForExit(60000) | Out-Null
    Copy-Item (Join-Path $TestDir 'consent.png') $Artifacts -ErrorAction SilentlyContinue
    if (-not $isolated) { throw ($isolation | Where-Object { $_ -like 'ALLOWED*' }) -join '; ' }
    if (-not (Get-Status).lockdown) { throw 'lockdown was turned off without confirmation' }
    "prompt on desktop $desktop could not be reached; lockdown stayed on"
}

Check 'a connection flood from an unknown program doesn''t lock out the desktop app' {
    $out = Join-Path $Artifacts 'flood.txt'
    $flood = Start-Process $Probe -ArgumentList 'as-basic-user', 'flood', '300', '25' -PassThru -NoNewWindow -RedirectStandardOutput $out
    Start-Sleep -Seconds 8
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $reply = Invoke-Client 'status'
    $elapsed = [math]::Round($timer.Elapsed.TotalSeconds, 1)
    if (-not $reply.ok) { throw 'the desktop app got no answer during the flood' }
    $servicePid = (Get-CimInstance Win32_Service -Filter "Name='AiShield'").ProcessId
    $memory = [math]::Round((Get-Process -Id $servicePid).WorkingSet64 / 1MB)
    $flood.WaitForExit(60000) | Out-Null
    Get-Process AiShield.TamperProbe -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if ($memory -gt 400) { throw "service memory reached $memory MB" }
    "answered in $elapsed s during the flood; service at $memory MB; $((Get-Content $out -Raw).Trim())"
}

Check 'squatting the old fixed pipe name doesn''t stop the service' {
    Start-Process $Probe -ArgumentList 'as-basic-user', 'hold-pipe', 'AiShield.v1', '20' -NoNewWindow | Out-Null
    Start-Sleep -Seconds 2
    Restart-Service AiShield
    Wait-Until { try { (Invoke-Client 'hello').ok } catch { $false } } 30 'the restarted service to answer' | Out-Null
    # The probe's launcher and its limited-token child are both test processes.
    Get-Process AiShield.TamperProbe -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $name = (Get-ItemProperty 'HKLM:\SOFTWARE\AiShield').PipeName
    "serving on $name"
}

Check 'service restarts after being killed, with policy intact' {
    $before = (Get-CimInstance Win32_Service -Filter "Name='AiShield'").ProcessId
    taskkill /F /PID $before | Out-Host
    $after = Wait-Until {
        $service = Get-CimInstance Win32_Service -Filter "Name='AiShield'"
        if ($service.State -eq 'Running' -and $service.ProcessId -ne $before -and $service.ProcessId -ne 0) { $service.ProcessId }
    } 45 'the service to restart'
    Wait-Until { try { (Invoke-Client 'hello').ok } catch { $false } } 30 'the restarted service to answer' | Out-Null
    if ((Invoke-Client 'config').data.camera_policy -ne 'block') { throw 'policy lost on restart' }
    if (-not (Get-Status).lockdown) { throw 'lockdown lost on restart' }
    "PID $before replaced by $after"
}

Write-Host '== Logs'
Copy-Item (Join-Path $Data 'logs\service.log') $Artifacts -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'AiShield' } -MaxEvents 50 -ErrorAction SilentlyContinue |
    Format-List TimeCreated, LevelDisplayName, Message | Out-File (Join-Path $Artifacts 'event-log.txt')

Write-Host '== Uninstall'
Check 'uninstall leaves nothing running or installed' {
    & (Join-Path $PSScriptRoot 'uninstall-service.ps1') -Install $Install -RemoveData
    if (Get-Service AiShield -ErrorAction SilentlyContinue) { throw 'service still registered' }
    if (Test-Path $Install) { throw 'install folder still there' }
    if (Test-Path $Data) { throw 'data folder still there' }
    $running = Get-Process AiShield.* -ErrorAction SilentlyContinue | Where-Object Name -ne 'AiShield.TamperProbe'
    if ($running) { throw "AI Firewall processes still running: $($running.Name -join ', ')" }
    if ((logman query -ets) -match 'AiShield') { throw 'event tracing session left behind' }
    if (Test-Path 'HKLM:\SOFTWARE\AiShield') { throw 'registry key still there' }
    'clean'
}

$Results | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Out-File (Join-Path $Artifacts 'results.txt')
$Results | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
$failed = @($Results | Where-Object Result -eq 'FAIL').Count
if ($failed) { throw "$failed check(s) failed" }
Write-Host "All $($Results.Count) checks passed" -ForegroundColor Green
