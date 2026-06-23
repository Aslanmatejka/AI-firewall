$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location (Join-Path $Root "python")
python -m aishield.enterprise.policy_server --host 127.0.0.1 --port 9480 --policy "$Root\config\enterprise-policy.json"
Pop-Location
