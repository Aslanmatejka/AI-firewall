# AI Firewall — Architecture

Technical overview for developers and IT admins. End users should read [USER_GUIDE.md](USER_GUIDE.md) instead.

---

## System diagram

```
┌─────────────────────────────────────────────────────────────┐
│              Dashboard (Web :9470  /  WPF)                   │
│         Approve · Deny · Policies · Audit · Lockdown         │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP on this PC only, signed in
┌──────────────────────────▼──────────────────────────────────┐
│                   Python Service (aishield)                    │
│  EventBus · PolicyResolver · PermissionManager (SQLite+DPAPI)  │
│  ProcessMonitor · NetworkFirewall · FileGuard · FileEnforcer   │
│  ClipboardGuard · ScreenshotGuard · DeviceGuard/Enforcer     │
│  BrowserProtection · EnterprisePolicyClient                   │
└────────────┬────────────────────────────────────────────────┘
             │
   ┌─────────▼─────────────────────────────────────────┐
   │              Windows 10 / 11                        │
   └───────────────────────────────────────────────────┘

```

---

## Policy resolution order

For any access request:

1. **Temporary grant** (user clicked Allow in last 24h)
2. **Protected folder policy** (for file access)
3. **Per-app rule** (App Rules table)
4. **Global resource policy** (`network_policy`, `clipboard_policy`, …)
5. **Global default** (`global_policy`)

If policy is **ask**, `EventBus.request_approval()` blocks until dashboard `/api/approve` or timeout → block.

---

## Components

### Process monitor + AI detector
- Polls processes every `monitor_interval_seconds`
- Signature match against `ai_process_signatures`
- Signatures match the program's file name, not its whole path
- GPU usage via `nvidia-smi`
- Unknown AI via `ml_heuristics.py` (behavioral score)
- `fail_closed`: mark unknown GPU workloads as blocked in events (nothing is stopped)

### Network firewall
- `psutil` TCP connections → reverse DNS → match `ai_domains`. **This doesn't work:** AI services sit behind CDNs, so reverse DNS rarely returns their names
- Blocking is switched off, and a denial is only recorded

### File protection
- File enforcer polls the open files of detected AI processes, so it responds after a file is opened
- Only an explicit `block` policy stops the app, and never a browser, shell or part of Windows (`core/process_safety.py`)

### Clipboard
- `AddClipboardFormatListener` via ctypes message-only window
- Falls back to 1s poll if listener unavailable
- Sensitive regex patterns + foreground AI check
- Only a category label such as `clipboard: API key` is stored, never the text

### Device (mic/camera)
- Windows' ConsentStore registry records show which desktop apps use the mic or camera right now
- Decisions are recorded, and nothing is stopped

### Permissions
- SQLite: grants, app_policies, audit_log
- Grants match the exact resource, ignoring case
- `encrypt_db_at_rest` writes an encrypted copy on stop, but the plaintext database stays on disk

### API access (`dashboard/security.py`)
- Exact Host check, which stops DNS rebinding
- Other sites' requests are refused by an Origin check and a strict cookie
- API clients send a per-run token from `%APPDATA%\AiShield\api-token.json`
- Browsers sign in with a one-time link and hold an HttpOnly session cookie
- **Limit:** software running as this user can read the token file. Stopping that needs the SYSTEM service planned for M2

---

## C# service (being built, M2)

The replacement for the Python engine. It isn't installable yet: the installer arrives in M3.

| Project | Runs as | Role |
|---------|---------|------|
| `AiShield.Service` | SYSTEM | Holds policy and decides. Hosts the pipe, the guards and the approval queue |
| `AiShield.Dashboard` | The user, once per session | Main window and tray. The service starts it at sign-in and restarts it if it's killed |
| `AiShield.Consent` | SYSTEM, without privileges | The secure prompt, on a private desktop in the user's session |
| `AiShield.Core` | (library) | Policy store, resolver, approval queue, detection and the pipe protocol |
| `AiShield.TamperProbe` | (CI only) | Attacks an installed service from a non-admin token. Never shipped |

### Who may do what

| Caller | Read status | Tighten or deny | Loosen or allow |
|--------|-------------|-----------------|-----------------|
| Installed desktop app | Yes | Yes | Only after the user confirms on the secure prompt |
| Any other program | No | No | No |
| Administrator | Yes, and can change anything | | |

- **Trusted desktop app:** the service trusts a caller only when Windows reports its program as `dashboard\AiShield.Dashboard.exe` inside the install folder, and only when that folder is protected from ordinary users. A copy elsewhere, or a build run from the repo, isn't trusted.
- **Why the secure prompt:** software running as the user can inject into or drive the desktop app, so being the desktop app isn't enough to loosen anything.
- **The prompt:** it runs as SYSTEM on its own desktop, like UAC, so the user's programs can't see, click or read it. `Allow` only works after two seconds.
- **The pipe:** its name is random each start and published in `HKLM\SOFTWARE\AiShield`, which only administrators can change. It refuses network clients, gives unknown programs a small separate budget, and only SYSTEM and administrators can create instances. Clients check the service owns it before sending anything.
- **More:** [SECURITY-MODEL.md](SECURITY-MODEL.md) lists every defense, what CI proves, and the known limits.
- **Data:** policy and audit live in `%ProgramData%\AiShield`, which only SYSTEM and administrators can open. Anything planted there first is moved aside.

### Guards

Each guard reports `active`, `degraded`, `unavailable` or `off`, with a reason. `active` needs evidence: the process guard starts a harmless program and only reports active once event tracing has reported it.

| Guard | State |
|-------|-------|
| AI apps | Event tracing of process starts, plus a 10-second scan. Recognizes command-line agents through their interpreter and counts what an AI app starts as part of it |
| Network, files, microphone and camera, clipboard | Unavailable: not ported yet |

---

## Config merge

`load_merged_config()` layers:

1. `config/default.json`
2. `%APPDATA%\AiShield\user_config.json`

See [CONFIGURATION.md](CONFIGURATION.md) for all keys.

---

## API (selected)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/status` | GET | Live state + pending requests |
| `/api/approve/{id}?allow=true` | POST | Resolve pending approval (`allow` is required) |
| `/api/login-code` | POST | Mint a one-time sign-in link (token only) |
| `/api/policy/global` | POST | Set network/clipboard/… policy |
| `/api/lockdown` | POST | Emergency strict mode |
| `/api/audit/export` | GET | CSV audit download |

Full list in web dashboard **Documentation** page and `dashboard/server.py`.

---

## Security notes

- AI Firewall refuses to listen on anything but this PC
- It has no tamper resistance yet: software running as this user can stop it or change its settings
- The enterprise policy URL must use HTTPS, but policies aren't signed yet

---

## Testing

```powershell
cd python
python -m unittest discover -s tests -v    # Includes booting the real service
```

`.\scripts\smoke-dashboard.ps1` launches the real desktop app and fails if it crashes or logs an error.

The C# tests run with `dotnet test --project csharp/AiShield.Core.Tests/AiShield.Core.Tests.csproj`.

CI also installs the service on an elevated runner with `scripts/ci/service-integration.ps1`, attacks it from a non-admin token and uninstalls it. Those scripts change system settings, so they refuse to run unless `CI` is set: don't run them on your own PC.

CI (`.github/workflows/`) runs all of this on Windows, plus lint, format, dependency and secret checks and CodeQL.

---

## Future work

See [NEXT.md](NEXT.md) for the rebuild plan.

---

## Related docs

- [USER_GUIDE.md](USER_GUIDE.md) — operator manual
- [INSTALLATION.md](INSTALLATION.md) — setup paths
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — failure modes
- [CONFIGURATION.md](CONFIGURATION.md) — config reference
