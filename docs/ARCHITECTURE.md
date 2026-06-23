# AI Firewall — Architecture

Technical overview for developers and IT admins. End users should read [USER_GUIDE.md](USER_GUIDE.md) instead.

---

## System diagram

```
┌─────────────────────────────────────────────────────────────┐
│              Dashboard (Web :9470  /  WPF)                   │
│         Approve · Deny · Policies · Audit · Lockdown         │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP REST  +  Named pipe \\.\pipe\AiShield
┌──────────────────────────▼──────────────────────────────────┐
│                   Python Service (aishield)                    │
│  EventBus · PolicyResolver · PermissionManager (SQLite+DPAPI)  │
│  ProcessMonitor · NetworkFirewall · FileGuard · FileEnforcer   │
│  ClipboardGuard · ScreenshotGuard · DeviceGuard/Enforcer     │
│  BrowserProtection · EnterprisePolicyClient · MinifilterBridge │
└────────────┬───────────────────────────────┬─────────────────┘
             │                               │
   ┌─────────▼─────────┐           ┌─────────▼─────────┐
   │  WFP (fwpuclnt)   │           │ Minifilter driver  │
   │  netsh fallback   │           │ (optional, kernel) │
   └───────────────────┘           └────────────────────┘
             │
   ┌─────────▼─────────────────────────────────────────┐
   │              Windows 10 / 11                        │
   └───────────────────────────────────────────────────┘

Parallel: C# AiShield.Service supervises Python + native Process/Network monitors
```

---

## Policy resolution order

For any access request:

1. **Temporary grant** (user clicked Allow in last 24h)
2. **Per-app rule** (App Rules table)
3. **Protected folder policy** (for file access)
4. **Global resource policy** (`network_policy`, `clipboard_policy`, …)
5. **Global default** (`global_policy`)

If policy is **ask**, `EventBus.request_approval()` blocks until dashboard `/api/approve` or timeout → block.

---

## Components

### Process monitor + AI detector
- Polls processes every `monitor_interval_seconds`
- Signature match against `ai_process_signatures`
- GPU usage via `nvidia-smi` / WMI fallback
- Unknown AI via `ml_heuristics.py` (behavioral score)
- `fail_closed`: terminate unknown GPU workloads

### Network firewall
- `psutil` TCP connections → match `ai_domains`
- Block path: WFP user-mode (`wfp_bridge.py`) → `netsh advfirewall` fallback
- Ask/block triggers approval or process terminate

### File protection (dual layer)
| Layer | Mechanism | Blocks before open? |
|-------|-----------|---------------------|
| File guard | `watchdog` directory events | No — detects activity |
| File enforcer | Scans AI process open handles | Partial — active handles |
| Minifilter (optional) | Kernel IRP_MJ_CREATE | Yes — when driver loaded |

### Clipboard
- `AddClipboardFormatListener` via ctypes message-only window
- Falls back to 1s poll if listener unavailable
- Sensitive regex patterns + foreground AI check

### Device (mic/camera)
- **Device guard:** policy on AI process appearance
- **Device enforcer:** pycaw audio sessions + ConsentStore registry for webcam

### Permissions
- SQLite: grants, app_policies, audit_log
- DPAPI seal on service stop when `encrypt_db_at_rest: true`

### IPC
| Channel | Use |
|---------|-----|
| HTTP `:9470` | Dashboard REST API |
| Named pipe | Local tools, `simulate_approval`, WPF fallback |
| Minifilter port | Kernel ↔ user policy sync + file queries |

---

## C# stack

| Project | Role |
|---------|------|
| `AiShield.Core` | Config, permissions, event bus, process/network monitors |
| `AiShield.Service` | Windows Service — supervises Python backend |
| `AiShield.Dashboard` | WPF UI — HTTP client to Python API |

---

## Config merge

`load_merged_config()` layers:

1. `config/default.json`
2. `%ProgramData%\AiShield\config.json`
3. `%APPDATA%\AiShield\config.json`

See [CONFIGURATION.md](CONFIGURATION.md) for all keys.

---

## API (selected)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/status` | GET | Live state + pending requests |
| `/api/approve/{id}?allow=true` | POST | Resolve pending approval |
| `/api/policy/global` | POST | Set network/clipboard/… policy |
| `/api/lockdown` | POST | Emergency strict mode |
| `/api/audit/export` | GET | CSV audit download |

Full list in web dashboard **Documentation** page and `dashboard/server.py`.

---

## Security notes

- Bind dashboard to `127.0.0.1` only (default) — do not expose to LAN without auth
- Admin required for persistent firewall rules
- Fail-closed mode terminates unknown AI processes — test before enabling
- Enterprise policy URL should use HTTPS in production

---

## Testing

```powershell
cd python
python -m unittest discover -s tests -v    # 12 unit tests
python ..\scripts\test-live-approval.py  # Live approval E2E
```

CI: `.github/workflows/ci.yml` — Python tests + dotnet build on Windows.

---

## Future work

See [NEXT.md](NEXT.md) — kernel signing, Linux eBPF, enterprise SaaS, MSI installer.

---

## Related docs

- [USER_GUIDE.md](USER_GUIDE.md) — operator manual
- [INSTALLATION.md](INSTALLATION.md) — setup paths
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — failure modes
- [CONFIGURATION.md](CONFIGURATION.md) — config reference
