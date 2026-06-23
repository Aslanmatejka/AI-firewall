# AI Firewall Minifilter Driver — Phase 3 Scaffold

Kernel-mode minifilter that intercepts file I/O from AI processes and enforces
folder policy before data reaches user-mode guards.

## Status

**Scaffold only** — not signed, not loaded by the installer. Use for WDK development.

## Layout

```
native/minifilter/
  aishield_minifilter.c   # FltRegisterFilter + pre-create callback stub
  aishield_minifilter.inf # Driver installation INF
  README.md               # This file
  build.ps1               # WDK build helper
```

## Build requirements

- Windows Driver Kit (WDK) 10 matching your VS version
- Visual Studio with Desktop development + SDK
- Test signing enabled for dev machines: `bcdedit /set testsigning on`

## Build

```powershell
.\native\minifilter\build.ps1
```

## Install (dev, admin)

```powershell
pnputil /add-driver native\minifilter\aishield_minifilter.inf /install
sc create AiShieldMinifilter type= filesys binPath= "C:\Path\To\aishield_minifilter.sys"
sc start AiShieldMinifilter
```

## Communication

User-mode service connects via `FilterConnectCommunicationPort("\\AiShieldMinifilterPort")`.

Protocol header: `native/minifilter/aishield_protocol.h`  
Python client: `python/aishield/ipc/minifilter_client.py`  
Service bridge: `python/aishield/ipc/minifilter_bridge.py`

Commands:
| Cmd | Direction | Purpose |
|-----|-----------|---------|
| `SYNC_POLICY` | user → kernel | Push protected folders + AI process list |
| `PING` | user → kernel | Health check |
| `FILE_QUERY` | kernel → user | Ask service for allow/block/ask decision |
| `FILE_RESPONSE` | user → kernel | Reply to file query |

When the driver is not loaded, the service falls back to the user-mode file guard (`watchdog`).

## Policy flow

```
IRP_MJ_CREATE (file open)
    → identify requesting process
    → match against AI process list (cached from service)
    → check path against protected folders
    → allow / block / pend (ask user via service)
```

## Related

- User-mode file guard: `python/aishield/guard/file_guard.py` (watchdog, MVP)
- Architecture: `docs/ARCHITECTURE.md` Phase 3
