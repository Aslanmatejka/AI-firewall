# Configuration Reference

AI Firewall reads config from these locations, **in order** (later overrides earlier):

1. `config/default.json` (in the project — shipped defaults)
2. `%ProgramData%\AiShield\config.json` (after service install)
3. `%APPDATA%\AiShield\config.json` (your personal overrides — create this to customize)

Edit JSON with Notepad or VS Code. **Invalid JSON will prevent the service from starting.** Use a [JSON validator](https://jsonlint.com/) if unsure.

After editing, restart the service (`Ctrl+C` then `.\scripts\start.ps1` again).

---

## Policies

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `global_policy` | `allow` \| `ask` \| `block` | `ask` | Fallback for file/process access |
| `network_policy` | same | `ask` | Outbound connections to AI domains |
| `clipboard_policy` | same | `ask` | Clipboard when AI is active + sensitive content |
| `screenshot_policy` | same | `block` | Screen capture exclusion for non-AI windows |
| `microphone_policy` | same | `ask` | Mic access by AI processes |
| `camera_policy` | same | `ask` | Camera access by AI processes |
| `fail_closed` | `true` \| `false` | `false` | If `true`, unknown AI-like GPU processes are **terminated** |

### Policy values explained

- **`allow`** — silent pass-through.
- **`ask`** — shows pending request on dashboard; times out to **block** after `approval_timeout_seconds`.
- **`block`** — deny immediately; may terminate process for network/file/device.

---

## Protected folders

```json
"protected_folders": [
  { "name": "Documents", "path": "%USERPROFILE%\\Documents", "policy": "ask" }
]
```

| Field | Description |
|-------|-------------|
| `name` | Label shown in dashboard |
| `path` | Folder path. `%USERPROFILE%` expands to your user folder. |
| `policy` | `allow`, `ask`, or `block` for that folder |

You can also add/remove folders from the dashboard UI without editing JSON.

---

## AI detection

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ai_domains` | string[] | 16+ domains | Network monitor matches remote hosts against this list |
| `ai_process_signatures` | object[] | see file | `{ "name": "Ollama", "patterns": ["ollama"] }` |
| `ai_extension_patterns` | string[] | see file | Browser extension scan keywords |
| `model_file_extensions` | string[] | `.gguf`, etc. | Extensions for local model file scan |
| `gpu_threshold_mb` | number | `512` | GPU memory (MB) to flag unknown AI |
| `ml_heuristics_enabled` | boolean | `true` | Behavioral scoring for unknown processes |
| `ml_heuristic_threshold` | number | `65` | Score 0–100; above = flagged as unknown AI |

---

## Security & storage

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `encrypt_db_at_rest` | boolean | `true` | DPAPI-encrypt permissions DB when service stops |
| `approval_ui` | string | `dashboard` | `dashboard`, `desktop`, or `both` for approval prompts |
| `approval_timeout_seconds` | number | `120` | Auto-deny pending requests after this many seconds |
| `device_deny_cooldown_seconds` | number | `3600` | After mic/camera deny, suppress re-prompts for same app this long |
| `allow_simulate_approval` | boolean | `false` | Allow named-pipe `simulate_approval` (dev/testing only) |

---

## Network & kernel features

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `wfp_enabled` | boolean | `true` | Use Windows Filtering Platform before `netsh` fallback |
| `minifilter_enabled` | boolean | `true` | Try to connect to kernel minifilter comm port (harmless if driver not installed) |
| `named_pipe_enabled` | boolean | `true` | Local IPC pipe `\\.\pipe\AiShield` for tools/tests |

---

## Enterprise sync

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enterprise_policy_url` | string | `""` | URL returning policy JSON. Empty = disabled. |
| `enterprise_sync_seconds` | number | `300` | How often to pull enterprise policy |

Example enterprise payload: see `config/enterprise-policy.json`.

---

## Service tuning

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `monitor_interval_seconds` | number | `2` | How often process/network/file scans run |
| `dashboard_host` | string | `127.0.0.1` | Bind address (keep localhost for security) |
| `dashboard_port` | number | `9470` | Web dashboard port |
| `version` | number | `1` | Config schema version |

---

## Example — strict home setup

Save as `%APPDATA%\AiShield\config.json`:

```json
{
  "network_policy": "block",
  "clipboard_policy": "block",
  "microphone_policy": "block",
  "camera_policy": "block",
  "fail_closed": true,
  "screenshot_policy": "block"
}
```

Restart the service. AI apps will be heavily restricted; use dashboard to allow specific apps as needed.

---

## Example — permissive dev setup (Cursor + local Ollama)

```json
{
  "network_policy": "ask",
  "fail_closed": false,
  "app_policies": {
    "Cursor": { "default": "ask", "network": "allow", "files": "ask" },
    "Ollama": { "default": "ask", "network": "block", "files": "ask" }
  }
}
```

(App policies are normally created via the UI when you block/allow apps; enterprise server can push them too.)

---

## Config mistakes to avoid

| Mistake | Symptom | Fix |
|---------|---------|-----|
| Trailing comma in JSON | Service crashes on start | Remove trailing `,` before `}` |
| Wrong path slashes | Folder not watched | Use `\\` or `/` in paths |
| Port already in use | “Address already in use” | Change `dashboard_port` or kill old process |
| Edited wrong file | Changes ignored | Edit `%APPDATA%\AiShield\config.json` or restart after editing ProgramData copy |
