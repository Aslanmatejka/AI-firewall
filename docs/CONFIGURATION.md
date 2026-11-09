# Configuration Reference

AI Firewall reads two files, and the second overrides the first:

1. `config/default.json` in the project: the defaults
2. `%APPDATA%\AiShield\user_config.json`: your changes (the dashboard writes here too)

Edit JSON with Notepad or VS Code. **Invalid JSON will prevent the service from starting.** Use a [JSON validator](https://jsonlint.com/) if unsure.

After editing, restart the service (`Ctrl+C` then `.\scripts\start.ps1` again).

---

## Policies

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `global_policy` | `allow` \| `ask` \| `block` | `ask` | Fallback for file/process access |
| `network_policy` | same | `ask` | Outbound connections to AI domains |
| `clipboard_policy` | same | `ask` | Clipboard when AI is active + sensitive content |
| `screenshot_policy` | same | `block` | Has no real effect today: the Windows call used only affects AI Firewall's own windows |
| `microphone_policy` | same | `ask` | Mic access by AI processes |
| `camera_policy` | same | `ask` | Camera access by AI processes |
| `fail_closed` | `true` \| `false` | `false` | If `true`, unknown AI-like GPU processes are reported as blocked. They aren't stopped |

### Policy values explained

- **`allow`** — silent pass-through.
- **`ask`** — shows pending request on dashboard; times out to **block** after `approval_timeout_seconds`.
- **`block`** — deny immediately. For a protected folder, this also stops the AI app that has a file open there, unless it's a browser, a shell or part of Windows. For network, microphone and camera, the denial is only recorded for now.

---

## Protected folders

```json
"protected_folders": [
  { "name": "Documents", "path": "%DOCUMENTS%", "policy": "ask" }
]
```

| Field | Description |
|-------|-------------|
| `name` | Label shown in dashboard |
| `path` | Folder path. `%DOCUMENTS%` and `%PICTURES%` find the real folders even if OneDrive moved them. `%USERPROFILE%` and other environment variables also work. The folder isn't created if it's missing. |
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
| `gpu_threshold_mb` | number | `512` | GPU memory (MB) to flag unknown AI. Needs an NVIDIA GPU with `nvidia-smi` |
| `ml_heuristics_enabled` | boolean | `true` | Behavioral scoring for unknown processes |
| `ml_heuristic_threshold` | number | `65` | Score 0–100; above = flagged as unknown AI |

---

## Security & storage

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `encrypt_db_at_rest` | boolean | `true` | Keeps an encrypted copy of the database when AI Firewall stops. The unencrypted database stays on disk too, so this doesn't protect your data |
| `approval_ui` | string | `dashboard` | `dashboard`, `desktop`, or `both` for approval prompts |
| `approval_timeout_seconds` | number | `120` | Auto-deny pending requests after this many seconds |
| `device_deny_cooldown_seconds` | number | `3600` | After mic/camera deny, suppress re-prompts for same app this long |

---

## Enterprise sync

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enterprise_policy_url` | string | `""` | HTTPS URL returning policy JSON. Empty = disabled. Plain HTTP only works for an address on this PC. |
| `enterprise_sync_seconds` | number | `300` | How often to pull enterprise policy |

Example enterprise payload: see `config/enterprise-policy.json`.

---

## Service tuning

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `monitor_interval_seconds` | number | `2` | How often process/network/file scans run |
| `dashboard_host` | string | `127.0.0.1` | Must be `127.0.0.1`, `localhost` or `::1`. AI Firewall refuses to start with anything else |
| `dashboard_port` | number | `9470` | Web dashboard port |
| `version` | number | `1` | Config schema version |

---

## Example — strict home setup

Save as `%APPDATA%\AiShield\user_config.json`:

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

Restart AI Firewall to apply it. Remember that network, microphone and camera denials are only recorded for now.

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
