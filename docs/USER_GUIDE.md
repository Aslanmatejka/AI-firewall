# User Guide

This guide assumes AI Firewall is already running. If not, read [INSTALLATION.md](INSTALLATION.md) first.

---

## What AI Firewall does (plain English)

AI apps (ChatGPT, Cursor, Ollama, Claude, etc.) can read your files, send data over the network, use your microphone, and copy from your clipboard. **AI Firewall watches for that** and lets you **allow**, **block**, or **ask every time**.

Think of it as a bouncer for AI software on your PC.

---

## Open the dashboard

| Interface | URL / app |
|-----------|-----------|
| Web (always works) | **http://127.0.0.1:9470** |
| Desktop (optional) | Run `.\scripts\launch-dashboard.ps1` after starting the service |

Bookmark the web URL. Port **9470** is fixed unless you change `dashboard_port` in config.

---

## Dashboard pages — what each one is for

| Page | Use it to… |
|------|------------|
| **Home** | See overview, quick stats, getting started |
| **Dashboard** | Live stats, pending approvals, emergency actions |
| **Documentation** | In-app help (same info as these docs) |
| **AI Processes** | Block, allow, or stop detected AI apps |
| **Network** | See AI traffic; block connections or domains |
| **Protected Files** | Set allow/ask/block per folder; add folders |
| **Activity Log** | Full history of decisions |
| **Settings** | Global policies, app rules, lockdown, export audit |

---

## The three policies — memorize this

Every protected resource uses one of three modes:

| Policy | Meaning |
|--------|---------|
| **allow** | AI can access silently. No popup. |
| **ask** | You get a **pending request** on the dashboard. You must click Allow or Deny. |
| **block** | Access is denied automatically. Logged in Activity. |

If you are unsure, use **ask**. That is the default everywhere.

---

## How to approve or deny a request

When policy is **ask**, a yellow **Pending Approvals** panel appears on the Dashboard.

1. Read what app is asking (e.g. “Cursor → network → api.openai.com”).
2. Click **Allow** or **Deny**.
3. The request disappears. The decision is logged.

If you do nothing for **120 seconds** (default), the request is **automatically denied** (blocked).

### You closed the browser — will it still work?

Yes, as long as the Python service is still running. Reopen **http://127.0.0.1:9470** and pending items will still be there until you approve/deny or they time out.

---

## Common tasks — step by step

### Block an AI app completely

1. Go to **AI Processes**.
2. Find the app (e.g. Ollama).
3. Click **Block**.

Or on **Settings → App Rules**, set that app’s **Default** policy to **block**.

### Block all network access to OpenAI

1. Go to **Settings**.
2. Under **Network**, click **Block**.
3. Or click **Lockdown Mode** (also blocks clipboard, mic, camera, and AI domains).

### Protect a new folder

1. Go to **Protected Files**.
2. Click **+ Add Folder**.
3. Pick a folder and choose **ask** or **block**.
4. Click save / confirm.

### Block a specific AI website domain

1. Go to **Network**.
2. Find the connection row.
3. Click **Block Domain**.

Requires **Administrator** for the firewall rule to actually apply. Without admin, the block may not stick at the OS level.

### Export audit log

1. Go to **Activity Log** or **Settings**.
2. Click **Export Audit** (downloads CSV).

### Emergency — stop everything AI-related

On **Dashboard** or **Settings**:

- **Stop All AI** — terminates detected AI processes.
- **Lockdown Mode** — sets strict block policies network-wide.
- **Restore Defaults** — resets policies to config file defaults.

---

## What gets protected automatically

Out of the box (`config/default.json`):

| Area | Default policy |
|------|----------------|
| Documents, Photos, Projects | ask |
| Passwords, Financial folders | block |
| Network to AI domains | ask |
| Clipboard (sensitive content) | ask |
| Screenshots | block |
| Microphone / camera | ask |

Sensitive clipboard patterns include: `password`, `api_key`, `secret`, `token`, OpenAI-style keys (`sk-...`).

---

## Admin vs normal user

| Action | Normal user | Administrator |
|--------|-------------|---------------|
| View dashboard | Yes | Yes |
| Approve/deny requests | Yes | Yes |
| Change policies in UI | Yes | Yes |
| Block domains (firewall rules) | May fail silently | Works |
| Hosts-file browser blocking | No | Yes (`configure-browser-gpo.ps1`) |
| Install kernel minifilter | No | Yes |

**Tip:** Right-click PowerShell → **Run as administrator**, then `.\scripts\start.ps1` if you need full network blocking.

---

## Enterprise / IT admins

1. Host a policy JSON file (see `config/enterprise-policy.json` for format).
2. Run `.\scripts\start-policy-server.ps1` for a local test server.
3. Set in config:
   ```json
   "enterprise_policy_url": "http://your-server:9480/policy.json",
   "enterprise_sync_seconds": 300
   ```
4. Clients pull policy every 5 minutes and apply it.

---

## Daily workflow (recommended)

1. Start AI Firewall once per boot: `.\scripts\start.ps1` (or use Windows Service install).
2. Keep dashboard tab open or check it when using AI tools.
3. Review **Activity Log** weekly.
4. Adjust **Protected Files** and **App Rules** as you learn what you trust.

---

## Glossary

| Term | Meaning |
|------|---------|
| **AI process** | A running program AI Firewall recognizes (Cursor, Ollama, etc.) |
| **Pending request** | Something waiting for your Allow/Deny click |
| **App rule** | Per-app override (e.g. “allow network for Cursor, block for Ollama”) |
| **Grant** | Temporary allow stored for 24 hours after you click Allow |
| **Fail-closed** | Unknown AI-like processes are blocked/terminated automatically |
| **Lockdown** | One-click maximum restriction |
