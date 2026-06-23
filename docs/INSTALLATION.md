# Installation Guide

Follow these steps in order. Do not skip steps unless the note says it is optional.

---

## Before you start — checklist

You need all of this on a Windows 10 or Windows 11 PC:

| Requirement | How to check | If missing |
|-------------|--------------|------------|
| **Python 3.10+** | Open PowerShell, run `python --version` | Install from [python.org](https://www.python.org/downloads/). Tick **“Add Python to PATH”** during install. |
| **Internet** (first run only) | — | Needed to `pip install` dependencies |
| **Administrator** (optional) | — | Required only for firewall domain blocking, hosts-file blocking, and kernel driver install |

You do **not** need Python knowledge. You do **not** need to edit code.

---

## Method A — Fastest (recommended for first try)

Open **PowerShell**, go to the project folder, and run:

```powershell
cd C:\path\to\firewall
.\scripts\install.ps1
```

That installs dependencies and runs tests.

Then start the app:

```powershell
.\scripts\start.ps1
```

You should see:

```
AI Firewall is running
Dashboard: http://127.0.0.1:9470
```

Open that URL in **Chrome**, **Edge**, or **Firefox**.

### How to know it worked

1. The web page loads (dark dashboard, not “connection refused”).
2. Top of the page shows **“Firewall Active”** (not “Service Offline”).
3. Leaving the PowerShell window open keeps the service running. Closing it stops the service.

---

## Method B — Manual (if scripts fail)

```powershell
cd C:\path\to\firewall
pip install -r python\requirements.txt
cd python
python -m aishield
```

Same dashboard URL: **http://127.0.0.1:9470**

---

## Method C — Windows desktop app (WPF)

The desktop app is a **remote control** for the Python service. The service must run first.

**Terminal 1** — start the service:

```powershell
.\scripts\start.ps1
```

**Terminal 2** — start the desktop UI:

```powershell
.\scripts\launch-dashboard.ps1
```

Requires [.NET 8 SDK](https://dotnet.microsoft.com/download). The script builds and opens the WPF window automatically.

If the desktop app says **“Service Offline”**, go back to Terminal 1 — the Python service is not running.

---

## Method D — Install as Windows Service (always-on, admin)

Run PowerShell **as Administrator**:

```powershell
cd C:\path\to\firewall
.\scripts\install-service.ps1
```

This will:

1. Copy config to `%ProgramData%\AiShield\config.json`
2. Install Python packages
3. Build the C# service
4. Register **AiShield** as a Windows Service and start it

The C# service supervises the Python backend. Dashboard is still at **http://127.0.0.1:9470**.

---

## Method E — Portable package (zip)

```powershell
.\scripts\package.ps1
```

Output: `dist\AiShield-portable.zip` and `dist\AiShield\` folder. Copy that folder to another machine, then:

```powershell
pip install -r python\requirements.txt
cd python
python -m aishield
```

---

## Optional add-ons

These are **not** required for basic use.

| Script | Admin? | What it does |
|--------|--------|--------------|
| `.\scripts\configure-browser-gpo.ps1` | Yes | Blocks AI domains in the Windows hosts file |
| `.\scripts\start-policy-server.ps1` | No | Runs a local enterprise policy server on port 9480 |
| `.\scripts\install-minifilter.ps1` | Yes | Installs kernel file filter (needs WDK-built driver — see [NEXT.md](NEXT.md)) |
| `.\scripts\build-native.ps1` | No | Builds Rust native DLL (optional) |
| `.\native\minifilter\build.ps1` | No | Builds minifilter driver (needs Visual Studio + WDK) |

---

## Where files live after install

| What | Location |
|------|----------|
| Default config (dev) | `config\default.json` in the project |
| Live config (service install) | `%ProgramData%\AiShield\config.json` |
| User override config | `%APPDATA%\AiShield\config.json` |
| Permissions database | `%APPDATA%\AiShield\permissions.db` |
| Audit log | Inside the permissions database + export from dashboard |

---

## Uninstall

**If you used Method A or B:** close the PowerShell window running `python -m aishield`. Done.

**If you used Method D (Windows Service):**

```powershell
# Run as Administrator
Stop-Service AiShield -Force
sc.exe delete AiShield
```

Delete `%ProgramData%\AiShield` and `%APPDATA%\AiShield` if you want to remove all data.
