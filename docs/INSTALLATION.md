# Installation

AI Firewall is pre-release. There are two ways to run it:

| | Python engine | Protected service (preview) |
|---|---|---|
| **How** | From a copy of this repository | Installed with an MSI |
| **Protects against** | Nothing that runs as you: other programs can stop it or change its settings | Programs without admin rights can't stop it, change its policy or approve their own access |
| **Can do today** | Everything in the [status table](../README.md#current-status) | Only notice AI apps, including command-line agents. Network, file, microphone, camera and clipboard protection aren't ported yet |

[What's next](NEXT.md) explains the plan.

## Protected service (preview)

The MSI is unsigned, so Windows SmartScreen warns about it, and it's a test build. Try it in a virtual machine rather than on a PC you rely on.

1. Open the latest [CI run](https://github.com/Aslanmatejka/AI-firewall/actions/workflows/ci.yml) that passed, and download the **AiShield-unsigned-test-build** artifact.
2. Run the MSI. It needs administrator rights.
3. AI Firewall starts in the tray. Open it from the Start menu any time.

When you loosen a protection or allow an AI app's request, Windows switches to a separate screen, like a UAC prompt, and asks you to confirm. Programs on your PC can't see or click that screen. **Allow** only works after two seconds.

The installer also removes what older versions left behind: their Windows service, their `AiShield-Block` firewall rules and their hosts-file blocks. Lines you added to the hosts file yourself stay.

**Remove it** from Settings > Apps, like any other program. That removes everything, including its policies and logs. Upgrading to a newer MSI keeps them.

## Python engine

### What you need

- Windows 10 or 11
- [Python 3.12](https://www.python.org/downloads/), with **Add Python to PATH** ticked during setup
- [.NET 10 SDK](https://dotnet.microsoft.com/download), only for the desktop app

You don't need administrator rights.

### Set up

In PowerShell, from the project folder:

```powershell
.\scripts\install.ps1
```

This installs the dependencies, runs the tests and, if the .NET 10 SDK is available, builds the desktop app.

### Start

```powershell
.\scripts\start.ps1
```

Your browser opens the dashboard and signs you in. Keep the PowerShell window open: closing it stops AI Firewall.

The sign-in link works once, for two minutes. To open the dashboard again later, run:

```powershell
.\scripts\open-dashboard.ps1
```

### Desktop app

With AI Firewall running, in a second PowerShell window:

```powershell
.\scripts\launch-dashboard.ps1
```

If it shows **Service offline**, AI Firewall isn't running yet. It connects on its own once you start it.

### Where files live

| What | Where |
|------|-------|
| Default settings | `config\default.json` in the project |
| Your changes to the settings | `%APPDATA%\AiShield\user_config.json` |
| Policies and audit log | `%APPDATA%\AiShield\permissions.db` |
| Token for the desktop app, only while running | `%APPDATA%\AiShield\api-token.json` |
| Desktop app error log | `%LOCALAPPDATA%\AiShield\dashboard.log` |

### Remove it

1. Close the PowerShell window running AI Firewall.
2. Delete the project folder.
3. Delete `%APPDATA%\AiShield` and `%LOCALAPPDATA%\AiShield`.

#### If you used an older version

Older versions could change your system in ways this one doesn't undo for you. From an administrator PowerShell window:

```powershell
# The Windows service, if you installed it
Stop-Service AiShield -Force -ErrorAction SilentlyContinue
sc.exe delete AiShield

# Firewall rules from "Block domain" or "Lockdown"
Get-NetFirewallRule -DisplayName 'AiShield-*' | Remove-NetFirewallRule
```

If you ran `configure-browser-gpo.ps1` or used **Block websites**, also open `C:\Windows\System32\drivers\etc\hosts` and delete the lines marked as AiShield entries.

Older versions could also create empty `Passwords`, `Financial` and `Projects` folders. It's safe to delete them if you don't use them.
