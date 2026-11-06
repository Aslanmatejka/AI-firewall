# AI Firewall

Control what AI software can access on your Windows PC: files, network, clipboard, microphone and camera.

> **Pre-release: not production ready.** AI Firewall is being rebuilt, and the current version doesn't yet protect you the way its name suggests. Read [Current status](#current-status) before relying on it. The plan is in [docs/NEXT.md](docs/NEXT.md).

## Try it

**Needs:** Windows 10 or 11, Python 3.12

```powershell
.\scripts\install.ps1
.\scripts\start.ps1
```

Your browser opens the dashboard and signs you in. To open it again later, run `.\scripts\open-dashboard.ps1`.

## Current status

| Area | State today |
|------|-------------|
| AI app detection | **Works, with limits.** Matches program names, so a renamed app slips through, and it misses command-line agents running under `node` or `python`. |
| Network | **Not working.** In testing it recognized none of its 16 configured AI domains. Blocking is switched off because it acted on IP addresses, which many unrelated sites can share. |
| Files | **Partial.** Notices protected files that an AI app already has open, so it responds after the fact. Under a `block` policy it stops the app, but never a browser, shell or part of Windows. |
| Clipboard | **Partial.** Spots sensitive text while an AI app is in front, but can't tell who read it. Stores only a category, never the text. |
| Mic and camera | **Detection only.** Uses Windows' own usage records, and a denial is recorded but not enforced. |
| Screenshots | **Not working.** The Windows call it uses only affects the app's own windows. |
| Audit log | **Works, but isn't encrypted.** An unencrypted copy stays on disk even with `encrypt_db_at_rest` on. |
| Dashboard access | **Protected from other websites and casual scripts** with a sign-in and token. |
| Tamper resistance | **None.** Software running as you can read that token, stop AI Firewall or change its settings. |

## Project layout

```
config/         Default policy
csharp/         WPF desktop app and the future Windows service (.NET 10)
docs/           Guides
experimental/   Unfinished kernel, Rust and Linux code (not built or shipped)
python/         Current engine and web dashboard (being replaced by C#)
scripts/        Setup and start scripts
```

## Docs

| Guide | Read it for |
|-------|-------------|
| [Installation](docs/INSTALLATION.md) | Setting it up |
| [User guide](docs/USER_GUIDE.md) | Approvals, policies, lockdown |
| [Configuration](docs/CONFIGURATION.md) | Every setting |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | When something breaks |
| [Architecture](docs/ARCHITECTURE.md) | How it's built |
| [What's next](docs/NEXT.md) | The rebuild and what v1 will promise |

## License

[MIT](LICENSE)
