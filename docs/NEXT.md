# What's next

AI Firewall is being rebuilt for production. **It isn't production ready yet**, and this page says what's changing and why.

## Why a rebuild

An AI app running as you has the same rights as anything else running as you. If the firewall runs that way too, the app can switch it off, edit its policy or approve its own requests. Real protection needs a part of the firewall that a non-admin app can't touch.

Reviewing the current version also found that several features can't do what they claim. [The README](../README.md#current-status) lists them.

## Where it's going

One .NET 10 codebase with three processes:

| Process | Runs as | Job |
|---------|---------|-----|
| `AiShield.Service` | SYSTEM | Holds policy, decides, enforces |
| `AiShield.Dashboard` | You, once per session | Main window, tray, clipboard watch |
| `AiShield.Consent` | Restricted SYSTEM, private desktop | The only way to allow or weaken anything, isolated like a UAC prompt |

## What v1 will promise

| Area | Promise | Won't promise |
|------|---------|---------------|
| Network | Per-app blocking with firewall rules; browsers through an optional policy | Seeing browsers that use encrypted DNS on shared CDNs |
| Files | Detected within about a second, then respond | Blocking before a file opens (that needs a kernel driver) |
| Mic and camera | Detect from Windows' own usage records; act on dedicated apps by policy | The exact process; browsers get a notification only |
| Clipboard | "Sensitive text was copied while an AI app was in front" | Knowing who read it (Windows doesn't expose this) |
| Screenshots | Our own windows are excluded from capture | Stopping other apps' captures |
| Tampering | Apps without admin rights can't stop it, edit policy or approve themselves | Stopping admin-level code, or identifying a renamed or unknown AI |

## Milestones

| | Milestone | Status |
|---|-----------|--------|
| M0 | Repo cleanup, .NET 10, stricter CI | In progress |
| M1 | Contain the worst risks in today's code | Planned |
| M2 | Protected service core and Consent prompt | Planned |
| M3 | Real installer (MSI), upgrade, clean uninstall | Planned |
| M4 | Network detection and blocking that works | Planned |
| M5 | File, device and clipboard guards in C#; Python removed | Planned |
| M6 | Operational hardening; signed enterprise policy; opt-in web dashboard | Planned |
| M7 | Signed releases, release gate, security docs | Planned |

## After v1

- Windows Hello approvals, signed by a key the service can verify
- Reviving the kernel filter for block-before-open (see [experimental/](../experimental/README.md))
- Company fleet deployment
- A trained classifier for unknown AI apps
- Linux and macOS agents
