# What’s Next

Everything in this document is **not required** to use AI Firewall today. The app is fully usable without any of it. This is the honest list of what still needs external work, signing, or future development.

---

## You do not need any of this to start

If you only want to monitor AI apps, approve access, and block network/files from the dashboard:

1. `.\scripts\start.ps1`
2. Open http://127.0.0.1:9470

Stop reading here unless you are a developer, IT admin, or want kernel-level blocking.

---

## Tier 1 — Needs hardware/signing (not in repo alone)

These have **code scaffolds** in the repository but cannot protect a normal user’s PC until built and signed:

| Item | Status in repo | What you still need |
|------|----------------|---------------------|
| **Kernel minifilter** (block file opens before they happen) | C source + `.vcxproj` + install script | Visual Studio, WDK, `testsigning` or EV code-signing cert, reboot |
| **Kernel WFP callout driver** | Rust stub only | Windows driver project + signing |
| **Production MSI installer** | `package.ps1` zip only | WiX/Inno Setup + code-signing cert |
| **Microsoft Store / SmartScreen trust** | — | Authenticode signing, reputation |

### Minifilter — if you want to try it (experts only)

```powershell
# 1. Install Visual Studio + Windows Driver Kit
# 2. Enable test signing (ONE TIME, requires reboot):
bcdedit /set testsigning on

# 3. Build
.\native\minifilter\build.ps1

# 4. Install (Administrator)
.\scripts\install-minifilter.ps1

# 5. Restart AI Firewall service
.\scripts\start.ps1
```

If the driver is not loaded, file protection still works via **user-mode enforcer** (open-handle scan) and **folder watcher** — you lose only kernel pre-open blocking.

---

## Tier 2 — Platform expansion

| Item | Status | Notes |
|------|--------|-------|
| **Linux agent** | eBPF scaffold in `linux/aishield-ebpf/` | Needs loader daemon, policy sync, packaging |
| **macOS agent** | Not started | EndpointSecurity framework |
| **Full C# guard port** | C# supervises Python; native monitors added | Rewriting all guards in C# is optional |

---

## Tier 3 — Enterprise & advanced detection

| Item | Status | Notes |
|------|--------|-------|
| **Hosted enterprise policy server** | Local test server works (`start-policy-server.ps1`) | Production needs HTTPS, auth, multi-tenant UI |
| **Browser extension block via GPO** | Script + docs (`configure-browser-gpo.ps1`) | Manual GPO in Active Directory, not automated |
| **True ML model for unknown AI** | Behavioral heuristics shipped (`ml_heuristics.py`) | Train classifier on process/network features — future |
| **ETW telemetry pipeline** | Not started | Deep OS event stream |

---

## Tier 4 — Nice-to-have polish

| Item | Notes |
|------|-------|
| Rust WFP in native DLL | Python `wfp_bridge.py` is the active path; Rust returns stub |
| System tray in WPF | Partial; minimize behavior varies |
| Auto-update channel | Not implemented |
| Mobile approval app | Not implemented |
| Signed kernel catalog for minifilter INF | Required for production driver load without test signing |

---

## Roadmap summary

```
SHIPPED TODAY          NEXT (optional)              FUTURE
─────────────────────────────────────────────────────────────
Web + WPF dashboard    Kernel minifilter load       Linux eBPF agent
Process detection    Code-signed MSI               macOS agent
Network WFP/netsh    Full kernel WFP               ML classifier model
File watch + enforcer Enterprise SaaS policy      Mobile approvals
Clipboard/mic/camera Browser ADMX templates
Approval flow        C#-only service mode
Enterprise pull sync
Audit export + DPAPI
```

---

## For contributors — priority order

1. Get minifilter building in CI with WDK container (hard).
2. WiX installer with service + start menu (medium).
3. Linux eBPF loader reading same `config/default.json` (medium).
4. Replace heuristic scorer with lightweight ONNX model (research).

---

## Document map

| Doc | Purpose |
|-----|---------|
| [INSTALLATION.md](INSTALLATION.md) | How to install |
| [USER_GUIDE.md](USER_GUIDE.md) | How to use |
| [CONFIGURATION.md](CONFIGURATION.md) | Every config key |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | When things break |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How it is built |
