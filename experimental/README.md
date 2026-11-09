# Experimental code

Nothing in this folder is built, tested, shipped or used by AI Firewall. It's kept so the work can be picked up later.

| Path | What it was meant to do | Why it's here |
|------|-------------------------|---------------|
| `native/minifilter/` | Kernel file filter to block opens before they happen | Doesn't compile. Shipping it also needs Microsoft attestation signing, an EV certificate and an assigned altitude. Its message format also doesn't match the user-mode client. |
| `native/aishield-native/` | Rust helper DLL with WFP hooks | Doesn't compile, and its WFP function always returns false. |
| `linux/aishield-ebpf/` | Linux connection monitor | Scaffold only: no loader, and `vmlinux.h` is missing. |
| `python/wfp_bridge.py` | User-mode Windows Filtering Platform filters | Its layer and condition GUIDs and its struct layout are wrong, so it can't work. |
| `python/minifilter_*.py` | User-mode side of the kernel filter | Its message header layout and port name don't match the driver. |
| `scripts/` | Build and install scripts for the above | They only serve the code above. |

Paths inside these files still refer to their old locations.

Reviving the kernel filter is the only way to get true block-before-open file protection, so it's on the list for after v1. See [docs/NEXT.md](../docs/NEXT.md).
