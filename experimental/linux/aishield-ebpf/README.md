# AI Firewall — Linux eBPF scaffold (Phase 3)

User-space loader + BPF program to log/block outbound `connect()` to AI domains.

## Requirements

- Linux 5.8+ with BTF (`CONFIG_DEBUG_INFO_BTF=y`)
- clang, llvm, libbpf-dev, bpftool

## Build

```bash
cd linux/aishield-ebpf
make
```

## Run (requires root)

```bash
sudo ./aishield-ebpf --domains openai.com,anthropic.com --policy ask
```

## Architecture

```
connect() syscall
    → aishield_connect.bpf.c (tracepoint/syscall hook)
    → ring buffer events
    → aishield_loader (Go/C user-space)
    → policy JSON (same schema as Windows config)
```

## Status

Scaffold only — BPF object compiles; full loader policy integration is Phase 3.
