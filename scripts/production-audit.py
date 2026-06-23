#!/usr/bin/env python3
"""Production readiness audit for AI Firewall."""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / "python"
BASE = "http://127.0.0.1:9470"

PASS = 0
WARN = 0
FAIL = 0


def ok(msg: str) -> None:
    global PASS
    PASS += 1
    print(f"  [PASS] {msg}")


def warn(msg: str) -> None:
    global WARN
    WARN += 1
    print(f"  [WARN] {msg}")


def fail(msg: str) -> None:
    global FAIL
    FAIL += 1
    print(f"  [FAIL] {msg}")


def run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str]:
    r = subprocess.run(
        cmd, cwd=cwd or ROOT, capture_output=True, text=True, timeout=120,
    )
    return r.returncode, (r.stdout + r.stderr).strip()


def http_get(path: str, timeout: float = 10.0) -> dict | list | None:
    try:
        with urllib.request.urlopen(f"{BASE}{path}", timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def audit_tests() -> None:
    print("\n== 1. Automated tests ==")
    code, out = run([sys.executable, "-m", "pytest", "tests/", "-q"], cwd=PYTHON)
    if code == 0:
        ok("Python pytest suite")
    else:
        fail(f"Python tests failed:\n{out[-500:]}")

    code, out = run([sys.executable, "-m", "unittest", "discover", "-s", "python/tests", "-q"])
    if code == 0:
        ok("Python unittest (CI parity)")
    else:
        fail(f"Unittest failed:\n{out[-500:]}")

    code, out = run(["dotnet", "build", "csharp/AiShield.sln", "-c", "Release"])
    if code == 0 and "Error(s)" in out and "0 Error" in out.replace(" ", ""):
        ok(".NET Release build")
    elif code == 0:
        ok(".NET Release build")
    else:
        fail(f".NET build failed:\n{out[-500:]}")


def audit_config() -> None:
    print("\n== 2. Configuration & security ==")
    cfg_path = ROOT / "config" / "default.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))

    host = cfg.get("dashboard_host", "127.0.0.1")
    if host in ("127.0.0.1", "localhost", "::1"):
        ok(f"Dashboard binds to localhost ({host})")
    else:
        warn(f"Dashboard host is {host} — API has no auth; use localhost in production")

    if not cfg.get("allow_simulate_approval", False):
        ok("simulate_approval disabled (production default)")
    else:
        warn("allow_simulate_approval is true — disable before shipping")

    if cfg.get("encrypt_db_at_rest", True):
        ok("Audit DB encryption enabled")
    else:
        warn("encrypt_db_at_rest is false")

    sigs = cfg.get("ai_process_signatures", [])
    cursor = next((s for s in sigs if s.get("name") == "Cursor"), None)
    if cursor and "cursor.exe" in cursor.get("patterns", []):
        ok("Cursor signature is specific (cursor.exe)")
    else:
        warn("Cursor signature may be too broad")


def ensure_service() -> bool:
    if http_get("/api/status", timeout=3):
        return True
    print("  (starting service for runtime checks...)")
    subprocess.Popen(
        [sys.executable, "-m", "aishield", "--log-level", "WARNING"],
        cwd=PYTHON,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    deadline = time.time() + 20
    while time.time() < deadline:
        if http_get("/api/status", timeout=3):
            return True
        time.sleep(0.5)
    return False


def audit_runtime() -> None:
    print("\n== 3. Runtime smoke test ==")
    if not ensure_service():
        fail("Service not reachable on :9470 — run .\\scripts\\start.ps1 first")
        return

    status = http_get("/api/status")
    if not status:
        fail("Service unreachable after start")
        return

    ok("Service online")
    if status.get("running"):
        ok("Service reports running=true")
    else:
        fail("Service reports running=false")

    proc_count = len(status.get("ai_processes", []))
    if proc_count <= 10:
        ok(f"Dashboard process list reasonable ({proc_count} apps)")
    else:
        warn(f"Dashboard shows {proc_count} AI apps — check deduplication")

    pending = len(status.get("pending_requests", []))
    if pending == 0:
        ok("No stale pending approvals")
    else:
        warn(f"{pending} pending approval(s) — resolve or wait for timeout")

    for path in ("/api/config", "/api/events?limit=5", "/api/policies/apps", "/api/audit?limit=5"):
        if http_get(path) is not None:
            ok(f"GET {path}")
        else:
            fail(f"GET {path} failed")


def audit_live_approval() -> None:
    print("\n== 4. Live approval flow ==")
    code, out = run([sys.executable, str(ROOT / "scripts" / "test-live-approval.py")])
    if code == 0:
        ok("Live approval E2E test")
    else:
        if "simulate_approval disabled" in out or "FAILED to simulate" in out:
            warn("Live approval skipped — set allow_simulate_approval=true in user_config for dev testing")
        elif "Service not running" in out:
            fail("Live approval skipped — service offline")
        else:
            fail(f"Live approval test failed:\n{out}")


def audit_files() -> None:
    print("\n== 5. Production hygiene ==")
    debug_files = list(PYTHON.rglob("debug_log.py")) + list(ROOT.glob("debug-*.log"))
    if not debug_files:
        ok("No debug session artifacts")
    else:
        warn(f"Debug artifacts present: {debug_files}")

    req = (PYTHON / "requirements.txt").read_text(encoding="utf-8")
    if "pytest" not in req.lower():
        ok("requirements.txt has no test-only deps pinned as runtime")
    else:
        warn("pytest in requirements.txt")

    docs = ["docs/README.md", "docs/INSTALLATION.md", "docs/TROUBLESHOOTING.md", "docs/NEXT.md"]
    missing = [d for d in docs if not (ROOT / d).exists()]
    if not missing:
        ok("Core documentation present")
    else:
        fail(f"Missing docs: {missing}")


def main() -> int:
    print("=" * 50)
    print(" AI Firewall — Production Readiness Audit")
    print("=" * 50)

    audit_tests()
    audit_config()
    audit_files()
    audit_runtime()
    audit_live_approval()

    print("\n" + "=" * 50)
    print(f" Results: {PASS} passed, {WARN} warnings, {FAIL} failed")
    print("=" * 50)

    if FAIL:
        print("\nNOT production-ready — fix FAIL items above.")
        return 1
    if WARN:
        print("\nProduction-ready for user-mode deployment with warnings noted.")
        print("Kernel driver / MSI / signed install remain optional (see docs/NEXT.md).")
        return 0
    print("\nAll checks passed — production-ready for user-mode deployment.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
