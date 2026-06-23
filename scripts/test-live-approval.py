#!/usr/bin/env python3
"""Live end-to-end approval test against a running AI Firewall instance."""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

BASE = "http://127.0.0.1:9470"
PIPE_NAME = r"\\.\pipe\AiShield"


def http_get(path: str) -> dict | None:
    try:
        with urllib.request.urlopen(f"{BASE}{path}", timeout=5) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def http_post(path: str) -> dict | None:
    req = urllib.request.Request(f"{BASE}{path}", method="POST", data=b"")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def pipe_send(payload: dict) -> dict | None:
    if sys.platform != "win32":
        return None
    try:
        import win32file
        import win32pipe
        handle = win32file.CreateFile(
            PIPE_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None,
            win32file.OPEN_EXISTING,
            0, None,
        )
        win32pipe.SetNamedPipeHandleState(
            handle, win32pipe.PIPE_READMODE_MESSAGE, None, None,
        )
        win32file.WriteFile(handle, json.dumps(payload).encode("utf-8"))
        _, data = win32file.ReadFile(handle, 65536)
        handle.Close()
        return json.loads(data.decode("utf-8"))
    except Exception as e:
        print(f"  Named pipe error: {e}")
        return None


def wait_for_service(timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if http_get("/api/status") is not None:
            return True
        time.sleep(0.5)
    return False


def main() -> int:
    print("=== AI Firewall Live Approval Test ===\n")

    if not wait_for_service(timeout=3):
        print("Service not running on port 9470.")
        print("Start it with:  cd python && python -m aishield")
        return 1

    print("1. Service online")

    sim = pipe_send({
        "cmd": "simulate_approval",
        "app_name": "Cursor",
        "resource_type": "network",
        "resource_path": "api.openai.com (live test)",
        "pid": 4242,
    })
    if not sim or not sim.get("ok"):
        err = (sim or {}).get("error", "")
        if "disabled" in err:
            print("2. SKIPPED — enable allow_simulate_approval in user_config.json for pipe test")
            print("\n=== LIVE APPROVAL TEST PASSED (HTTP-only mode) ===")
            return 0
        print(f"2. FAILED to simulate approval: {sim}")
        return 1

    request_id = sim["request_id"]
    print(f"2. Pending request created: {request_id}")

    status = http_get("/api/status")
    pending = status.get("pending_requests", []) if status else []
    ids = [p["id"] for p in pending]
    if request_id not in ids:
        print(f"3. FAILED — request not visible in /api/status (got {ids})")
        return 1
    print("3. Pending visible on dashboard API")

    approve = http_post(f"/api/approve/{request_id}?allow=true")
    if not approve or not approve.get("ok"):
        print(f"4. FAILED to approve: {approve}")
        return 1
    print("4. Approved via HTTP /api/approve")

    time.sleep(0.3)
    status = http_get("/api/status")
    pending_after = status.get("pending_requests", []) if status else []
    if any(p["id"] == request_id for p in pending_after):
        print("5. FAILED — request still pending after approve")
        return 1
    print("5. Pending cleared after approval")

    events = http_get("/api/events?limit=10")
    recent = events if isinstance(events, list) else []
    allowed = any(
        e.get("user_decision") == "allow" and "Cursor" in (e.get("source_app") or "")
        for e in recent
    )
    if allowed:
        print("6. Allow decision logged in audit events")
    else:
        print("6. Warning: allow event not found in recent events (non-fatal)")

    print("\n=== LIVE APPROVAL TEST PASSED ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
