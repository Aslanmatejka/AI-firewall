"""Integration tests for dashboard approval API."""

from __future__ import annotations

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient

from aishield.core.events import EventBus
from aishield.core.models import PolicyAction, ResourceType, ShieldStatus
from aishield.dashboard.server import create_app


class StubPermissions:
    def get_audit_log(self, limit: int = 100) -> list:
        return []

    def export_audit_csv(self, limit: int = 1000) -> str:
        return "timestamp,app_name,resource_type,resource,action,decision,message"


class StubActions:
    def get_app_policies(self) -> list:
        return []

    def unblock_domain(self, domain: str) -> dict:
        return {"ok": True, "domain": domain}

    def terminate_process(self, pid: int) -> dict:
        return {"ok": True}

    def set_app_policy(self, app_name: str, action: str) -> dict:
        return {"ok": True}

    def terminate_all_ai(self) -> dict:
        return {"ok": True}

    def set_app_resource_policy(self, app_name: str, resource: str, policy: str) -> dict:
        return {"ok": True}

    def remove_app_policy(self, app_name: str) -> dict:
        return {"ok": True}

    def set_folder_policy(self, folder_name: str, policy: str) -> dict:
        return {"ok": True}

    def add_protected_folder(self, name: str, path: str, policy: str) -> dict:
        return {"ok": True}

    def remove_protected_folder(self, folder_name: str) -> dict:
        return {"ok": True}

    def set_global_policy(self, key: str, value: str) -> dict:
        return {"ok": True}

    def block_all_ai_domains(self) -> dict:
        return {"ok": True}

    def block_connection(self, pid: int) -> dict:
        return {"ok": True}

    def block_ai_websites(self) -> dict:
        return {"ok": True}

    def lockdown_mode(self) -> dict:
        return {"ok": True}

    def restore_defaults(self) -> dict:
        return {"ok": True}


class StubService:
    def __init__(self) -> None:
        self.event_bus = EventBus(approval_timeout=10)
        self.event_bus.on_approval(lambda _req: None)
        self.config = {"network_policy": "ask", "clipboard_policy": "ask"}
        self.permissions = StubPermissions()
        self.actions = StubActions()
        self.browser = SimpleNamespace(detected_extensions=[])
        self.cached_models: list = []
        self.detector = SimpleNamespace(scan_model_files=lambda: [])
        self._network = SimpleNamespace(block_domain=lambda _d: True)

    def get_status(self) -> ShieldStatus:
        return ShieldStatus(
            running=True,
            ai_processes=[],
            active_connections=[],
            pending_requests=self.event_bus.get_pending(),
            recent_events=self.event_bus.get_events(10),
            protected_folders=[],
            stats={},
        )


class ApiApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = StubService()
        self.client = TestClient(create_app(self.service))

    def test_approve_endpoint_resolves_pending(self) -> None:
        result: list[PolicyAction] = []

        def worker() -> None:
            decision = self.service.event_bus.request_approval(
                "Cursor", 42, ResourceType.NETWORK, "api.openai.com", PolicyAction.ASK,
            )
            result.append(decision)

        t = threading.Thread(target=worker)
        t.start()
        time.sleep(0.15)

        pending = self.service.event_bus.get_pending()
        self.assertEqual(len(pending), 1)

        res = self.client.post(f"/api/approve/{pending[0].id}?allow=true")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["ok"])

        t.join(timeout=3)
        self.assertEqual(result[0], PolicyAction.ALLOW)

    def test_deny_endpoint_blocks_request(self) -> None:
        result: list[PolicyAction] = []

        def worker() -> None:
            decision = self.service.event_bus.request_approval(
                "Ollama", 7, ResourceType.FILE, "C:\\secret.txt", PolicyAction.ASK,
            )
            result.append(decision)

        t = threading.Thread(target=worker)
        t.start()
        time.sleep(0.15)
        pending = self.service.event_bus.get_pending()
        res = self.client.post(f"/api/approve/{pending[0].id}?allow=false")
        self.assertEqual(res.status_code, 200)

        t.join(timeout=3)
        self.assertEqual(result[0], PolicyAction.BLOCK)

    def test_approve_unknown_returns_404(self) -> None:
        res = self.client.post("/api/approve/missing-id?allow=true")
        self.assertEqual(res.status_code, 404)

    def test_pending_visible_in_status(self) -> None:
        def worker() -> None:
            self.service.event_bus.request_approval(
                "Claude", 1, ResourceType.CLIPBOARD, "clipboard", PolicyAction.ASK,
            )

        t = threading.Thread(target=worker)
        t.start()
        time.sleep(0.15)

        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data["pending_requests"]), 1)
        self.assertEqual(data["pending_requests"][0]["app_name"], "Claude")

        pending = self.service.event_bus.get_pending()
        self.client.post(f"/api/approve/{pending[0].id}?allow=true")
        t.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
