"""Tests for async approval flow."""

from __future__ import annotations

import sys
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aishield.core.events import EventBus
from aishield.core.models import PolicyAction, ResourceType


class ApprovalFlowTests(unittest.TestCase):
    def test_dashboard_approve_unblocks_waiter(self) -> None:
        bus = EventBus(approval_timeout=5)
        bus.on_approval(lambda _req: None)
        result: list[PolicyAction] = []

        def worker() -> None:
            d = bus.request_approval(
                "Cursor", 99, ResourceType.NETWORK, "api.openai.com", PolicyAction.ASK,
            )
            result.append(d)

        t = threading.Thread(target=worker)
        t.start()
        time.sleep(0.2)
        pending = bus.get_pending()
        self.assertEqual(len(pending), 1)
        bus.resolve_request(pending[0].id, True)
        t.join(timeout=3)
        self.assertEqual(result[0], PolicyAction.ALLOW)

    def test_timeout_defaults_to_block(self) -> None:
        bus = EventBus(approval_timeout=1)
        bus.on_approval(lambda _req: None)
        d = bus.request_approval("X", 1, ResourceType.FILE, "/tmp", PolicyAction.ASK)
        self.assertEqual(d, PolicyAction.BLOCK)


if __name__ == "__main__":
    unittest.main()
