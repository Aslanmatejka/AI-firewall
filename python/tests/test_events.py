"""Tests for async approval flow."""

from __future__ import annotations

import sys
import threading
import time
import unittest
from unittest import mock
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


class ApprovalRaceTests(unittest.TestCase):
    """A grant must never exist for a request whose caller was told it was blocked."""

    def test_decision_arriving_as_the_wait_times_out_still_wins(self) -> None:
        bus = EventBus(approval_timeout=5)
        bus.on_approval(lambda _req: None)
        granted: list = []
        bus.on_resolve(lambda req, decision: granted.append(decision))

        class ResolvedAsItTimesOut(threading.Event):
            def wait(self, timeout=None) -> bool:
                bus.resolve_request(bus.get_pending()[0].id, True)
                return False

        with mock.patch("aishield.core.events.threading.Event", ResolvedAsItTimesOut):
            decision = bus.request_approval("AI", 1, ResourceType.FILE, "/x", PolicyAction.ASK)

        self.assertEqual(granted, [PolicyAction.ALLOW])
        self.assertEqual(decision, PolicyAction.ALLOW)

    def test_decision_after_the_timeout_is_refused_and_grants_nothing(self) -> None:
        bus = EventBus(approval_timeout=0.05)
        bus.on_approval(lambda _req: None)
        granted: list = []
        bus.on_resolve(lambda req, decision: granted.append(decision))
        ids: list[str] = []
        bus.subscribe(lambda _event: None)

        def worker() -> None:
            bus.request_approval("AI", 1, ResourceType.FILE, "/x", PolicyAction.ASK)

        t = threading.Thread(target=worker)
        t.start()
        while not bus.get_pending():
            time.sleep(0.001)
        ids.append(bus.get_pending()[0].id)
        t.join(timeout=3)

        self.assertIsNone(bus.resolve_request(ids[0], True))
        self.assertEqual(granted, [])

    def test_a_request_can_only_be_decided_once(self) -> None:
        bus = EventBus(approval_timeout=5)
        bus.on_approval(lambda _req: None)
        granted: list = []
        bus.on_resolve(lambda req, decision: granted.append(decision))
        result: list = []

        def worker() -> None:
            result.append(bus.request_approval("AI", 1, ResourceType.FILE, "/x", PolicyAction.ASK))

        t = threading.Thread(target=worker)
        t.start()
        while not bus.get_pending():
            time.sleep(0.001)
        request_id = bus.get_pending()[0].id
        self.assertIsNotNone(bus.resolve_request(request_id, False))
        self.assertIsNone(bus.resolve_request(request_id, True))
        t.join(timeout=3)
        self.assertEqual(result, [PolicyAction.BLOCK])
        self.assertEqual(granted, [PolicyAction.BLOCK])

    def test_failing_audit_subscriber_is_logged_not_hidden(self) -> None:
        bus = EventBus()

        def broken(_event) -> None:
            raise RuntimeError("database is locked")

        bus.subscribe(broken)
        with self.assertLogs("aishield.core.events", level="ERROR"):
            bus.emit(ResourceType.FILE, PolicyAction.ASK, "AI", "x", "m")


if __name__ == "__main__":
    unittest.main()
