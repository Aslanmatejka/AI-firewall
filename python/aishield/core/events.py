"""In-memory event bus for component communication."""

from __future__ import annotations

import logging
import threading
import uuid
from collections import deque
from datetime import datetime
from typing import Callable

from .models import AccessRequest, EventSeverity, PolicyAction, ResourceType, ShieldEvent

logger = logging.getLogger(__name__)


class EventBus:
    def __init__(self, max_events: int = 500, approval_timeout: float = 120.0) -> None:
        self._events: deque[ShieldEvent] = deque(maxlen=max_events)
        self._pending: dict[str, AccessRequest] = {}
        self._waiters: dict[str, threading.Event] = {}
        self._lock = threading.Lock()
        self._approval_timeout = approval_timeout
        self._subscribers: list[Callable[[ShieldEvent], None]] = []
        self._approval_handlers: list[Callable[[AccessRequest], PolicyAction | None]] = []
        self._resolve_callbacks: list[Callable[[AccessRequest, PolicyAction], None]] = []

    def subscribe(self, handler: Callable[[ShieldEvent], None]) -> None:
        self._subscribers.append(handler)

    def on_approval(self, handler: Callable[[AccessRequest], PolicyAction | None]) -> None:
        self._approval_handlers.append(handler)

    def on_resolve(self, handler: Callable[[AccessRequest, PolicyAction], None]) -> None:
        self._resolve_callbacks.append(handler)

    def emit(
        self,
        resource_type: ResourceType,
        action: PolicyAction,
        source_app: str,
        resource: str,
        message: str,
        severity: EventSeverity = EventSeverity.INFO,
        user_decision: str | None = None,
    ) -> ShieldEvent:
        event = ShieldEvent(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(),
            severity=severity,
            resource_type=resource_type,
            action=action,
            source_app=source_app,
            resource=resource,
            message=message,
            user_decision=user_decision,
        )
        with self._lock:
            self._events.appendleft(event)
        for sub in self._subscribers:
            try:
                sub(event)
            except Exception:
                pass
        return event

    def request_approval(
        self,
        app_name: str,
        app_pid: int,
        resource_type: ResourceType,
        resource_path: str,
        policy: PolicyAction,
    ) -> PolicyAction:
        if policy == PolicyAction.ALLOW:
            return PolicyAction.ALLOW
        if policy == PolicyAction.BLOCK:
            self.emit(
                resource_type, PolicyAction.BLOCK, app_name, resource_path,
                f"Blocked {resource_type.value} access to {resource_path}",
                EventSeverity.WARNING,
            )
            return PolicyAction.BLOCK

        req = AccessRequest(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(),
            app_name=app_name,
            app_pid=app_pid,
            resource_type=resource_type,
            resource_path=resource_path,
            policy=policy,
        )
        waiter = threading.Event()
        with self._lock:
            self._pending[req.id] = req
            self._waiters[req.id] = waiter

        decision: PolicyAction | None = None
        for handler in self._approval_handlers:
            try:
                result = handler(req)
                if result is not None:
                    decision = result
                    break
            except Exception as e:
                logger.debug("Approval handler error: %s", e)

        if decision is None:
            if not waiter.wait(timeout=self._approval_timeout):
                decision = PolicyAction.BLOCK
                logger.info("Approval timed out for %s — defaulting to block", req.id)
            else:
                decision = req.decision or PolicyAction.BLOCK

        req.resolved = True
        req.decision = decision
        with self._lock:
            self._pending.pop(req.id, None)
            self._waiters.pop(req.id, None)

        sev = EventSeverity.INFO if decision == PolicyAction.ALLOW else EventSeverity.WARNING
        self.emit(
            resource_type, decision, app_name, resource_path,
            f"User {'allowed' if decision == PolicyAction.ALLOW else 'denied'} {resource_type.value} access",
            sev, user_decision=decision.value,
        )
        return decision

    def get_events(self, limit: int = 50) -> list[ShieldEvent]:
        with self._lock:
            return list(self._events)[:limit]

    def get_pending(self) -> list[AccessRequest]:
        with self._lock:
            return list(self._pending.values())

    def resolve_request(self, request_id: str, allow: bool) -> AccessRequest | None:
        decision = PolicyAction.ALLOW if allow else PolicyAction.BLOCK
        with self._lock:
            req = self._pending.get(request_id)
            if not req:
                return None
            req.resolved = True
            req.decision = decision
            waiter = self._waiters.get(request_id)

        for cb in self._resolve_callbacks:
            try:
                cb(req, decision)
            except Exception as e:
                logger.debug("Resolve callback error: %s", e)

        if waiter:
            waiter.set()
        return req
