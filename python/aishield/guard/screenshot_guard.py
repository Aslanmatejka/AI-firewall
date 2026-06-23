"""Screenshot protection — exclude non-AI windows from capture when AI is active."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from ..core.events import EventBus
from ..core.models import EventSeverity, PolicyAction, ResourceType
from ..native.win32_capture import exclude_windows_for_pids
from ..permissions.resolver import PolicyResolver

logger = logging.getLogger(__name__)


class ScreenshotGuard:
    def __init__(
        self,
        config: dict[str, Any],
        event_bus: EventBus,
        policy_resolver: PolicyResolver,
        get_ai_pids: Callable[[], set[int]],
        is_ai_active: Callable[[], bool],
        get_ai_app: Callable[[], tuple[str, int]],
    ) -> None:
        self._config = config
        self._bus = event_bus
        self._resolver = policy_resolver
        self._get_ai_pids = get_ai_pids
        self._is_ai_active = is_ai_active
        self._get_ai_app = get_ai_app
        self._interval = config.get("monitor_interval_seconds", 2)
        self._running = False
        self._thread: threading.Thread | None = None
        self._last_protected = 0
        self._prompted = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ScreenshotGuard")
        self._thread.start()
        logger.info("Screenshot guard started")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while self._running:
            try:
                self._tick()
            except Exception as e:
                logger.error("Screenshot guard error: %s", e)
            time.sleep(self._interval)

    def _tick(self) -> None:
        if not self._is_ai_active():
            self._prompted = False
            return

        app_name, app_pid = self._get_ai_app()
        policy = self._resolver.for_access(app_name, ResourceType.SCREENSHOT)

        if policy == PolicyAction.ALLOW:
            return

        if policy == PolicyAction.ASK and not self._prompted:
            self._prompted = True
            decision = self._bus.request_approval(
                app_name or "AI Process", app_pid, ResourceType.SCREENSHOT,
                "Screen capture while AI is active", policy,
            )
            if decision == PolicyAction.BLOCK:
                policy = PolicyAction.BLOCK
            elif decision == PolicyAction.ALLOW:
                return

        if policy == PolicyAction.BLOCK:
            ai_pids = self._get_ai_pids()
            count = exclude_windows_for_pids(ai_pids)
            if count != self._last_protected:
                self._last_protected = count
                self._bus.emit(
                    ResourceType.SCREENSHOT, PolicyAction.BLOCK,
                    app_name or "AI", f"{count} windows",
                    f"Excluded {count} window(s) from screen capture while AI is active",
                    EventSeverity.INFO,
                )
