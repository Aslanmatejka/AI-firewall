"""Microphone and camera policy enforcement when AI processes start."""

from __future__ import annotations

import logging
from typing import Any

from ..core.events import EventBus
from ..core.models import AiProcess, EventSeverity, PolicyAction, ResourceType
from ..permissions.resolver import PolicyResolver

logger = logging.getLogger(__name__)


class DeviceGuard:
    """Enforce block policy when new AI processes appear.

    Ask/allow mic/camera decisions are handled by DeviceEnforcer when a device
    is actually in use — not on every process spawn.
    """

    def __init__(
        self,
        config: dict[str, Any],
        event_bus: EventBus,
        policy_resolver: PolicyResolver,
    ) -> None:
        self._bus = event_bus
        self._resolver = policy_resolver
        self._handled: set[tuple[int, str]] = set()

    def on_ai_processes_changed(self, processes: list[AiProcess]) -> None:
        current = {p.pid for p in processes}
        self._handled = {(pid, res) for pid, res in self._handled if pid in current}

        for proc in processes:
            self._enforce_block(proc, ResourceType.MICROPHONE)
            self._enforce_block(proc, ResourceType.CAMERA)

    def _enforce_block(self, proc: AiProcess, resource: ResourceType) -> None:
        key = (proc.pid, resource.value)
        if key in self._handled:
            return

        policy = self._resolver.for_access(proc.ai_type, resource)
        if policy != PolicyAction.BLOCK:
            return

        self._handled.add(key)
        label = "Microphone" if resource == ResourceType.MICROPHONE else "Camera"
        try:
            import psutil
            psutil.Process(proc.pid).terminate()
        except Exception:
            pass
        self._bus.emit(
            resource, PolicyAction.BLOCK, proc.ai_type, label,
            f"Blocked {label.lower()} access for {proc.ai_type} (PID {proc.pid})",
            EventSeverity.WARNING,
        )
