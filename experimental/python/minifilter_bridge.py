"""Bridge between AI Firewall service and minifilter driver."""

from __future__ import annotations

import logging
from typing import Any

from ..core.models import PolicyAction, ResourceType
from .minifilter_client import MinifilterClient, get_client

logger = logging.getLogger(__name__)


class MinifilterBridge:
    """Syncs policy to kernel minifilter and handles file-access queries."""

    def __init__(self, service: Any) -> None:
        self._service = service
        self._client = get_client(on_file_query=self._on_file_query)

    def start(self) -> bool:
        if not self._service.config.get("minifilter_enabled", True):
            return False
        if not self._client.connect():
            logger.info("Minifilter driver not loaded — using user-mode file guard only")
            return False
        if self._client.ping():
            logger.info("Minifilter driver connected")
        return self.sync_policy()

    def stop(self) -> None:
        self._client.close()

    def sync_policy(self) -> bool:
        if not self._client.connected:
            return False

        folders = [
            {"name": f.name, "path": f.path, "policy": f.policy.value}
            for f in self._service._folders
        ]
        ai_procs = [
            {
                "pid": p.pid,
                "name": p.name,
                "ai_type": p.ai_type,
            }
            for p in self._service._process_monitor.ai_processes
        ]
        global_policy = self._service.config.get("global_policy", "ask")
        ok = self._client.sync_policy(folders, ai_procs, global_policy)
        if ok:
            logger.debug("Synced policy to minifilter (%d folders, %d AI procs)", len(folders), len(ai_procs))
        return ok

    def _on_file_query(self, payload: dict[str, Any]) -> str:
        """Handle kernel file-access query via dashboard approval flow."""
        path = payload.get("path", "")
        app_name = payload.get("app_name", "Unknown")
        app_pid = int(payload.get("pid", 0))
        folder_name = payload.get("folder_name", "")

        folder = next(
            (f for f in self._service._folders if f.name == folder_name),
            None,
        )
        policy = self._service.policy_resolver.for_access(
            app_name, ResourceType.FILE, path, folder=folder,
        )
        decision = self._service.event_bus.request_approval(
            app_name, app_pid, ResourceType.FILE, path, policy,
        )
        return decision.value
