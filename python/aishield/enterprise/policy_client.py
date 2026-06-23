"""Optional enterprise policy server sync."""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)


class EnterprisePolicyClient:
    """Pulls policy updates from a central server and applies them locally."""

    def __init__(self, service: Any) -> None:
        self._service = service
        self._url = service.config.get("enterprise_policy_url", "")
        self._interval = float(service.config.get("enterprise_sync_seconds", 300))
        self._running = False
        self._thread: threading.Thread | None = None

    @property
    def enabled(self) -> bool:
        return bool(self._url)

    def start(self) -> None:
        if not self.enabled or self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="EnterprisePolicy")
        self._thread.start()
        logger.info("Enterprise policy sync enabled: %s", self._url)

    def stop(self) -> None:
        self._running = False

    def sync_now(self) -> bool:
        if not self.enabled:
            return False
        try:
            req = urllib.request.Request(self._url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            self._apply(data)
            return True
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            logger.warning("Enterprise policy sync failed: %s", e)
            return False

    def _apply(self, data: dict[str, Any]) -> None:
        for key in ("global_policy", "network_policy", "clipboard_policy",
                    "screenshot_policy", "microphone_policy", "camera_policy", "fail_closed"):
            if key in data:
                self._service.config[key] = data[key]

        if "app_policies" in data:
            for app_name, policies in data["app_policies"].items():
                self._service.permissions.set_app_policy(app_name, policies)

        self._service.reload_config(sync_minifilter=True)
        logger.info("Applied enterprise policy revision")

    def _loop(self) -> None:
        while self._running:
            self.sync_now()
            time.sleep(self._interval)
