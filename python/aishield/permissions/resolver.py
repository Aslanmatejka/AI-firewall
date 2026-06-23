"""Resolve effective policy: grants → app rules → resource global → global default."""

from __future__ import annotations

from typing import Any

from ..core.models import PolicyAction, ProtectedFolder, ResourceType


_GLOBAL_KEYS: dict[ResourceType, str] = {
    ResourceType.NETWORK: "network_policy",
    ResourceType.CLIPBOARD: "clipboard_policy",
    ResourceType.SCREENSHOT: "screenshot_policy",
    ResourceType.MICROPHONE: "microphone_policy",
    ResourceType.CAMERA: "camera_policy",
    ResourceType.FILE: "global_policy",
    ResourceType.PROCESS: "global_policy",
}

_APP_COLUMNS: dict[ResourceType, str] = {
    ResourceType.FILE: "files",
    ResourceType.NETWORK: "network",
    ResourceType.CLIPBOARD: "clipboard",
    ResourceType.MICROPHONE: "microphone",
    ResourceType.CAMERA: "camera",
    ResourceType.SCREENSHOT: "default_action",
    ResourceType.PROCESS: "default_action",
}


class PolicyResolver:
    def __init__(self, config: dict[str, Any], permissions: Any) -> None:
        self._config = config
        self._permissions = permissions

    def update_config(self, config: dict[str, Any]) -> None:
        self._config = config

    def for_access(
        self,
        app_name: str,
        resource_type: ResourceType,
        resource_path: str = "",
        folder: ProtectedFolder | None = None,
    ) -> PolicyAction:
        grant = self._permissions.get_grant(app_name, resource_type, resource_path)
        if grant is not None:
            return grant

        if folder is not None:
            return folder.policy

        app_policy = self._permissions.get_app_resource_policy(app_name, resource_type)
        if app_policy is not None:
            return app_policy

        key = _GLOBAL_KEYS.get(resource_type, "global_policy")
        raw = self._config.get(key, self._config.get("global_policy", "ask"))
        try:
            return PolicyAction(raw)
        except ValueError:
            return PolicyAction.ASK

    def fail_closed(self) -> bool:
        return bool(self._config.get("fail_closed", False))
