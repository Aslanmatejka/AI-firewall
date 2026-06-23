"""Windows approval dialog for access requests."""

from __future__ import annotations

import ctypes

from ..core.models import AccessRequest, PolicyAction, ResourceType

MB_YESNO = 0x04
MB_ICONWARNING = 0x30
MB_TOPMOST = 0x40000
IDYES = 6


def show_approval_dialog(request: AccessRequest) -> PolicyAction:
    resource_labels = {
        ResourceType.FILE: "File Access",
        ResourceType.NETWORK: "Network Connection",
        ResourceType.CLIPBOARD: "Clipboard Read",
        ResourceType.SCREENSHOT: "Screenshot",
        ResourceType.MICROPHONE: "Microphone",
        ResourceType.CAMERA: "Camera",
        ResourceType.PROCESS: "AI Process",
    }
    label = resource_labels.get(request.resource_type, "Access")

    message = (
        f"AI Access Request\n\n"
        f"Application: {request.app_name}\n"
        f"Type: {label}\n"
        f"Resource: {request.resource_path}\n\n"
        f"Allow this access?"
    )
    title = "AI Firewall — Access Request"

    result = ctypes.windll.user32.MessageBoxW(0, message, title, MB_YESNO | MB_ICONWARNING | MB_TOPMOST)
    return PolicyAction.ALLOW if result == IDYES else PolicyAction.BLOCK
