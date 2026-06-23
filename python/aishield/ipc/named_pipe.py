"""Named-pipe IPC for local dashboard/service communication."""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, Callable

from ..core.models import PolicyAction, ResourceType

logger = logging.getLogger(__name__)

PIPE_NAME = r"\\.\pipe\AiShield"


class NamedPipeServer:
    """JSON command server on Windows named pipe."""

    def __init__(self, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self._handler = handler
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._running or os.name != "nt":
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="NamedPipeServer")
        self._thread.start()
        logger.info("Named pipe server listening on %s", PIPE_NAME)

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        try:
            import win32file
            import win32pipe
            import pywintypes
        except ImportError:
            logger.warning("pywin32 required for named pipe IPC")
            return

        while self._running:
            try:
                handle = win32pipe.CreateNamedPipe(
                    PIPE_NAME,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    1, 65536, 65536, 0, None,
                )
                win32pipe.ConnectNamedPipe(handle, None)
                _, data = win32file.ReadFile(handle, 65536)
                req = json.loads(data.decode("utf-8"))
                resp = self._handler(req)
                win32file.WriteFile(handle, json.dumps(resp).encode("utf-8"))
                win32file.FlushFileBuffers(handle)
                handle.DisconnectNamedPipe()
                handle.Close()
            except pywintypes.error:
                if self._running:
                    continue
            except Exception as e:
                if self._running:
                    logger.debug("Named pipe error: %s", e)


def pipe_handler(service: Any) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def handle(req: dict[str, Any]) -> dict[str, Any]:
        cmd = req.get("cmd", "")
        if cmd == "status":
            from ..dashboard.server import _serialize
            return {"ok": True, "data": _serialize(service.get_status())}
        if cmd == "pending":
            return {"ok": True, "data": _serialize(service.event_bus.get_pending())}
        if cmd == "approve":
            rid = req.get("request_id", "")
            allow = bool(req.get("allow", True))
            req_obj = service.event_bus.resolve_request(rid, allow)
            if not req_obj:
                return {"ok": False, "error": "not found"}
            return {"ok": True, "allowed": allow}
        if cmd == "simulate_approval":
            if not service.config.get("allow_simulate_approval", False):
                return {"ok": False, "error": "simulate_approval disabled in production config"}
            return _simulate_approval(service, req)
        return {"ok": False, "error": f"unknown cmd: {cmd}"}

    return handle


def _simulate_approval(service: Any, req: dict[str, Any]) -> dict[str, Any]:
    """Trigger a pending approval request (for live testing)."""
    app_name = req.get("app_name", "TestApp")
    resource_type = ResourceType(req.get("resource_type", "network"))
    resource_path = req.get("resource_path", "api.openai.com")
    app_pid = int(req.get("pid", 9999))

    pending_before = len(service.event_bus.get_pending())
    holder: dict[str, Any] = {}

    def worker() -> None:
        decision = service.event_bus.request_approval(
            app_name, app_pid, resource_type, resource_path, PolicyAction.ASK,
        )
        holder["decision"] = decision.value

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    import time
    for _ in range(50):
        time.sleep(0.05)
        pending = service.event_bus.get_pending()
        if pending:
            return {
                "ok": True,
                "request_id": pending[-1].id,
                "app_name": app_name,
                "resource_path": resource_path,
            }

    return {"ok": False, "error": "pending request not created"}
