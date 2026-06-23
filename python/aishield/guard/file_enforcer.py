"""User-mode file access enforcer — scans AI process open handles on protected paths."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

import psutil

from ..core.events import EventBus
from ..core.models import EventSeverity, PolicyAction, ProtectedFolder, ResourceType
from ..permissions.resolver import PolicyResolver

logger = logging.getLogger(__name__)


class FileAccessEnforcer:
    """Blocks or prompts when AI processes hold open handles to protected files."""

    def __init__(
        self,
        folders: list[ProtectedFolder],
        event_bus: EventBus,
        get_ai_pids: Callable[[], set[int]],
        get_ai_type: Callable[[int], str],
        resolver: PolicyResolver,
        interval: float = 3.0,
    ) -> None:
        self._folders = folders
        self._bus = event_bus
        self._get_ai_pids = get_ai_pids
        self._get_ai_type = get_ai_type
        self._resolver = resolver
        self._interval = interval
        self._running = False
        self._thread: threading.Thread | None = None
        self._seen: set[str] = set()

    def update_folders(self, folders: list[ProtectedFolder]) -> None:
        self._folders = folders

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="FileAccessEnforcer")
        self._thread.start()
        logger.info("File access enforcer started (%d protected folders)", len(self._folders))

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _match_folder(self, path: str) -> ProtectedFolder | None:
        norm = path.replace("/", "\\").lower()
        for folder in self._folders:
            fp = folder.path.replace("/", "\\").lower().rstrip("\\")
            if norm == fp or norm.startswith(fp + "\\"):
                return folder
        return None

    def _loop(self) -> None:
        while self._running:
            try:
                self._scan_open_files()
            except Exception as e:
                logger.debug("File enforcer scan error: %s", e)
            time.sleep(self._interval)

    def _scan_open_files(self) -> None:
        ai_pids = self._get_ai_pids()
        if not ai_pids:
            return

        for pid in ai_pids:
            try:
                proc = psutil.Process(pid)
                open_files = proc.open_files()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            app_name = self._get_ai_type(pid)
            for ofile in open_files:
                folder = self._match_folder(ofile.path)
                if folder is None:
                    continue

                key = f"{pid}:{ofile.path}"
                if key in self._seen:
                    continue
                self._seen.add(key)

                policy = self._resolver.for_access(
                    app_name, ResourceType.FILE, ofile.path, folder=folder,
                )
                decision = self._bus.request_approval(
                    app_name, pid, ResourceType.FILE, ofile.path, policy,
                )
                if decision == PolicyAction.BLOCK:
                    try:
                        proc.terminate()
                        logger.warning("Terminated PID %d for blocked file access: %s", pid, ofile.path)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    self._bus.emit(
                        ResourceType.FILE, PolicyAction.BLOCK, app_name, ofile.path,
                        f"Blocked open handle to protected folder '{folder.name}'",
                        EventSeverity.WARNING,
                    )
