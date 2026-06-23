"""File access guard for protected folders."""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ..core.models import EventSeverity, PolicyAction, ProtectedFolder, ResourceType
from ..core.events import EventBus
from ..permissions.resolver import PolicyResolver

logger = logging.getLogger(__name__)


class _GuardHandler(FileSystemEventHandler):
    def __init__(
        self,
        folder: ProtectedFolder,
        event_bus: EventBus,
        get_ai_app: Callable[[], tuple[str, int]],
        resolver: PolicyResolver,
    ) -> None:
        self._folder = folder
        self._bus = event_bus
        self._get_ai_app = get_ai_app
        self._resolver = resolver

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        app_name, app_pid = self._get_ai_app()
        if not app_name:
            return

        src = event.src_path
        policy = self._resolver.for_access(
            app_name, ResourceType.FILE, src, folder=self._folder,
        )
        decision = self._bus.request_approval(
            app_name, app_pid, ResourceType.FILE, src, policy,
        )
        if decision == PolicyAction.BLOCK:
            logger.warning("Blocked file access: %s by %s", src, app_name)
            self._bus.emit(
                ResourceType.FILE, PolicyAction.BLOCK, app_name, src,
                f"Denied access to protected folder '{self._folder.name}'",
                EventSeverity.WARNING,
            )


class FileAccessGuard:
    def __init__(
        self,
        folders: list[ProtectedFolder],
        event_bus: EventBus,
        get_ai_app: Callable[[], tuple[str, int]],
        resolver: PolicyResolver,
    ) -> None:
        self._folders = folders
        self._bus = event_bus
        self._get_ai_app = get_ai_app
        self._resolver = resolver
        self._observer = Observer()
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        for folder in self._folders:
            path = folder.path
            if not os.path.isdir(path):
                logger.info("Creating protected folder: %s", path)
                try:
                    os.makedirs(path, exist_ok=True)
                except OSError as e:
                    logger.warning("Cannot create %s: %s", path, e)
                    continue
            handler = _GuardHandler(folder, self._bus, self._get_ai_app, self._resolver)
            self._observer.schedule(handler, path, recursive=True)
            logger.info("Watching protected folder: %s (%s)", folder.name, path)

        self._observer.start()
        self._running = True
        logger.info("File access guard started (%d folders)", len(self._folders))

    def stop(self) -> None:
        if not self._running:
            return
        self._observer.stop()
        self._observer.join(timeout=5)
        self._running = False
