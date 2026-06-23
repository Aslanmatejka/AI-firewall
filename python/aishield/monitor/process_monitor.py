"""Monitor running processes for AI software."""

from __future__ import annotations

import ctypes
import logging
import threading
import time
from typing import Any, Callable

import psutil

from ..core.models import AiProcess, EventSeverity, PolicyAction, ResourceType
from ..core.events import EventBus
from ..detector.ai_detector import AiDetector

logger = logging.getLogger(__name__)
user32 = ctypes.windll.user32


class ProcessMonitor:
    def __init__(self, config: dict[str, Any], event_bus: EventBus, detector: AiDetector) -> None:
        self._config = config
        self._bus = event_bus
        self._detector = detector
        self._interval = config.get("monitor_interval_seconds", 2)
        self._fail_closed = bool(config.get("fail_closed", False))
        self._running = False
        self._thread: threading.Thread | None = None
        self._known_pids: set[int] = set()
        self._ai_processes: list[AiProcess] = []
        self._pid_to_type: dict[int, str] = {}
        self._on_change: list[Callable[[list[AiProcess]], None]] = []

    def on_change(self, handler: Callable[[list[AiProcess]], None]) -> None:
        self._on_change.append(handler)

    @property
    def ai_processes(self) -> list[AiProcess]:
        return list(self._ai_processes)

    def get_ai_pids(self) -> set[int]:
        return {p.pid for p in self._ai_processes}

    def get_ai_type_for_pid(self, pid: int) -> str:
        if pid in self._pid_to_type:
            return self._pid_to_type[pid]
        try:
            proc = psutil.Process(pid)
            ai_type, _ = self._detector.match_process(proc.name(), proc.exe() or "")
            return ai_type or proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"

    def is_ai_foreground(self) -> bool:
        try:
            fg = user32.GetForegroundWindow()
            if not fg:
                return False
            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(fg, ctypes.byref(pid))
            return pid.value in self.get_ai_pids()
        except Exception:
            return False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ProcessMonitor")
        self._thread.start()
        logger.info("Process monitor started")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while self._running:
            try:
                self._scan()
            except Exception as e:
                logger.error("Process scan error: %s", e)
            time.sleep(self._interval)

    def _scan(self) -> None:
        detected: list[AiProcess] = []
        current_pids: set[int] = set()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = info["name"] or ""
                exe = info["exe"] or ""
                ai_type, confidence = self._detector.match_process(name, exe)

                if ai_type:
                    current_pids.add(pid)
                    ai_proc = AiProcess(pid=pid, name=name, exe=exe, ai_type=ai_type, confidence=confidence)
                    detected.append(ai_proc)
                    self._pid_to_type[pid] = ai_type

                    if pid not in self._known_pids:
                        self._bus.emit(
                            ResourceType.PROCESS, PolicyAction.ASK, ai_type, exe,
                            f"AI process detected: {ai_type} (PID {pid})",
                            EventSeverity.WARNING,
                        )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        detected = self._detector.enrich_with_gpu(detected)
        all_pids = {proc.info["pid"] for proc in psutil.process_iter(["pid"]) if proc.info.get("pid")}
        unknown = self._detector.detect_unknown_ai(all_pids, current_pids)
        for u in unknown:
            if u.pid not in self._known_pids:
                policy = PolicyAction.BLOCK if self._fail_closed else PolicyAction.ASK
                self._bus.emit(
                    ResourceType.PROCESS, policy, "Unknown", str(u.pid),
                    f"Unknown AI model running (PID {u.pid}, GPU {u.gpu_mb:.0f} MB)",
                    EventSeverity.CRITICAL,
                )
                if self._fail_closed:
                    try:
                        psutil.Process(u.pid).terminate()
                        logger.warning("Fail-closed: terminated unknown AI PID %d", u.pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            detected.append(u)
            self._pid_to_type[u.pid] = u.ai_type

        self._known_pids = current_pids | {u.pid for u in unknown}
        self._ai_processes = detected
        snapshot = list(detected)
        threading.Thread(
            target=self._run_handlers,
            args=(snapshot,),
            daemon=True,
            name="ProcessMonitorNotify",
        ).start()

    def _run_handlers(self, processes: list[AiProcess]) -> None:
        for handler in self._on_change:
            try:
                handler(processes)
            except Exception:
                pass

    def is_ai_running(self) -> bool:
        return len(self._ai_processes) > 0
