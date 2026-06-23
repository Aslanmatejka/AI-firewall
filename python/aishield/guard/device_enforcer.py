"""Active microphone and camera session monitoring for AI processes."""

from __future__ import annotations

import ctypes
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Callable

import psutil

from ..core.events import EventBus
from ..core.models import EventSeverity, PolicyAction, ResourceType
from ..permissions.resolver import PolicyResolver

logger = logging.getLogger(__name__)
user32 = ctypes.windll.user32

_CONSENT_MIC = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged"
_CONSENT_CAM = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged"


class DeviceEnforcer:
    """Detects live mic/camera use by AI processes and enforces policy."""

    def __init__(
        self,
        config: dict[str, Any],
        event_bus: EventBus,
        get_ai_pids: Callable[[], set[int]],
        get_ai_type: Callable[[int], str],
        resolver: PolicyResolver,
        interval: float = 2.0,
    ) -> None:
        self._config = config
        self._bus = event_bus
        self._get_ai_pids = get_ai_pids
        self._get_ai_type = get_ai_type
        self._resolver = resolver
        self._interval = interval
        self._running = False
        self._thread: threading.Thread | None = None
        self._seen_mic: set[int] = set()
        self._seen_cam: set[int] = set()
        self._denied_until: dict[tuple[str, str], float] = {}
        self._deny_cooldown = float(config.get("device_deny_cooldown_seconds", 3600))
        self._pycaw_ok = False
        if os.name == "nt":
            try:
                from pycaw.pycaw import AudioUtilities  # noqa: F401
                self._pycaw_ok = True
            except ImportError:
                logger.info("pycaw not installed — mic session detection uses registry fallback")

    def start(self) -> None:
        if self._running or os.name != "nt":
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="DeviceEnforcer")
        self._thread.start()
        logger.info("Device enforcer started (mic=%s)", "pycaw" if self._pycaw_ok else "registry")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while self._running:
            try:
                ai_pids = self._get_ai_pids()
                if ai_pids:
                    self._scan_microphone(ai_pids)
                    self._scan_camera(ai_pids)
                    self._seen_mic &= ai_pids
                    self._seen_cam &= ai_pids
            except Exception as e:
                logger.debug("Device enforcer error: %s", e)
            time.sleep(self._interval)

    def _scan_microphone(self, ai_pids: set[int]) -> None:
        active = set(self._mic_sessions_pycaw()) if self._pycaw_ok else set()
        if not active:
            active = self._mic_sessions_registry(ai_pids)
        for pid in active & ai_pids:
            if pid in self._seen_mic:
                continue
            self._seen_mic.add(pid)
            self._enforce(pid, ResourceType.MICROPHONE, "Microphone")

    def _scan_camera(self, ai_pids: set[int]) -> None:
        for pid in self._camera_sessions_registry(ai_pids) & ai_pids:
            if pid in self._seen_cam:
                continue
            self._seen_cam.add(pid)
            self._enforce(pid, ResourceType.CAMERA, "Camera")

    def _mic_sessions_pycaw(self) -> list[int]:
        from pycaw.pycaw import AudioUtilities

        pids: list[int] = []
        for session in AudioUtilities.GetAllSessions():
            if session.Process:
                try:
                    pids.append(session.Process.pid)
                except Exception:
                    pass
        return pids

    def _consent_pids(self, hive_path: str, ai_pids: set[int]) -> set[int]:
        found: set[int] = set()
        cutoff = datetime.now() - timedelta(seconds=30)
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, hive_path) as key:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(key, i)
                        i += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(key, sub) as sk:
                            last_used, _ = winreg.QueryValueEx(sk, "LastUsedTimeStart")
                            if last_used:
                                ts = self._filetime_to_dt(int(last_used))
                                if ts < cutoff:
                                    continue
                            exe = sub.replace("#", "\\").replace("/", "\\")
                            candidates: list[int] = []
                            for pid in ai_pids:
                                try:
                                    if psutil.Process(pid).exe().lower() == exe.lower():
                                        candidates.append(pid)
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass
                            if candidates:
                                found.add(self._pick_pid(candidates))
                    except OSError:
                        continue
        except OSError:
            pass
        return found

    @staticmethod
    def _pick_pid(candidates: list[int]) -> int:
        """Prefer the foreground window PID; otherwise the newest process."""
        try:
            fg = user32.GetForegroundWindow()
            if fg:
                pid = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(fg, ctypes.byref(pid))
                if pid.value in candidates:
                    return pid.value
        except Exception:
            pass
        return max(candidates)

    @staticmethod
    def _filetime_to_dt(filetime: int) -> datetime:
        return datetime(1601, 1, 1) + timedelta(microseconds=filetime // 10)

    def _mic_sessions_registry(self, ai_pids: set[int]) -> set[int]:
        return self._consent_pids(_CONSENT_MIC, ai_pids)

    def _camera_sessions_registry(self, ai_pids: set[int]) -> set[int]:
        return self._consent_pids(_CONSENT_CAM, ai_pids)

    def _enforce(self, pid: int, resource: ResourceType, label: str) -> None:
        app_name = self._get_ai_type(pid)
        policy = self._resolver.for_access(app_name, resource)
        deny_key = (app_name, resource.value)
        if time.time() < self._denied_until.get(deny_key, 0):
            return
        if policy == PolicyAction.ALLOW:
            return

        if policy == PolicyAction.BLOCK:
            self._block_device(pid, app_name, resource, label)
            return

        decision = self._bus.request_approval(app_name, pid, resource, label, policy)
        if decision == PolicyAction.BLOCK:
            self._denied_until[deny_key] = time.time() + self._deny_cooldown
            self._block_device(pid, app_name, resource, label, user_denied=True)

    def _block_device(
        self, pid: int, app_name: str, resource: ResourceType, label: str, user_denied: bool = False,
    ) -> None:
        if self._pycaw_ok and resource == ResourceType.MICROPHONE:
            self._mute_mic_sessions(pid)

        try:
            psutil.Process(pid).terminate()
            logger.warning("Terminated PID %d for blocked %s access", pid, label.lower())
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        msg = (
            f"User denied {label.lower()} for {app_name}"
            if user_denied
            else f"Blocked {label.lower()} access for {app_name} (PID {pid})"
        )
        self._bus.emit(resource, PolicyAction.BLOCK, app_name, label, msg, EventSeverity.WARNING)

    def _mute_mic_sessions(self, pid: int) -> None:
        try:
            from pycaw.pycaw import AudioUtilities
            from pycaw.utils import AudioSession

            for session in AudioUtilities.GetAllSessions():
                if session.Process and session.Process.pid == pid:
                    vol = session.SimpleAudioVolume
                    if vol:
                        vol.SetMute(1, None)
        except Exception as e:
            logger.debug("Could not mute mic session: %s", e)
