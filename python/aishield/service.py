"""AI Firewall service orchestrator."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from .core.config import get_protected_folders
from .core.user_config import load_merged_config
from .core.events import EventBus
from .core.models import PolicyAction, ResourceType, ShieldStatus
from .detector.ai_detector import AiDetector
from .monitor.process_monitor import ProcessMonitor
from .network.firewall import NetworkFirewall
from .guard.file_guard import FileAccessGuard
from .guard.file_enforcer import FileAccessEnforcer
from .guard.clipboard_guard import ClipboardGuard
from .guard.screenshot_guard import ScreenshotGuard
from .guard.device_guard import DeviceGuard
from .guard.device_enforcer import DeviceEnforcer
from .browser.protection import BrowserProtection
from .permissions.manager import PermissionManager
from .permissions.resolver import PolicyResolver
from .actions.shield_actions import ShieldActions
from .ui.approval_dialog import show_approval_dialog
from .ipc.named_pipe import NamedPipeServer, pipe_handler
from .ipc.minifilter_bridge import MinifilterBridge
from .enterprise.policy_client import EnterprisePolicyClient

logger = logging.getLogger(__name__)


class AiShieldService:
    def __init__(self, config_path: str | None = None) -> None:
        self._config = load_merged_config()
        timeout = float(self._config.get("approval_timeout_seconds", 120))
        encrypt_db = bool(self._config.get("encrypt_db_at_rest", True))
        self._bus = EventBus(approval_timeout=timeout)
        self._permissions = PermissionManager(encrypt_at_rest=encrypt_db)
        self._resolver = PolicyResolver(self._config, self._permissions)
        self._detector = AiDetector(self._config)
        self._process_monitor = ProcessMonitor(self._config, self._bus, self._detector)
        self._network = NetworkFirewall(
            self._config, self._bus, self._resolver, self._process_monitor.get_ai_type_for_pid,
        )
        self._folders = get_protected_folders(self._config)
        self._file_guard = FileAccessGuard(
            self._folders, self._bus, self._get_primary_ai_app, self._resolver,
        )
        self._file_enforcer = FileAccessEnforcer(
            self._folders, self._bus,
            self._process_monitor.get_ai_pids,
            self._process_monitor.get_ai_type_for_pid,
            self._resolver,
            interval=float(self._config.get("monitor_interval_seconds", 2)),
        )
        self._clipboard = ClipboardGuard(
            self._config, self._bus, self._process_monitor.is_ai_running,
            self._get_primary_ai_app, self._resolver, self._process_monitor.get_ai_pids,
            self._process_monitor.is_ai_foreground,
        )
        self._screenshot = ScreenshotGuard(
            self._config, self._bus, self._resolver,
            self._process_monitor.get_ai_pids, self._process_monitor.is_ai_running,
            self._get_primary_ai_app,
        )
        self._device = DeviceGuard(self._config, self._bus, self._resolver)
        self._device_enforcer = DeviceEnforcer(
            self._config, self._bus,
            self._process_monitor.get_ai_pids,
            self._process_monitor.get_ai_type_for_pid,
            self._resolver,
            interval=float(self._config.get("monitor_interval_seconds", 2)),
        )
        self._browser = BrowserProtection(self._config, self._bus)
        self._actions = ShieldActions(self)
        self._running = False
        self._cached_models: list[dict[str, Any]] = []
        self._pipe: NamedPipeServer | None = None
        self._minifilter: MinifilterBridge | None = None
        self._enterprise: EnterprisePolicyClient | None = None
        self._status_cache: tuple[float, Any] | None = None
        self._status_cache_ttl = 10.0

        self._bus.on_approval(self._handle_approval)
        self._bus.on_resolve(self._on_request_resolved)
        self._bus.subscribe(self._permissions.log_event)
        self._process_monitor.on_change(self._device.on_ai_processes_changed)
        self._process_monitor.on_change(self._on_ai_processes_changed)

    def _on_ai_processes_changed(self, _procs: list | None = None) -> None:
        if self._minifilter and self._minifilter._client.connected:
            self._minifilter.sync_policy()

    def _get_primary_ai_app(self) -> tuple[str, int]:
        procs = self._process_monitor.ai_processes
        if procs:
            p = max(procs, key=lambda x: (x.gpu_mb, x.confidence))
            return p.ai_type, p.pid
        return "", 0

    @staticmethod
    def _summarize_processes(processes: list) -> list:
        """One dashboard row per AI app — highest GPU/confidence wins."""
        best: dict[str, object] = {}
        for p in processes:
            cur = best.get(p.ai_type)
            if cur is None or (p.gpu_mb, p.confidence) > (cur.gpu_mb, cur.confidence):
                best[p.ai_type] = p
        return list(best.values())

    def _handle_approval(self, request) -> PolicyAction | None:
        cached = self._permissions.get_grant(
            request.app_name, request.resource_type, request.resource_path,
        )
        if cached:
            return cached

        ui_mode = self._config.get("approval_ui", "dashboard")
        if ui_mode in ("desktop", "both"):
            decision = show_approval_dialog(request)
            if decision == PolicyAction.ALLOW:
                self._permissions.grant(
                    request.app_name, request.resource_type, request.resource_path,
                    PolicyAction.ALLOW, hours=24,
                )
            return decision
        return None

    def _on_request_resolved(self, request, decision: PolicyAction) -> None:
        if decision == PolicyAction.ALLOW:
            self._permissions.grant(
                request.app_name, request.resource_type, request.resource_path,
                PolicyAction.ALLOW, hours=24,
            )

    def start(self) -> None:
        if self._running:
            return
        logger.info("Starting AI Firewall service...")
        self._process_monitor.start()
        self._network.start()
        self._file_guard.start()
        self._file_enforcer.start()
        self._clipboard.start()
        self._screenshot.start()
        self._device_enforcer.start()

        ext_thread = threading.Thread(
            target=self._browser.scan_extensions, daemon=True, name="BrowserScan",
        )
        ext_thread.start()

        model_thread = threading.Thread(
            target=self._scan_models_startup, daemon=True, name="ModelScan",
        )
        model_thread.start()

        if self._config.get("named_pipe_enabled", True):
            self._pipe = NamedPipeServer(pipe_handler(self))
            self._pipe.start()

        if self._config.get("minifilter_enabled", True):
            self._minifilter = MinifilterBridge(self)
            self._minifilter.start()

        if self._config.get("enterprise_policy_url"):
            self._enterprise = EnterprisePolicyClient(self)
            self._enterprise.start()

        self._running = True
        logger.info("AI Firewall is active")

    def _scan_models_startup(self) -> None:
        try:
            self._cached_models = self._detector.scan_model_files()
            logger.info("Startup model scan found %d file(s)", len(self._cached_models))
        except Exception as e:
            logger.debug("Startup model scan failed: %s", e)

    def stop(self) -> None:
        self._running = False
        self._process_monitor.stop()
        self._network.stop()
        self._file_guard.stop()
        self._file_enforcer.stop()
        self._clipboard.stop()
        self._screenshot.stop()
        self._device_enforcer.stop()
        if self._pipe:
            self._pipe.stop()
        if self._minifilter:
            self._minifilter.stop()
        if self._enterprise:
            self._enterprise.stop()
        self._permissions.seal()
        logger.info("AI Firewall stopped")

    def reload_config(self, sync_minifilter: bool = False) -> None:
        self._config = load_merged_config()
        self._folders = get_protected_folders(self._config)
        self._resolver.update_config(self._config)
        self._file_enforcer.update_folders(self._folders)
        self._network.update_policy(self._config.get("network_policy", "ask"))
        self._clipboard.update_policy(self._config.get("clipboard_policy", "ask"))
        if sync_minifilter and self._minifilter:
            self._minifilter.sync_policy()

    def invalidate_status_cache(self) -> None:
        self._status_cache = None

    def get_status(self) -> ShieldStatus:
        now = time.time()
        if self._status_cache and now - self._status_cache[0] < self._status_cache_ttl:
            return self._status_cache[1]

        status = ShieldStatus(
            running=self._running,
            ai_processes=self._summarize_processes(self._process_monitor.ai_processes),
            active_connections=[c for c in self._network.connections if c.is_ai_traffic],
            pending_requests=self._bus.get_pending(),
            recent_events=self._bus.get_events(30),
            protected_folders=self._folders,
            stats={
                "network": self._network.get_stats(),
                "permissions": self._permissions.get_stats(),
                "extensions_found": len(self._browser.detected_extensions),
                "models_found": len(self._cached_models),
            },
        )
        self._status_cache = (now, status)
        return status

    def is_healthy(self) -> bool:
        return self._running

    @property
    def event_bus(self) -> EventBus:
        return self._bus

    @property
    def permissions(self) -> PermissionManager:
        return self._permissions

    @property
    def config(self) -> dict[str, Any]:
        return self._config

    @property
    def browser(self) -> BrowserProtection:
        return self._browser

    @property
    def actions(self) -> ShieldActions:
        return self._actions

    @property
    def detector(self) -> AiDetector:
        return self._detector

    @property
    def cached_models(self) -> list[dict[str, Any]]:
        return self._cached_models

    @cached_models.setter
    def cached_models(self, value: list[dict[str, Any]]) -> None:
        self._cached_models = value

    @property
    def policy_resolver(self) -> PolicyResolver:
        return self._resolver
