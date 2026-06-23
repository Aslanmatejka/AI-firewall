"""User-facing actions — terminate, block, policy changes."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import psutil

from ..core.config import get_protected_folders
from ..core.models import EventSeverity, PolicyAction, ResourceType
from ..core.user_config import load_merged_config, save_user_config
from ..guard.file_guard import FileAccessGuard

logger = logging.getLogger(__name__)


class ShieldActions:
    def __init__(self, service: Any) -> None:
        self._service = service

    def _touch(self) -> None:
        self._service.invalidate_status_cache()

    def terminate_process(self, pid: int) -> dict[str, Any]:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            proc.terminate()
            proc.wait(timeout=5)
            self._service.event_bus.emit(
                ResourceType.PROCESS, PolicyAction.BLOCK, name, str(pid),
                f"User terminated AI process {name} (PID {pid})",
                EventSeverity.WARNING, user_decision="block",
            )
            self._touch()
            return {"ok": True, "pid": pid, "name": name}
        except psutil.NoSuchProcess:
            return {"ok": False, "error": "Process not found"}
        except psutil.AccessDenied:
            return {"ok": False, "error": "Access denied — run as administrator"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def set_app_policy(self, app_name: str, action: str) -> dict[str, Any]:
        policies = {
            "default": action, "files": action, "network": action,
            "clipboard": action, "microphone": action, "camera": action,
        }
        self._service.permissions.set_app_policy(app_name, policies)
        self._service.event_bus.emit(
            ResourceType.PROCESS, PolicyAction(action), app_name, app_name,
            f"User set {app_name} policy to {action}",
            EventSeverity.INFO, user_decision=action,
        )
        return {"ok": True, "app_name": app_name, "policy": action}

    def set_folder_policy(self, folder_name: str, policy: str) -> dict[str, Any]:
        folders = self._service.config.get("protected_folders", [])
        found = False
        for folder in folders:
            if folder["name"] == folder_name:
                folder["policy"] = policy
                found = True
                break
        if not found:
            return {"ok": False, "error": f"Folder '{folder_name}' not found"}

        save_user_config({"protected_folders": folders})
        self._reload_folders()
        self._service.event_bus.emit(
            ResourceType.FILE, PolicyAction(policy), "User", folder_name,
            f"Folder '{folder_name}' policy set to {policy}",
            EventSeverity.INFO, user_decision=policy,
        )
        return {"ok": True, "folder": folder_name, "policy": policy}

    def add_protected_folder(self, name: str, path: str, policy: str = "ask") -> dict[str, Any]:
        path = str(Path(path).resolve())
        folders = list(self._service.config.get("protected_folders", []))
        for f in folders:
            if f["path"] == path or f["name"] == name:
                return {"ok": False, "error": "Folder already protected"}

        folders.append({"name": name, "path": path, "policy": policy})
        save_user_config({"protected_folders": folders})
        self._service.config["protected_folders"] = folders
        self._reload_folders()

        Path(path).mkdir(parents=True, exist_ok=True)
        return {"ok": True, "name": name, "path": path, "policy": policy}

    def set_global_policy(self, key: str, value: str) -> dict[str, Any]:
        result = self.set_global_policies({key: value})
        if not result.get("ok"):
            return result
        return {"ok": True, "key": key, "value": value}

    def set_global_policies(self, policies: dict[str, str]) -> dict[str, Any]:
        allowed = {
            "network_policy", "clipboard_policy", "screenshot_policy",
            "microphone_policy", "camera_policy", "global_policy",
        }
        clean: dict[str, str] = {}
        for key, value in policies.items():
            if key not in allowed:
                return {"ok": False, "error": f"Unknown policy key: {key}"}
            if value not in {"allow", "ask", "block"}:
                return {"ok": False, "error": f"Invalid policy value: {value}"}
            clean[key] = value

        save_user_config(clean)
        self._service.reload_config()

        self._service.event_bus.emit(
            ResourceType.FILE, PolicyAction.ASK, "User", "global_policies",
            f"Updated global policies: {', '.join(clean.keys())}", EventSeverity.INFO,
        )
        self._service.invalidate_status_cache()
        return {"ok": True, "updated": list(clean.keys())}

    def block_all_ai_domains(self) -> dict[str, Any]:
        blocked = []
        failed = []
        for domain in self._service.config.get("ai_domains", []):
            if self._service._network.block_domain(domain):
                blocked.append(domain)
            else:
                failed.append(domain)
        return {"ok": len(failed) == 0, "blocked": blocked, "failed": failed}

    def block_ai_websites(self) -> dict[str, Any]:
        ok = self._service.browser.block_ai_domains_hosts()
        return {"ok": ok, "message": "Hosts file updated" if ok else "Requires administrator"}

    def block_connection(self, pid: int) -> dict[str, Any]:
        return self.terminate_process(pid)

    def unblock_domain(self, domain: str) -> dict[str, Any]:
        ok = self._service._network.unblock_domain(domain)
        return {"ok": ok, "domain": domain}

    def _reload_folders(self) -> None:
        self._service.config = load_merged_config()
        self._service._folders = get_protected_folders(self._service.config)
        try:
            self._service._file_guard.stop()
            self._service._file_guard = FileAccessGuard(
                self._service._folders,
                self._service.event_bus,
                self._service._get_primary_ai_app,
                self._service.policy_resolver,
            )
            self._service._file_guard.start()
            self._service.reload_config(sync_minifilter=True)
        except Exception as e:
            logger.warning("Could not reload file guard: %s", e)

    def get_app_policies(self) -> list[dict[str, Any]]:
        return self._service.permissions.get_app_policies()

    def remove_protected_folder(self, folder_name: str) -> dict[str, Any]:
        folders = list(self._service.config.get("protected_folders", []))
        new_folders = [f for f in folders if f["name"] != folder_name]
        if len(new_folders) == len(folders):
            return {"ok": False, "error": f"Folder '{folder_name}' not found"}

        save_user_config({"protected_folders": new_folders})
        self._reload_folders()
        self._service.event_bus.emit(
            ResourceType.FILE, PolicyAction.BLOCK, "User", folder_name,
            f"Removed protected folder '{folder_name}'",
            EventSeverity.INFO,
        )
        return {"ok": True, "folder": folder_name}

    def remove_app_policy(self, app_name: str) -> dict[str, Any]:
        removed = self._service.permissions.remove_app_policy(app_name)
        if not removed:
            return {"ok": False, "error": f"No saved policy for '{app_name}'"}
        self._service.event_bus.emit(
            ResourceType.PROCESS, PolicyAction.ASK, app_name, app_name,
            f"Removed saved policy for {app_name}",
            EventSeverity.INFO,
        )
        return {"ok": True, "app_name": app_name}

    def set_app_resource_policy(
        self, app_name: str, resource: str, value: str,
    ) -> dict[str, Any]:
        allowed_resources = {"default", "files", "network", "clipboard", "microphone", "camera"}
        if resource not in allowed_resources:
            return {"ok": False, "error": f"Unknown resource: {resource}"}
        if value not in {"allow", "ask", "block"}:
            return {"ok": False, "error": f"Invalid policy: {value}"}

        existing = {p["app_name"]: p for p in self.get_app_policies()}.get(app_name, {})
        policies = {
            "default": existing.get("default_action", "ask"),
            "files": existing.get("files", "ask"),
            "network": existing.get("network", "ask"),
            "clipboard": existing.get("clipboard", "ask"),
            "microphone": existing.get("microphone", "ask"),
            "camera": existing.get("camera", "ask"),
        }
        policies[resource] = value
        self._service.permissions.set_app_policy(app_name, policies)
        return {"ok": True, "app_name": app_name, "resource": resource, "policy": value}

    def lockdown_mode(self) -> dict[str, Any]:
        self.set_global_policies({
            "network_policy": "block",
            "clipboard_policy": "block",
            "screenshot_policy": "block",
            "microphone_policy": "block",
            "camera_policy": "block",
        })
        domains = self.block_all_ai_domains()
        return {
            "ok": True,
            "message": "Lockdown enabled — AI network, clipboard, and device access blocked",
            "domains": domains,
        }

    def restore_defaults(self) -> dict[str, Any]:
        self.set_global_policies({
            "network_policy": "ask",
            "clipboard_policy": "ask",
            "screenshot_policy": "ask",
            "microphone_policy": "ask",
            "camera_policy": "ask",
        })
        return {"ok": True, "message": "Policies restored to Ask mode"}

    def terminate_all_ai(self) -> dict[str, Any]:
        terminated: list[int] = []
        failed: list[dict[str, Any]] = []
        targets = self._service._summarize_processes(
            list(self._service._process_monitor.ai_processes),
        )
        for proc in targets:
            result = self.terminate_process(proc.pid)
            if result.get("ok"):
                terminated.append(proc.pid)
            else:
                failed.append({"pid": proc.pid, "error": result.get("error", "Failed")})
        return {
            "ok": len(failed) == 0,
            "terminated": terminated,
            "failed": failed,
            "message": f"Stopped {len(terminated)} AI process(es)",
        }
