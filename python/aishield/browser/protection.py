"""Browser extension and AI website protection."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from ..core.models import EventSeverity, PolicyAction, ResourceType
from ..core.events import EventBus

logger = logging.getLogger(__name__)

BROWSER_EXTENSION_PATHS = [
    Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/User Data/Default/Extensions",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/Edge/User Data/Default/Extensions",
    Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/Profiles",
]


class BrowserProtection:
    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        self._config = config
        self._bus = event_bus
        self._patterns = [p.lower() for p in config.get("ai_extension_patterns", [])]
        self._domains = config.get("ai_domains", [])
        self._detected_extensions: list[dict[str, str]] = []

    def scan_extensions(self) -> list[dict[str, str]]:
        found = []
        for base in BROWSER_EXTENSION_PATHS:
            if not base.exists():
                continue
            try:
                if "Firefox" in str(base):
                    found.extend(self._scan_firefox(base))
                else:
                    found.extend(self._scan_chromium(base))
            except (PermissionError, OSError) as e:
                logger.debug("Cannot scan %s: %s", base, e)

        self._detected_extensions = found
        for ext in found:
            self._bus.emit(
                ResourceType.NETWORK, PolicyAction.ASK, ext.get("browser", "Browser"),
                ext.get("name", ext.get("id", "unknown")),
                f"AI browser extension detected: {ext.get('name', ext['id'])}",
                EventSeverity.WARNING,
            )
        return found

    def _scan_chromium(self, ext_dir: Path) -> list[dict[str, str]]:
        results = []
        browser = "Chrome" if "Chrome" in str(ext_dir) else "Edge"
        for ext_id_dir in ext_dir.iterdir():
            if not ext_id_dir.is_dir():
                continue
            for version_dir in ext_id_dir.iterdir():
                manifest = version_dir / "manifest.json"
                if not manifest.exists():
                    continue
                try:
                    data = json.loads(manifest.read_text(encoding="utf-8"))
                    name = data.get("name", ext_id_dir.name).lower()
                    if any(p in name for p in self._patterns):
                        results.append({
                            "browser": browser,
                            "id": ext_id_dir.name,
                            "name": data.get("name", ext_id_dir.name),
                            "path": str(version_dir),
                        })
                except (json.JSONDecodeError, OSError):
                    continue
                break
        return results

    def _scan_firefox(self, profiles_dir: Path) -> list[dict[str, str]]:
        results = []
        for profile in profiles_dir.iterdir():
            ext_json = profile / "extensions.json"
            if not ext_json.exists():
                continue
            try:
                data = json.loads(ext_json.read_text(encoding="utf-8"))
                for addon in data.get("addons", []):
                    name = (addon.get("defaultLocale", {}).get("name") or "").lower()
                    if any(p in name for p in self._patterns):
                        results.append({
                            "browser": "Firefox",
                            "id": addon.get("id", "unknown"),
                            "name": addon.get("defaultLocale", {}).get("name", "unknown"),
                            "path": str(profile),
                        })
            except (json.JSONDecodeError, OSError):
                continue
        return results

    @property
    def detected_extensions(self) -> list[dict[str, str]]:
        return list(self._detected_extensions)

    def block_ai_domains_hosts(self) -> bool:
        """Add AI domains to hosts file (requires admin). Redirect to 127.0.0.1."""
        hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")
        marker = "# AiShield blocked domains"
        try:
            content = hosts_path.read_text(encoding="utf-8")
            if marker in content:
                return True
            lines = [marker]
            for domain in self._domains:
                lines.append(f"127.0.0.1 {domain}")
                lines.append(f"127.0.0.1 www.{domain}")
            with open(hosts_path, "a", encoding="utf-8") as f:
                f.write("\n" + "\n".join(lines) + "\n")
            logger.info("Added %d AI domains to hosts file", len(self._domains))
            return True
        except PermissionError:
            logger.warning("Admin required to modify hosts file")
            return False
