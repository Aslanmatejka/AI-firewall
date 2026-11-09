"""Configuration loading and path expansion."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from .models import PolicyAction, ProtectedFolder


logger = logging.getLogger(__name__)

# A path under %USERPROFILE% is wrong on PCs where OneDrive or a policy moved the folder.
_KNOWN_FOLDERS = {
    "%DOCUMENTS%": ("FOLDERID_Documents", "Documents"),
    "%PICTURES%": ("FOLDERID_Pictures", "Pictures"),
}


def _known_folder(folder_id: str, fallback: str) -> str:
    try:
        from win32com.shell import shell, shellcon

        return shell.SHGetKnownFolderPath(getattr(shellcon, folder_id))
    except Exception as e:
        logger.warning("Could not look up %s, using the default location: %s", folder_id, e)
        return str(Path.home() / fallback)


def _expand_path(path: str) -> str:
    for token, (folder_id, fallback) in _KNOWN_FOLDERS.items():
        if token in path:
            path = path.replace(token, _known_folder(folder_id, fallback))
    return os.path.expandvars(os.path.expanduser(path))


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    if config_path is None:
        config_path = _project_root() / "config" / "default.json"
    with open(config_path, encoding="utf-8") as f:
        cfg = json.load(f)

    for folder in cfg.get("protected_folders", []):
        folder["path"] = _expand_path(folder["path"])

    return cfg


def get_protected_folders(cfg: dict[str, Any]) -> list[ProtectedFolder]:
    folders = []
    for item in cfg.get("protected_folders", []):
        try:
            policy = PolicyAction(item.get("policy", "ask"))
        except ValueError:
            logger.warning("Folder %s has an invalid policy, using ask", item["name"])
            policy = PolicyAction.ASK
        folders.append(ProtectedFolder(name=item["name"], path=item["path"], policy=policy))
    return folders


def get_data_dir() -> Path:
    base = Path(os.environ.get("APPDATA", Path.home())) / "AiShield"
    base.mkdir(parents=True, exist_ok=True)
    return base
