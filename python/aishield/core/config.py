"""Configuration loading and path expansion."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .models import PolicyAction, ProtectedFolder


def _expand_path(path: str) -> str:
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
        path = item["path"]
        if not Path(path).exists():
            try:
                Path(path).mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
        folders.append(
            ProtectedFolder(
                name=item["name"],
                path=path,
                policy=PolicyAction(item.get("policy", "ask")),
            )
        )
    return folders


def get_data_dir() -> Path:
    base = Path(os.environ.get("APPDATA", Path.home())) / "AiShield"
    base.mkdir(parents=True, exist_ok=True)
    return base
