"""User-editable config overrides stored in AppData."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .config import get_data_dir, load_config


def user_config_path() -> Path:
    return get_data_dir() / "user_config.json"


def load_merged_config() -> dict[str, Any]:
    cfg = load_config()
    path = user_config_path()
    if path.exists():
        with open(path, encoding="utf-8") as f:
            overrides = json.load(f)
        _deep_merge(cfg, overrides)
    return cfg


def save_user_config(overrides: dict[str, Any]) -> None:
    path = user_config_path()
    existing: dict[str, Any] = {}
    if path.exists():
        with open(path, encoding="utf-8") as f:
            existing = json.load(f)
    _deep_merge(existing, overrides)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)


def _deep_merge(base: dict, patch: dict) -> None:
    for k, v in patch.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
