"""Permission manager — persistent policy and audit log."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..core.config import get_data_dir
from ..core.models import PolicyAction, ResourceType, ShieldEvent
from ..security.dpapi import load_or_decrypt_db, seal_db

logger = logging.getLogger(__name__)


class PermissionManager:
    def __init__(self, encrypt_at_rest: bool = True) -> None:
        self._db_path = get_data_dir() / "permissions.db"
        self._encrypt_at_rest = encrypt_at_rest
        self._lock = threading.Lock()
        self._stats_cache: tuple[float, dict[str, int]] | None = None
        self._app_policies_cache: tuple[float, list[dict[str, Any]]] | None = None
        load_or_decrypt_db(self._db_path)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS grants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_pattern TEXT NOT NULL,
                    action TEXT NOT NULL,
                    granted_at TEXT NOT NULL,
                    expires_at TEXT,
                    UNIQUE(app_name, resource_type, resource_pattern)
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    app_name TEXT,
                    resource_type TEXT,
                    resource TEXT,
                    action TEXT,
                    decision TEXT,
                    message TEXT
                );
                CREATE TABLE IF NOT EXISTS app_policies (
                    app_name TEXT PRIMARY KEY,
                    default_action TEXT NOT NULL,
                    microphone TEXT DEFAULT 'ask',
                    camera TEXT DEFAULT 'ask',
                    files TEXT DEFAULT 'ask',
                    network TEXT DEFAULT 'ask',
                    clipboard TEXT DEFAULT 'ask'
                );
                CREATE INDEX IF NOT EXISTS idx_audit_log_id ON audit_log(id DESC);
            """)

    def log_event(self, event: ShieldEvent) -> None:
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "INSERT INTO audit_log (timestamp, app_name, resource_type, resource, action, decision, message) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event.timestamp.isoformat(),
                    event.source_app,
                    event.resource_type.value,
                    event.resource,
                    event.action.value,
                    event.user_decision,
                    event.message,
                ),
            )
        self._stats_cache = None

    def get_grant(
        self, app_name: str, resource_type: ResourceType, resource: str,
    ) -> PolicyAction | None:
        with self._lock, sqlite3.connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT action, expires_at FROM grants "
                "WHERE app_name = ? AND resource_type = ? AND ? LIKE resource_pattern "
                "AND (expires_at IS NULL OR expires_at > ?)",
                (app_name, resource_type.value, resource, datetime.now().isoformat()),
            ).fetchone()
            if row:
                return PolicyAction(row[0])
        return None

    def grant(
        self,
        app_name: str,
        resource_type: ResourceType,
        resource_pattern: str,
        action: PolicyAction,
        hours: int | None = None,
    ) -> None:
        expires = (datetime.now() + timedelta(hours=hours)).isoformat() if hours else None
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO grants (app_name, resource_type, resource_pattern, action, granted_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (app_name, resource_type.value, resource_pattern, action.value,
                 datetime.now().isoformat(), expires),
            )

    def set_app_policy(self, app_name: str, policies: dict[str, str]) -> None:
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO app_policies "
                "(app_name, default_action, microphone, camera, files, network, clipboard) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    app_name,
                    policies.get("default", "ask"),
                    policies.get("microphone", "ask"),
                    policies.get("camera", "ask"),
                    policies.get("files", "ask"),
                    policies.get("network", "ask"),
                    policies.get("clipboard", "ask"),
                ),
            )
        self._app_policies_cache = None

    def get_audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_app_policies(self) -> list[dict[str, Any]]:
        now = time.time()
        if self._app_policies_cache and now - self._app_policies_cache[0] < 5.0:
            return self._app_policies_cache[1]
        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM app_policies").fetchall()
            policies = [dict(r) for r in rows]
        self._app_policies_cache = (now, policies)
        return policies

    def get_app_resource_policy(
        self, app_name: str, resource_type: ResourceType,
    ) -> PolicyAction | None:
        column = {
            ResourceType.FILE: "files",
            ResourceType.NETWORK: "network",
            ResourceType.CLIPBOARD: "clipboard",
            ResourceType.MICROPHONE: "microphone",
            ResourceType.CAMERA: "camera",
            ResourceType.SCREENSHOT: "default_action",
            ResourceType.PROCESS: "default_action",
        }.get(resource_type, "default_action")

        with self._lock, sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM app_policies WHERE app_name = ?", (app_name,),
            ).fetchone()
            if not row:
                return None
            raw = row[column] if column in row.keys() else row["default_action"]
            try:
                return PolicyAction(raw)
            except ValueError:
                return None

    def remove_app_policy(self, app_name: str) -> bool:
        with self._lock, sqlite3.connect(self._db_path) as conn:
            cur = conn.execute("DELETE FROM app_policies WHERE app_name = ?", (app_name,))
            deleted = cur.rowcount > 0
        if deleted:
            self._app_policies_cache = None
        return deleted

    def export_audit_csv(self, limit: int = 1000) -> str:
        rows = self.get_audit_log(limit)
        lines = ["timestamp,app_name,resource_type,resource,action,decision,message"]
        for row in reversed(rows):
            def esc(val: Any) -> str:
                s = str(val or "").replace('"', '""')
                return f'"{s}"' if "," in s or '"' in s else s

            lines.append(",".join([
                esc(row.get("timestamp")),
                esc(row.get("app_name")),
                esc(row.get("resource_type")),
                esc(row.get("resource")),
                esc(row.get("action")),
                esc(row.get("decision")),
                esc(row.get("message")),
            ]))
        return "\n".join(lines)

    def get_stats(self) -> dict[str, int]:
        now = time.time()
        if self._stats_cache and now - self._stats_cache[0] < 2.0:
            return self._stats_cache[1]
        with self._lock, sqlite3.connect(self._db_path) as conn:
            grants = conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0]
            audits = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            blocked = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE decision = 'block' OR action = 'block'"
            ).fetchone()[0]
            stats = {"grants": grants, "audit_entries": audits, "blocked": blocked}
        self._stats_cache = (now, stats)
        return stats

    def seal(self) -> None:
        seal_db(self._db_path, self._encrypt_at_rest)
