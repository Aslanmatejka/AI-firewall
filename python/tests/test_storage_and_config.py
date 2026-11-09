"""Stored data stays honest, secrets stay out of it, and settings changes actually work."""

from __future__ import annotations

import csv
import io
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aishield.actions.shield_actions import ShieldActions
from aishield.core import config as config_module
from aishield.core import user_config
from aishield.core.events import EventBus
from aishield.core.models import PolicyAction, ResourceType, ShieldEvent, EventSeverity
from aishield.guard.clipboard_guard import ClipboardGuard, classify_sensitive
from aishield.permissions import manager as manager_module
from aishield.permissions.manager import PermissionManager
from aishield.security import dpapi

SENTINEL = "sk-SENTINELSECRET1234567890abcdef"


class TempDataDir(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.data_dir = Path(tmp.name)
        for module in (manager_module, user_config):
            patcher = mock.patch.object(module, "get_data_dir", return_value=self.data_dir)
            patcher.start()
            self.addCleanup(patcher.stop)

    def db_rows(self, sql: str) -> list:
        conn = sqlite3.connect(self.data_dir / "permissions.db")
        try:
            return conn.execute(sql).fetchall()
        finally:
            conn.close()

    def db_bytes(self) -> bytes:
        return b"".join(p.read_bytes() for p in self.data_dir.glob("permissions.db*"))


class GrantTests(TempDataDir):
    def test_wildcard_characters_in_a_filename_stay_literal(self) -> None:
        manager = PermissionManager(encrypt_at_rest=False)
        manager.grant("AI", ResourceType.FILE, "C:\\docs\\100%_report.txt", PolicyAction.ALLOW)
        self.assertEqual(
            manager.get_grant("AI", ResourceType.FILE, "C:\\docs\\100%_report.txt"), PolicyAction.ALLOW,
        )
        self.assertIsNone(manager.get_grant("AI", ResourceType.FILE, "C:\\docs\\100 percent secrets.txt"))

    def test_path_case_doesnt_matter(self) -> None:
        manager = PermissionManager(encrypt_at_rest=False)
        manager.grant("AI", ResourceType.FILE, "C:\\Docs\\A.txt", PolicyAction.ALLOW)
        self.assertEqual(manager.get_grant("AI", ResourceType.FILE, "c:\\docs\\a.txt"), PolicyAction.ALLOW)


class CsvTests(TempDataDir):
    def test_formula_cells_are_neutralized(self) -> None:
        manager = PermissionManager(encrypt_at_rest=False)
        manager.log_event(ShieldEvent(
            id="1", timestamp=datetime.now(), severity=EventSeverity.INFO,
            resource_type=ResourceType.FILE, action=PolicyAction.ASK,
            source_app='=HYPERLINK("http://evil.example")', resource="+1,2\nnext", message="@SUM(A1)",
        ))
        rows = list(csv.DictReader(io.StringIO(manager.export_audit_csv())))
        self.assertEqual(rows[0]["app_name"], '\'=HYPERLINK("http://evil.example")')
        self.assertEqual(rows[0]["resource"], "'+1,2\nnext")
        self.assertEqual(rows[0]["message"], "'@SUM(A1)")

    def test_header_comes_first(self) -> None:
        manager = PermissionManager(encrypt_at_rest=False)
        self.assertEqual(
            manager.export_audit_csv(),
            "timestamp,app_name,resource_type,resource,action,decision,message",
        )


class ClipboardSecrecyTests(TempDataDir):
    def test_label_never_contains_the_text(self) -> None:
        for text in (SENTINEL, f"password={SENTINEL}", "x" * 600, f"token {SENTINEL}"):
            label = classify_sensitive(text)
            self.assertIsNotNone(label)
            self.assertNotIn(SENTINEL, label)
            self.assertNotIn("xxx", label)
        self.assertIsNone(classify_sensitive("just some ordinary text"))

    def test_secret_reaches_no_event_grant_or_database(self) -> None:
        manager = PermissionManager(encrypt_at_rest=False)
        bus = EventBus(approval_timeout=5)
        events: list[ShieldEvent] = []
        bus.subscribe(events.append)
        bus.subscribe(manager.log_event)
        seen: list = []

        def approve_and_grant(request) -> PolicyAction:
            seen.append(request)
            manager.grant(request.app_name, request.resource_type, request.resource_path,
                          PolicyAction.ALLOW, hours=24)
            return PolicyAction.BLOCK

        bus.on_approval(approve_and_grant)
        resolver = SimpleNamespace(for_access=lambda *_a, **_k: PolicyAction.ASK)
        guard = ClipboardGuard(
            {}, bus, lambda: True, lambda: ("AI", 5), resolver, lambda: {5}, lambda: True,
        )
        guard._running = True
        with mock.patch.object(guard, "_get_clipboard_text", return_value=f"api_key={SENTINEL}"), \
                mock.patch.object(guard, "_clear_clipboard"):
            guard._handle_clipboard_change()

        self.assertEqual(len(seen), 1, "the secret should have triggered a prompt")
        self.assertNotIn(SENTINEL, seen[0].resource_path)
        for event in events:
            self.assertNotIn(SENTINEL, event.resource)
            self.assertNotIn(SENTINEL, event.message)
        self.assertNotIn(SENTINEL.encode(), self.db_bytes())

    def test_text_stored_by_older_versions_is_scrubbed(self) -> None:
        PermissionManager(encrypt_at_rest=False)
        conn = sqlite3.connect(self.data_dir / "permissions.db")
        conn.execute(
            "INSERT INTO audit_log (timestamp, app_name, resource_type, resource, action, decision, message) "
            "VALUES ('t', 'AI', 'clipboard', ?, 'ask', NULL, 'm')", (SENTINEL,),
        )
        conn.execute(
            "INSERT INTO grants (app_name, resource_type, resource_pattern, action, granted_at) "
            "VALUES ('AI', 'clipboard', ?, 'allow', 't')", (SENTINEL,),
        )
        conn.execute(
            "INSERT INTO audit_log (timestamp, app_name, resource_type, resource, action, decision, message) "
            "VALUES ('t', 'AI', 'file', 'C:\\keep.txt', 'ask', NULL, 'm')",
        )
        conn.commit()
        conn.close()

        PermissionManager(encrypt_at_rest=False)

        self.assertEqual(self.db_rows("SELECT COUNT(*) FROM grants WHERE resource_type = 'clipboard'"), [(0,)])
        self.assertEqual(
            self.db_rows("SELECT resource FROM audit_log ORDER BY id"),
            [("clipboard: redacted",), ("C:\\keep.txt",)],
        )
        self.assertNotIn(SENTINEL.encode(), self.db_bytes())


class DpapiTests(TempDataDir):
    def test_failed_encryption_writes_no_plaintext_copy(self) -> None:
        db = self.data_dir / "x.db"
        db.write_bytes(b"plaintext contents")
        fake = SimpleNamespace(CryptProtectData=mock.Mock(side_effect=OSError("no DPAPI")))
        with mock.patch.dict(sys.modules, {"win32crypt": fake}):
            dpapi.seal_db(db)
        self.assertFalse(db.with_suffix(".db.dpapi").exists())

    def test_protect_raises_rather_than_returning_plaintext(self) -> None:
        fake = SimpleNamespace(CryptProtectData=mock.Mock(side_effect=OSError("no DPAPI")))
        with mock.patch.dict(sys.modules, {"win32crypt": fake}), self.assertRaises(OSError):
            dpapi.protect(b"secret")


class KnownFolderTests(unittest.TestCase):
    def test_tokens_use_the_real_folder_not_the_profile_guess(self) -> None:
        with mock.patch.object(config_module, "_known_folder", return_value="D:\\Redirected\\Docs"):
            self.assertEqual(config_module._expand_path("%DOCUMENTS%\\Passwords"), "D:\\Redirected\\Docs\\Passwords")

    def test_real_lookup_finds_an_existing_folder(self) -> None:
        self.assertTrue(os.path.isdir(config_module._expand_path("%DOCUMENTS%")))

    def test_default_config_has_no_stale_profile_paths(self) -> None:
        with mock.patch.object(config_module, "_known_folder", return_value="D:\\Docs"):
            cfg = config_module.load_config()
        paths = {f["name"]: f["path"] for f in cfg["protected_folders"]}
        self.assertEqual(paths["Documents"], "D:\\Docs")
        self.assertEqual(paths["Passwords"], "D:\\Docs\\Passwords")

    def test_loading_folders_creates_nothing_and_survives_a_bad_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "never-created"
            folders = config_module.get_protected_folders({
                "protected_folders": [{"name": "Gone", "path": str(missing), "policy": "maybe"}],
            })
            self.assertFalse(missing.exists())
            self.assertEqual(folders[0].policy, PolicyAction.ASK)


class FolderActionTests(TempDataDir):
    def actions(self, folders: list) -> tuple[ShieldActions, SimpleNamespace]:
        service = SimpleNamespace(
            config={"protected_folders": folders},
            event_bus=EventBus(approval_timeout=1),
            reload_config=mock.Mock(),
            invalidate_status_cache=mock.Mock(),
        )
        return ShieldActions(service), service

    def test_changing_a_folder_policy_saves_and_reloads(self) -> None:
        # This used to raise, because the service's config property has no setter.
        actions, service = self.actions([{"name": "Docs", "path": "C:\\Docs", "policy": "ask"}])
        result = actions.set_folder_policy("Docs", "block")
        self.assertTrue(result["ok"])
        service.reload_config.assert_called_once()
        saved = (self.data_dir / "user_config.json").read_text(encoding="utf-8")
        self.assertIn('"block"', saved)

    def test_invalid_policy_is_refused_before_it_can_be_saved(self) -> None:
        actions, _ = self.actions([{"name": "Docs", "path": "C:\\Docs", "policy": "ask"}])
        self.assertFalse(actions.set_folder_policy("Docs", "maybe")["ok"])
        self.assertFalse(actions.add_protected_folder("X", str(self.data_dir), "maybe")["ok"])
        self.assertFalse(actions.set_app_policy("AI", "maybe")["ok"])
        self.assertFalse((self.data_dir / "user_config.json").exists())

    def test_adding_a_missing_folder_is_refused_and_creates_nothing(self) -> None:
        actions, _ = self.actions([])
        missing = self.data_dir / "somewhere" / "new"
        self.assertFalse(actions.add_protected_folder("New", str(missing))["ok"])
        self.assertFalse(missing.exists())

    def test_adding_an_existing_folder_works(self) -> None:
        actions, service = self.actions([])
        self.assertTrue(actions.add_protected_folder("Here", str(self.data_dir))["ok"])
        service.reload_config.assert_called_once()


if __name__ == "__main__":
    unittest.main()
