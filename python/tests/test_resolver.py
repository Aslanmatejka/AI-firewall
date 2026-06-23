"""Tests for policy resolution."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aishield.core.models import PolicyAction, ResourceType
from aishield.permissions.manager import PermissionManager
from aishield.permissions.resolver import PolicyResolver


class PolicyResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        import aishield.core.config as cfg
        import aishield.permissions.manager as mgr

        self._data_dir = Path(self._tmp.name)
        self._orig_cfg = cfg.get_data_dir
        self._orig_mgr = mgr.get_data_dir
        cfg.get_data_dir = lambda: self._data_dir
        mgr.get_data_dir = cfg.get_data_dir
        self.perms = PermissionManager()
        self.config = {
            "global_policy": "ask",
            "network_policy": "block",
            "clipboard_policy": "allow",
            "fail_closed": False,
        }
        self.resolver = PolicyResolver(self.config, self.perms)

    def tearDown(self) -> None:
        import aishield.core.config as cfg
        import aishield.permissions.manager as mgr

        cfg.get_data_dir = self._orig_cfg
        mgr.get_data_dir = self._orig_mgr
        db = self._data_dir / "permissions.db"
        enc = db.with_suffix(db.suffix + ".dpapi")
        for path in (db, enc):
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass
        self._tmp.cleanup()

    def test_global_network_block(self) -> None:
        p = self.resolver.for_access("Cursor", ResourceType.NETWORK)
        self.assertEqual(p, PolicyAction.BLOCK)

    def test_app_policy_overrides_global(self) -> None:
        self.perms.set_app_policy("Cursor", {"default": "ask", "network": "allow"})
        p = self.resolver.for_access("Cursor", ResourceType.NETWORK)
        self.assertEqual(p, PolicyAction.ALLOW)


if __name__ == "__main__":
    unittest.main()
