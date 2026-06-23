"""Tests for WFP bridge helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aishield.native.wfp_bridge import WfpEngine


class WfpBridgeTests(unittest.TestCase):
    def test_ip_to_uint32(self) -> None:
        self.assertEqual(WfpEngine._ip_to_uint32("8.8.8.8"), 0x08080808)
        self.assertIsNone(WfpEngine._ip_to_uint32("not-an-ip"))
        self.assertIsNone(WfpEngine._ip_to_uint32("::1"))

    def test_engine_available_on_windows(self) -> None:
        engine = WfpEngine()
        # fwpuclnt.dll exists on Windows even without admin
        if engine.available:
            self.assertIsNotNone(engine._dll)


if __name__ == "__main__":
    unittest.main()
