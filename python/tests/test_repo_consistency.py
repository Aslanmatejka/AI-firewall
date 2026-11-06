"""Checks that keep the repo's duplicated facts in step."""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

import aishield
from aishield.enterprise.policy_client import is_allowed_policy_url


class VersionTests(unittest.TestCase):
    def test_python_and_dotnet_versions_match(self) -> None:
        props = (ROOT / "csharp" / "Directory.Build.props").read_text(encoding="utf-8")
        match = re.search(r"<Version>([^<]+)</Version>", props)
        self.assertIsNotNone(match)
        self.assertEqual(aishield.__version__, match.group(1))


class PolicyUrlTests(unittest.TestCase):
    def test_accepts_https_and_loopback_http(self) -> None:
        self.assertTrue(is_allowed_policy_url("https://policy.example.com/policy.json"))
        self.assertTrue(is_allowed_policy_url("http://127.0.0.1:9480/policy.json"))

    def test_refuses_everything_else(self) -> None:
        for url in (
            "http://policy.example.com/policy.json",
            "file:///C:/Windows/win.ini",
            "ftp://policy.example.com/policy.json",
            "http://127.0.0.1.evil.example/policy.json",
            "https://",
            "not a url",
            "",
        ):
            self.assertFalse(is_allowed_policy_url(url), url)


if __name__ == "__main__":
    unittest.main()
