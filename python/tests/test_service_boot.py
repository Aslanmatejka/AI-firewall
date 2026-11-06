"""Boot the real service, with every real guard, against an isolated data folder."""

from __future__ import annotations

import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

PYTHON_DIR = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ServiceBootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.addClassCleanup(cls._tmp.cleanup)
        cls.data_dir = Path(cls._tmp.name) / "AiShield"
        cls.data_dir.mkdir()
        # No protected folders, so the real guards can't act on anything on this PC.
        (cls.data_dir / "user_config.json").write_text(
            json.dumps({"protected_folders": []}), encoding="utf-8",
        )
        cls.port = free_port()
        cls.log = (Path(cls._tmp.name) / "service.log").open("w", encoding="utf-8")
        cls.addClassCleanup(cls.log.close)
        env = {**os.environ, "APPDATA": cls._tmp.name, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"}
        cls.proc = subprocess.Popen(
            [sys.executable, "-m", "aishield", "--port", str(cls.port), "--log-level", "WARNING"],
            cwd=PYTHON_DIR, env=env, stdout=cls.log, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        cls.addClassCleanup(cls.proc.kill)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if cls.proc.poll() is not None:
                raise AssertionError(f"Service exited early: {cls.proc.returncode}")
            try:
                if cls.request("GET", "/api/health")[0] == 200 and cls.token_path().exists():
                    return
            except OSError:
                pass
            time.sleep(0.25)
        raise AssertionError("Service never became healthy")

    @classmethod
    def token_path(cls) -> Path:
        return cls.data_dir / "api-token.json"

    @classmethod
    def request(cls, method: str, path: str, headers: dict | None = None) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=30)
        try:
            conn.request(method, path, headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def auth(self) -> dict:
        token = json.loads(self.token_path().read_text(encoding="utf-8"))["token"]
        return {"Authorization": f"Bearer {token}"}

    def test_01_health_is_ok(self) -> None:
        status, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["ok"])

    def test_02_token_file_names_the_real_port(self) -> None:
        self.assertEqual(json.loads(self.token_path().read_text(encoding="utf-8"))["port"], self.port)

    def test_03_no_credential_no_data(self) -> None:
        self.assertEqual(self.request("GET", "/api/status")[0], 401)
        self.assertEqual(self.request("POST", "/api/approve/x?allow=true")[0], 401)
        self.assertEqual(self.request("GET", "/")[0], 401)

    def test_04_rebound_host_is_refused(self) -> None:
        status, _ = self.request("GET", "/api/status", {**self.auth(), "Host": "evil.example"})
        self.assertEqual(status, 403)

    def test_05_real_status_with_token(self) -> None:
        status, body = self.request("GET", "/api/status", self.auth())
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data["running"])
        self.assertEqual(data["protected_folders"], [])

    def test_06_sign_in_link_opens_the_page(self) -> None:
        status, body = self.request("POST", "/api/login-code", self.auth())
        self.assertEqual(status, 200)
        path = json.loads(body)["url"].split(f":{self.port}", 1)[1]
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        self.addCleanup(conn.close)
        conn.request("GET", path)
        response = conn.getresponse()
        response.read()
        self.assertEqual(response.status, 303)
        cookie = response.getheader("set-cookie").split(";", 1)[0]
        conn.request("GET", "/", headers={"Cookie": cookie})
        page = conn.getresponse()
        self.assertEqual(page.status, 200)
        self.assertIn(b"AI Firewall", page.read())

    def test_07_no_guard_crashed(self) -> None:
        self.log.flush()
        self.assertIsNone(self.proc.poll())
        text = Path(self.log.name).read_text(encoding="utf-8")
        self.assertNotIn("Traceback", text)

    def test_08_clean_stop_removes_the_token_file(self) -> None:
        self.proc.send_signal(signal.CTRL_BREAK_EVENT)
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.fail("Service didn't stop after CTRL+BREAK")
        self.assertEqual(self.proc.returncode, 0)
        self.assertFalse(self.token_path().exists())


class RefusalTests(unittest.TestCase):
    def test_refuses_to_listen_beyond_this_pc(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            env = {**os.environ, "APPDATA": tmp, "PYTHONDONTWRITEBYTECODE": "1"}
            result = subprocess.run(
                [sys.executable, "-m", "aishield", "--host", "0.0.0.0", "--port", str(free_port())],
                cwd=PYTHON_DIR, env=env, capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("only for this PC", result.stderr)


if __name__ == "__main__":
    unittest.main()
