"""Access control for the local dashboard API.

API clients such as the desktop app present a per-run token read from a file
only this user can open. Browsers sign in with a one-time link and then hold an
HttpOnly session cookie, so page scripts and other sites never see a credential.

This stops other websites and casual local scripts. It can't stop software that
already runs as this user, which could read the token file: real same-user
protection needs the SYSTEM service planned for M2.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

from ..core.config import get_data_dir

SESSION_COOKIE = "aishield_session"
LOGIN_CODE_TTL_SECONDS = 120.0
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def api_token_path() -> Path:
    return get_data_dir() / "api-token.json"


def _constant_time_equal(given: str | None, expected: str) -> bool:
    if not given:
        return False
    return hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8"))


class ApiSecurity:
    def __init__(self, port: int) -> None:
        self.port = port
        self.token = secrets.token_urlsafe(32)
        self.session = secrets.token_urlsafe(32)
        self.allowed_hosts = frozenset({f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"})
        self.allowed_origins = frozenset(f"http://{host}" for host in self.allowed_hosts)
        self._login_codes: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_valid_token(self, value: str | None) -> bool:
        return _constant_time_equal(value, self.token)

    def is_valid_session(self, value: str | None) -> bool:
        return _constant_time_equal(value, self.session)

    def new_login_url(self) -> str:
        code = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            self._login_codes = {c: exp for c, exp in self._login_codes.items() if exp > now}
            self._login_codes[code] = now + LOGIN_CODE_TTL_SECONDS
        return f"http://127.0.0.1:{self.port}/login?code={code}"

    def redeem_login_code(self, code: str) -> bool:
        """Each code works once and expires quickly, so a copied link is worth little."""
        with self._lock:
            expires = self._login_codes.pop(code, None)
        return expires is not None and expires > time.monotonic()

    def write_token_file(self, path: Path) -> None:
        temp = path.with_name(path.name + ".tmp")
        temp.write_text(json.dumps({"token": self.token, "port": self.port}), encoding="utf-8")
        os.replace(temp, path)
