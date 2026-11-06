"""The dashboard API must refuse other websites, scripts without a credential, and bad input."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.testclient import TestClient

from aishield.core.models import PolicyAction, ResourceType
from aishield.dashboard import security as security_module
from aishield.dashboard.security import SESSION_COOKIE, ApiSecurity
from aishield.dashboard.server import create_app
from test_api_approval import StubService

BASE_URL = "http://127.0.0.1:9470"
SAME_ORIGIN = {"Origin": BASE_URL}


class ApiSecurityTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.service = StubService()
        self.security = ApiSecurity(9470)
        self.client = TestClient(
            create_app(self.service, self.security), base_url=BASE_URL, follow_redirects=False,
        )
        self.auth = {"Authorization": f"Bearer {self.security.token}"}

    def sign_in(self) -> None:
        code = self.security.new_login_url().rsplit("code=", 1)[1]
        self.assertEqual(self.client.get(f"/login?code={code}").status_code, 303)

    def start_pending_request(self) -> str:
        thread = threading.Thread(
            target=self.service.event_bus.request_approval,
            args=("AI", 1, ResourceType.NETWORK, "x", PolicyAction.ASK),
            daemon=True,
        )
        thread.start()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            pending = self.service.event_bus.get_pending()
            if pending:
                return pending[0].id
            time.sleep(0.01)
        self.fail("request never became pending")


class CredentialTests(ApiSecurityTestCase):
    def test_every_data_route_needs_a_credential(self) -> None:
        for path in ("/api/status", "/api/config", "/api/events", "/api/audit", "/api/audit/export",
                     "/api/policies/apps", "/api/extensions", "/api/models"):
            self.assertEqual(self.client.get(path).status_code, 401, path)

    def test_tokenless_approve_is_refused_and_leaves_the_request_pending(self) -> None:
        request_id = self.start_pending_request()
        response = self.client.post(f"/api/approve/{request_id}?allow=true")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(len(self.service.event_bus.get_pending()), 1)
        self.service.event_bus.resolve_request(request_id, False)

    def test_wrong_token_is_refused(self) -> None:
        response = self.client.get("/api/status", headers={"Authorization": "Bearer wrong"})
        self.assertEqual(response.status_code, 401)

    def test_right_token_is_accepted(self) -> None:
        self.assertEqual(self.client.get("/api/status", headers=self.auth).status_code, 200)

    def test_health_is_public_but_reveals_nothing(self) -> None:
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.json()), {"ok", "running"})

    def test_generated_api_docs_are_gone(self) -> None:
        for path in ("/docs", "/redoc", "/openapi.json"):
            self.assertEqual(self.client.get(path, headers=self.auth).status_code, 404, path)


class HostAndOriginTests(ApiSecurityTestCase):
    def test_unexpected_host_is_refused_even_with_a_token(self) -> None:
        for host in ("evil.example", "127.0.0.1.evil.example:9470", "127.0.0.1", "localhost:80"):
            response = self.client.get("/api/status", headers={**self.auth, "Host": host})
            self.assertEqual(response.status_code, 403, host)

    def test_rebound_host_cant_reach_the_public_routes_either(self) -> None:
        response = self.client.get("/login?code=x", headers={"Host": "evil.example"})
        self.assertEqual(response.status_code, 403)

    def test_expected_hosts_are_accepted(self) -> None:
        for host in ("127.0.0.1:9470", "localhost:9470", "[::1]:9470", "LOCALHOST:9470"):
            response = self.client.get("/api/status", headers={**self.auth, "Host": host})
            self.assertEqual(response.status_code, 200, host)

    def test_cross_origin_post_is_refused_with_a_session(self) -> None:
        self.sign_in()
        response = self.client.post("/api/lockdown", headers={"Origin": "https://evil.example"})
        self.assertEqual(response.status_code, 403)

    def test_cross_origin_post_is_refused_with_a_token(self) -> None:
        response = self.client.post(
            "/api/lockdown", headers={**self.auth, "Origin": "https://evil.example"},
        )
        self.assertEqual(response.status_code, 403)

    def test_null_origin_is_refused(self) -> None:
        self.sign_in()
        response = self.client.post("/api/lockdown", headers={"Origin": "null"})
        self.assertEqual(response.status_code, 403)

    def test_session_post_without_origin_is_refused(self) -> None:
        self.sign_in()
        self.assertEqual(self.client.post("/api/lockdown").status_code, 403)

    def test_same_origin_session_post_is_accepted(self) -> None:
        self.sign_in()
        self.assertEqual(self.client.post("/api/lockdown", headers=SAME_ORIGIN).status_code, 200)


class SignInTests(ApiSecurityTestCase):
    def test_page_without_session_shows_only_how_to_sign_in(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 401)
        self.assertIn("open-dashboard.ps1", response.text)
        self.assertNotIn(self.security.token, response.text)
        self.assertNotIn("/api/approve", response.text)

    def test_signed_in_page_contains_no_credentials(self) -> None:
        self.sign_in()
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.security.token, response.text)
        self.assertNotIn(self.security.session, response.text)

    def test_session_cookie_is_hidden_from_scripts_and_other_sites(self) -> None:
        code = self.security.new_login_url().rsplit("code=", 1)[1]
        cookie = self.client.get(f"/login?code={code}").headers["set-cookie"].lower()
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=strict", cookie)
        self.assertIn(SESSION_COOKIE, cookie)

    def test_login_code_works_once(self) -> None:
        code = self.security.new_login_url().rsplit("code=", 1)[1]
        self.assertEqual(self.client.get(f"/login?code={code}").status_code, 303)
        self.client.cookies.clear()
        self.assertEqual(self.client.get(f"/login?code={code}").status_code, 401)

    def test_login_code_expires(self) -> None:
        code = self.security.new_login_url().rsplit("code=", 1)[1]
        later = time.monotonic() + security_module.LOGIN_CODE_TTL_SECONDS + 1
        with mock.patch.object(security_module.time, "monotonic", return_value=later):
            self.assertFalse(self.security.redeem_login_code(code))

    def test_unknown_login_code_is_refused(self) -> None:
        self.assertEqual(self.client.get("/login?code=guess").status_code, 401)
        self.assertEqual(self.client.get("/login").status_code, 401)

    def test_token_can_mint_a_sign_in_link(self) -> None:
        response = self.client.post("/api/login-code", headers=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertIn("/login?code=", response.json()["url"])

    def test_browser_session_cant_mint_a_sign_in_link(self) -> None:
        self.sign_in()
        self.assertEqual(self.client.post("/api/login-code", headers=SAME_ORIGIN).status_code, 401)

    def test_token_file_holds_token_and_port(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "api-token.json"
            self.security.write_token_file(path)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"token": self.security.token, "port": 9470},
            )


class InputTests(ApiSecurityTestCase):
    def test_approve_requires_an_explicit_decision(self) -> None:
        request_id = self.start_pending_request()
        response = self.client.post(f"/api/approve/{request_id}", headers=self.auth)
        self.assertEqual(response.status_code, 422)
        self.assertEqual(len(self.service.event_bus.get_pending()), 1)
        self.service.event_bus.resolve_request(request_id, False)

    def test_invalid_policy_values_are_refused(self) -> None:
        for path, body in (
            ("/api/policy/folder", {"folder_name": "Docs", "policy": "maybe"}),
            ("/api/folders/add", {"name": "X", "path": "C:\\X", "policy": "maybe"}),
            ("/api/policy/app", {"app_name": "X", "policies": {"files": "maybe"}}),
            ("/api/policy/app/resource", {"app_name": "X", "resource": "files", "policy": "maybe"}),
            ("/api/policy/global", {"key": "network_policy", "value": "maybe"}),
        ):
            self.assertEqual(self.client.post(path, json=body, headers=self.auth).status_code, 422, path)

    def test_bad_domain_and_pid_are_refused(self) -> None:
        response = self.client.post(
            "/api/firewall/block-domain", json={"domain": "a b;rm"}, headers=self.auth,
        )
        self.assertEqual(response.status_code, 422)
        response = self.client.post("/api/process/terminate", json={"pid": 0}, headers=self.auth)
        self.assertEqual(response.status_code, 422)

    def test_list_sizes_are_bounded(self) -> None:
        self.assertEqual(self.client.get("/api/events?limit=999999", headers=self.auth).status_code, 422)
        self.assertEqual(self.client.get("/api/audit?limit=0", headers=self.auth).status_code, 422)


class ResponseHeaderTests(ApiSecurityTestCase):
    def test_pages_cant_be_framed_or_sniffed(self) -> None:
        for response in (self.client.get("/"), self.client.get("/api/health")):
            self.assertEqual(response.headers["x-frame-options"], "DENY")
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])

    def test_api_responses_arent_cached(self) -> None:
        self.assertEqual(self.client.get("/api/health").headers["cache-control"], "no-store")


if __name__ == "__main__":
    unittest.main()
