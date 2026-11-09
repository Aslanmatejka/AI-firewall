"""FastAPI dashboard server."""

from __future__ import annotations

import threading
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import BaseModel, Field, StringConstraints

from .. import __version__
from ..service import AiShieldService
from .security import SESSION_COOKIE, ApiSecurity


def _serialize(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "value"):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _serialize(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_serialize(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    return obj


PolicyValue = Literal["allow", "ask", "block"]
ShortText = Annotated[str, StringConstraints(min_length=1, max_length=260)]
DomainName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9.-]{1,253}$")]

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
PUBLIC_PATHS = frozenset({"/api/health", "/login"})
CONTENT_SECURITY_POLICY = (
    "default-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
SIGN_IN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>AI Firewall</title></head>
<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;line-height:1.5">
<h1>Sign in to AI Firewall</h1>
<p>This link has expired or was already used. To get a new one, run this in PowerShell:</p>
<pre>.\\scripts\\open-dashboard.ps1</pre>
</body></html>"""


class AppPolicyBody(BaseModel):
    app_name: ShortText
    policies: dict[str, PolicyValue] = {}


class AppActionBody(BaseModel):
    app_name: ShortText
    action: PolicyValue


class FolderPolicyBody(BaseModel):
    folder_name: ShortText
    policy: PolicyValue


class AddFolderBody(BaseModel):
    name: ShortText
    path: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    policy: PolicyValue = "ask"


class GlobalPolicyBody(BaseModel):
    key: ShortText
    value: PolicyValue


class PidBody(BaseModel):
    pid: Annotated[int, Field(gt=0)]


class DomainBody(BaseModel):
    domain: DomainName


class RemoveFolderBody(BaseModel):
    folder_name: ShortText


class RemoveAppBody(BaseModel):
    app_name: ShortText


class AppResourcePolicyBody(BaseModel):
    app_name: ShortText
    resource: ShortText
    policy: PolicyValue


def _bearer_token(request: Request) -> str | None:
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    return value.strip() if scheme.lower() == "bearer" else None


def _rejection(request: Request, security: ApiSecurity) -> Response | None:
    """Return the response that refuses this request, or None if it may proceed."""
    # An unexpected Host means DNS rebinding: another site's name pointed at this PC.
    if request.headers.get("host", "").lower() not in security.allowed_hosts:
        return JSONResponse({"ok": False, "error": "Unrecognized Host header"}, status_code=403)

    path = request.url.path
    if path in PUBLIC_PATHS:
        return None

    origin = request.headers.get("origin")
    if origin is not None and origin.lower() not in security.allowed_origins:
        return JSONResponse({"ok": False, "error": "Cross-origin request refused"}, status_code=403)

    has_token = security.is_valid_token(_bearer_token(request))
    if has_token:
        return None

    # A browser session can't mint sign-in links, and its writes must prove their origin.
    has_session = path != "/api/login-code" and security.is_valid_session(
        request.cookies.get(SESSION_COOKIE),
    )
    if not has_session:
        if path == "/":
            return HTMLResponse(SIGN_IN_PAGE, status_code=401)
        return JSONResponse({"ok": False, "error": "Sign-in required"}, status_code=401)
    if request.method not in SAFE_METHODS and origin is None:
        return JSONResponse({"ok": False, "error": "Cross-origin request refused"}, status_code=403)
    return None


def create_app(service: AiShieldService, security: ApiSecurity) -> FastAPI:
    app = FastAPI(
        title="AI Firewall Dashboard", version=__version__,
        docs_url=None, redoc_url=None, openapi_url=None,
    )
    actions = service.actions

    @app.middleware("http")
    async def enforce_access(request: Request, call_next):
        response = _rejection(request, security) or await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/login")
    def login(code: str = ""):
        if not security.redeem_login_code(code):
            return HTMLResponse(SIGN_IN_PAGE, status_code=401)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(SESSION_COOKIE, security.session, httponly=True, samesite="strict", path="/")
        return response

    @app.post("/api/login-code")
    def login_code():
        return {"ok": True, "url": security.new_login_url()}

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        html_path = Path(__file__).parent / "static" / "index.html"
        build_id = str(int(time.time()))
        html = html_path.read_text(encoding="utf-8").replace("__BUILD_ID__", build_id)
        return HTMLResponse(
            html,
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

    @app.get("/api/health")
    def health():
        return {"ok": service.is_healthy(), "running": service.is_healthy()}

    @app.get("/api/status")
    def status():
        return JSONResponse(_serialize(service.get_status()))

    @app.get("/api/events")
    def events(limit: int = Query(50, ge=1, le=500)):
        return JSONResponse(_serialize(service.event_bus.get_events(limit)))

    @app.get("/api/audit")
    def audit(limit: int = Query(100, ge=1, le=5000)):
        return JSONResponse(service.permissions.get_audit_log(limit))

    @app.get("/api/config")
    def config():
        return JSONResponse(service.config)

    @app.get("/api/policies/apps")
    def app_policies():
        return JSONResponse(actions.get_app_policies())

    @app.get("/api/extensions")
    def extensions():
        return JSONResponse(service.browser.detected_extensions)

    @app.get("/api/models")
    def models():
        return JSONResponse(service.cached_models)

    # --- User actions ---

    @app.post("/api/approve/{request_id}")
    def approve(request_id: str, allow: bool):
        req = service.event_bus.resolve_request(request_id, allow)
        if not req:
            raise HTTPException(404, "Request not found")
        if hasattr(service, "invalidate_status_cache"):
            service.invalidate_status_cache()
        return {"ok": True, "allowed": allow, "request_id": request_id}

    @app.post("/api/process/terminate")
    def terminate_process(body: PidBody):
        return JSONResponse(actions.terminate_process(body.pid))

    @app.post("/api/process/block")
    def block_app(body: AppActionBody):
        return JSONResponse(actions.set_app_policy(body.app_name, "block"))

    @app.post("/api/process/allow")
    def allow_app(body: AppActionBody):
        return JSONResponse(actions.set_app_policy(body.app_name, "allow"))

    @app.post("/api/process/ask")
    def ask_app(body: AppActionBody):
        return JSONResponse(actions.set_app_policy(body.app_name, "ask"))

    @app.post("/api/process/terminate-all")
    def terminate_all_ai():
        return JSONResponse(actions.terminate_all_ai())

    @app.post("/api/policy/app")
    def set_app_policy(body: AppPolicyBody):  # Values are validated by PolicyValue.
        service.permissions.set_app_policy(body.app_name, body.policies)
        return {"ok": True}

    @app.post("/api/policy/app/resource")
    def set_app_resource_policy(body: AppResourcePolicyBody):
        result = actions.set_app_resource_policy(body.app_name, body.resource, body.policy)
        if not result.get("ok"):
            raise HTTPException(400, result.get("error", "Failed"))
        return result

    @app.post("/api/policy/app/remove")
    def remove_app_policy(body: RemoveAppBody):
        result = actions.remove_app_policy(body.app_name)
        if not result.get("ok"):
            raise HTTPException(400, result.get("error", "Failed"))
        return result

    @app.post("/api/policy/folder")
    def set_folder_policy(body: FolderPolicyBody):
        result = actions.set_folder_policy(body.folder_name, body.policy)
        if not result.get("ok"):
            raise HTTPException(400, result.get("error", "Failed"))
        return result

    @app.post("/api/folders/add")
    def add_folder(body: AddFolderBody):
        result = actions.add_protected_folder(body.name, body.path, body.policy)
        if not result.get("ok"):
            raise HTTPException(400, result.get("error", "Failed"))
        return result

    @app.post("/api/folders/remove")
    def remove_folder(body: RemoveFolderBody):
        result = actions.remove_protected_folder(body.folder_name)
        if not result.get("ok"):
            raise HTTPException(400, result.get("error", "Failed"))
        return result

    @app.post("/api/policy/global")
    def set_global_policy(body: GlobalPolicyBody):
        result = actions.set_global_policy(body.key, body.value)
        if not result.get("ok"):
            raise HTTPException(400, result.get("error", "Failed"))
        return result

    @app.post("/api/firewall/block-domain")
    def block_domain(body: DomainBody):
        return JSONResponse(actions.block_domain(body.domain))

    @app.post("/api/firewall/unblock-domain")
    def unblock_domain(body: DomainBody):
        return JSONResponse(actions.unblock_domain(body.domain))

    @app.post("/api/firewall/block-all")
    def block_all_domains():
        return JSONResponse(actions.block_all_ai_domains())

    @app.post("/api/firewall/block-connection")
    def block_connection(body: PidBody):
        return JSONResponse(actions.block_connection(body.pid))

    @app.post("/api/browser/scan")
    def scan_extensions():
        if getattr(service, "_ext_scan_running", False):
            return {"ok": True, "message": "Extension scan already running"}
        service._ext_scan_running = True

        def work() -> None:
            try:
                service.browser.scan_extensions()
            finally:
                service._ext_scan_running = False

        threading.Thread(target=work, daemon=True, name="ExtScan").start()
        return {"ok": True, "message": "Extension scan started"}

    @app.post("/api/browser/block-websites")
    def block_websites():
        return JSONResponse(actions.block_ai_websites())

    @app.post("/api/models/scan")
    def scan_models():
        if getattr(service, "_model_scan_running", False):
            return {"ok": True, "message": "Model scan already running"}
        service._model_scan_running = True

        def work() -> None:
            try:
                service.cached_models = service.detector.scan_model_files()
            finally:
                service._model_scan_running = False

        threading.Thread(target=work, daemon=True, name="ModelScan").start()
        return {"ok": True, "message": "Model scan started — results appear shortly"}

    @app.post("/api/lockdown")
    def lockdown():
        return JSONResponse(actions.lockdown_mode())

    @app.post("/api/restore-defaults")
    def restore_defaults():
        return JSONResponse(actions.restore_defaults())

    @app.get("/api/audit/export")
    def export_audit(limit: int = Query(1000, ge=1, le=100000)):
        csv_data = service.permissions.export_audit_csv(limit)
        return PlainTextResponse(
            csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="ai-firewall-audit.csv"'},
        )

    return app
