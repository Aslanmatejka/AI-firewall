"""FastAPI dashboard server."""

from __future__ import annotations

import threading
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from ..service import AiShieldService


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


class AppPolicyBody(BaseModel):
    app_name: str
    policies: dict[str, str] = {}


class AppActionBody(BaseModel):
    app_name: str
    action: str  # allow | block | ask


class FolderPolicyBody(BaseModel):
    folder_name: str
    policy: str


class AddFolderBody(BaseModel):
    name: str
    path: str
    policy: str = "ask"


class GlobalPolicyBody(BaseModel):
    key: str
    value: str


class PidBody(BaseModel):
    pid: int


class DomainBody(BaseModel):
    domain: str


class RemoveFolderBody(BaseModel):
    folder_name: str


class RemoveAppBody(BaseModel):
    app_name: str


class AppResourcePolicyBody(BaseModel):
    app_name: str
    resource: str
    policy: str


def create_app(service: AiShieldService) -> FastAPI:
    app = FastAPI(title="AI Firewall Dashboard", version="0.2.0")
    actions = service.actions

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
    def events(limit: int = 50):
        return JSONResponse(_serialize(service.event_bus.get_events(limit)))

    @app.get("/api/audit")
    def audit(limit: int = 100):
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
    def approve(request_id: str, allow: bool = True):
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
    def set_app_policy(body: AppPolicyBody):
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
        ok = service._network.block_domain(body.domain)
        return {"ok": ok, "domain": body.domain}

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
    def export_audit(limit: int = 1000):
        csv_data = service.permissions.export_audit_csv(limit)
        return PlainTextResponse(
            csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="ai-firewall-audit.csv"'},
        )

    return app
