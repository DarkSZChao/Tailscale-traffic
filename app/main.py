from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .collector import Collector
from .config import settings
from .database import Database
from .firewall import Firewall
from .tailscale import TailscaleCliClient, TailscaleClient
from .windows_capture import WindowsCaptureCollector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
SESSION_COOKIE = "tailscale_traffic_session"
SESSION_LIFETIME = 30 * 24 * 60 * 60
database = Database(settings.database_path)


def create_collector():
    windows_capture = (
        settings.collector_mode == "windows-capture"
        or settings.collector_mode == "auto" and os.name == "nt"
    )
    if windows_capture:
        return WindowsCaptureCollector(
            database,
            TailscaleCliClient(),
            settings.collect_interval,
        )
    return Collector(
        database,
        TailscaleClient(settings.tailscale_socket),
        Firewall(settings.tailscale_interface),
        settings.collect_interval,
    )


collector = create_collector()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if not settings.dashboard_password:
        raise RuntimeError("请设置 DASHBOARD_PASSWORD 后再启动")
    if settings.demo:
        database.seed_demo()
    else:
        collector.start()
    yield
    if not settings.demo:
        collector.stop()


app = FastAPI(
    title="Tailscale Traffic Monitor",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


def _session_signature(issued_at: str) -> str:
    return hmac.new(
        settings.dashboard_password.encode(),
        f"tailscale-traffic-session-v1:{issued_at}".encode(),
        hashlib.sha256,
    ).hexdigest()


def create_session_token() -> str:
    issued_at = str(int(time.time()))
    return f"{issued_at}.{_session_signature(issued_at)}"


def valid_session(token: str) -> bool:
    try:
        issued_at, signature = token.split(".", 1)
        age = int(time.time()) - int(issued_at)
    except (ValueError, TypeError):
        return False
    if age < 0 or age > SESSION_LIFETIME:
        return False
    return secrets.compare_digest(signature, _session_signature(issued_at))


@app.middleware("http")
async def protect_dashboard(request: Request, call_next):
    path = request.url.path
    public = (
        path in {"/healthz", "/login", "/api/login"}
        or path.startswith("/static/")
    )
    authenticated = valid_session(request.cookies.get(SESSION_COOKIE, ""))
    if not public and not authenticated:
        response = (
            JSONResponse({"detail": "请先登录"}, status_code=401)
            if path.startswith("/api/")
            else RedirectResponse("/login", status_code=303)
        )
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


class AliasUpdate(BaseModel):
    alias: str


class LoginRequest(BaseModel):
    password: str


class QuotaRuleUpdate(BaseModel):
    monthly_limit_bytes: int = Field(gt=0, le=1_000_000_000_000_000_000)


def enforcement_supported() -> bool:
    return bool(not settings.demo and collector.supports_enforcement)


def sync_enforcement() -> None:
    try:
        collector.apply_policies()
    except Exception as exc:
        collector.last_error = str(exc)
        raise HTTPException(
            status_code=500,
            detail=f"规则已保存，但同步防火墙失败：{exc}",
        ) from exc


def validate_target_type(target_type: str) -> None:
    if target_type not in {"user", "device"}:
        raise HTTPException(status_code=404, detail="不支持的限额目标")


@app.get("/healthz")
async def healthcheck():
    return {"status": "ok"}


@app.get("/login")
async def login_page(request: Request):
    if valid_session(request.cookies.get(SESSION_COOKIE, "")):
        return RedirectResponse("/", status_code=303)
    return FileResponse(BASE_DIR / "static" / "login.html")


@app.post("/api/login")
async def login(credentials: LoginRequest):
    valid_password = secrets.compare_digest(
        credentials.password.encode(), settings.dashboard_password.encode()
    )
    if not valid_password:
        return JSONResponse({"detail": "密码错误"}, status_code=401)
    response = JSONResponse({"ok": True})
    response.set_cookie(
        SESSION_COOKIE,
        create_session_token(),
        max_age=SESSION_LIFETIME,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    return response


@app.post("/api/logout")
async def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/api/dashboard")
async def dashboard(month: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}$")):
    payload = database.dashboard(month, settings.monthly_quota_bytes)
    payload["collector"] = {
        "healthy": settings.demo or not collector.last_error,
        "error": "" if settings.demo else collector.last_error,
        "mode": "demo" if settings.demo else collector.mode,
        "interval": settings.collect_interval,
        "enforcement_supported": enforcement_supported(),
    }
    return payload


@app.get("/api/users/{identity_key:path}/devices")
async def user_devices(
    identity_key: str,
    month: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}$"),
):
    return {
        "devices": database.devices_for(identity_key, month),
        "enforcement_supported": enforcement_supported(),
    }


@app.patch("/api/users/{identity_key:path}")
async def update_alias(identity_key: str, update: AliasUpdate):
    if not database.set_alias(identity_key, update.alias):
        raise HTTPException(status_code=404, detail="账号不存在")
    return {"ok": True}


@app.get("/api/policies")
async def quota_policies():
    return {
        "rules": database.quota_rules_overview(),
        "enforcement_supported": enforcement_supported(),
    }


@app.put("/api/policies/{target_type}/{target_key}")
async def update_quota_policy(
    target_type: str,
    target_key: str,
    update: QuotaRuleUpdate,
):
    validate_target_type(target_type)
    policy = database.set_quota_rule(
        target_type,
        target_key,
        update.monthly_limit_bytes,
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="用户或设备不存在")
    sync_enforcement()
    policy["enforcement_supported"] = enforcement_supported()
    return {"policy": policy}


@app.delete("/api/policies/{target_type}/{target_key}")
async def delete_quota_policy(target_type: str, target_key: str):
    validate_target_type(target_type)
    if not database.delete_quota_rule(target_type, target_key):
        raise HTTPException(status_code=404, detail="限额规则不存在")
    sync_enforcement()
    policy = database.quota_state(target_type, target_key)
    if policy:
        policy["enforcement_supported"] = enforcement_supported()
    return {"policy": policy}


@app.post("/api/policies/{target_type}/{target_key}/unlock")
async def unlock_quota_policy(target_type: str, target_key: str):
    validate_target_type(target_type)
    policy = database.bypass_quota_for_current_month(target_type, target_key)
    if policy is None:
        raise HTTPException(status_code=404, detail="限额规则不存在")
    sync_enforcement()
    policy["enforcement_supported"] = enforcement_supported()
    return {"policy": policy}


@app.get("/")
async def index():
    return FileResponse(BASE_DIR / "static" / "index.html")


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


if __name__ == "__main__":
    if not settings.dashboard_password:
        raise SystemExit("请设置 DASHBOARD_PASSWORD 后再启动")
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")
