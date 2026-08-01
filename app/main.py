from __future__ import annotations

import hashlib
import hmac
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .config import (
    AppConfig,
    CONFIG_PATH,
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    DATABASE_PATH,
    valid_timezone,
)
from .database import Database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
SESSION_COOKIE = "tailscale_traffic_session"
SESSION_LIFETIME = 30 * 24 * 60 * 60
database = Database(DATABASE_PATH, CONFIG_PATH)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield


app = FastAPI(
    title="Tailscale Traffic Monitor",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


def _session_signature(issued_at: str, secret: bytes) -> str:
    return hmac.new(
        secret,
        f"tailscale-traffic-session-v1:{issued_at}".encode(),
        hashlib.sha256,
    ).hexdigest()


def create_session_token() -> str:
    secret = database.session_secret()
    if not secret:
        raise RuntimeError("尚未设置面板密码")
    issued_at = str(int(time.time()))
    return f"{issued_at}.{_session_signature(issued_at, secret)}"


def valid_session(token: str) -> bool:
    secret = database.session_secret()
    if not secret:
        return False
    try:
        issued_at, signature = token.split(".", 1)
        age = int(time.time()) - int(issued_at)
    except (ValueError, TypeError):
        return False
    if age < 0 or age > SESSION_LIFETIME:
        return False
    return hmac.compare_digest(signature, _session_signature(issued_at, secret))


def session_response(payload: dict) -> JSONResponse:
    response = JSONResponse(payload)
    response.set_cookie(
        SESSION_COOKIE,
        create_session_token(),
        max_age=SESSION_LIFETIME,
        httponly=True,
        samesite="strict",
        path="/",
    )
    return response


@app.middleware("http")
async def protect_dashboard(request: Request, call_next):
    path = request.url.path
    public = (
        path
        in {
            "/healthz",
            "/login",
            "/api/auth/status",
            "/api/setup",
            "/api/login",
        }
        or path.startswith("/static/")
    )
    configured = database.auth_configured()
    authenticated = valid_session(request.cookies.get(SESSION_COOKIE, ""))
    if not configured and not public:
        response = (
            JSONResponse(
                {"detail": "请先完成首次密码设置"},
                status_code=428,
            )
            if path.startswith("/api/")
            else RedirectResponse("/login", status_code=303)
        )
    elif not public and not authenticated:
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
    alias: str = Field(max_length=80)


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class SetupRequest(BaseModel):
    password: str = Field(min_length=8, max_length=256)


class PasswordUpdate(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


class SettingsUpdate(BaseModel):
    monthly_quota_gb: float = Field(ge=0, le=1_000_000_000)
    collect_interval: int = Field(ge=1, le=3600)
    website_retention_days: int = Field(ge=1, le=3650)
    timezone: str = Field(min_length=1, max_length=100)

    @field_validator("timezone")
    @classmethod
    def timezone_exists(cls, value: str) -> str:
        if not valid_timezone(value):
            raise ValueError("无效的 IANA 时区")
        return value


class QuotaRuleUpdate(BaseModel):
    monthly_limit_bytes: int = Field(gt=0, le=1_000_000_000_000_000_000)


class AccessBlockUpdate(BaseModel):
    duration_seconds: int | None = Field(
        default=None,
        ge=60,
        le=31_536_000,
    )
    permanent: bool = False


class PolicyEnabledUpdate(BaseModel):
    enabled: bool


def validate_target_type(target_type: str) -> None:
    if target_type not in {"user", "device"}:
        raise HTTPException(status_code=404, detail="不支持的限额目标")


@app.get("/healthz")
async def healthcheck():
    return {"status": "ok"}


@app.get("/api/auth/status")
async def auth_status():
    return {"configured": database.auth_configured()}


@app.get("/login")
async def login_page(request: Request):
    if valid_session(request.cookies.get(SESSION_COOKIE, "")):
        return RedirectResponse("/", status_code=303)
    return FileResponse(BASE_DIR / "static" / "login.html")


@app.post("/api/setup")
async def setup(credentials: SetupRequest):
    if not database.initialize_password(credentials.password):
        raise HTTPException(status_code=409, detail="面板密码已经设置")
    return session_response({"ok": True, "configured": True})


@app.post("/api/login")
async def login(credentials: LoginRequest):
    if not database.auth_configured():
        raise HTTPException(status_code=409, detail="请先设置面板密码")
    if not database.verify_password(credentials.password):
        return JSONResponse({"detail": "密码错误"}, status_code=401)
    return session_response({"ok": True})


@app.post("/api/logout")
async def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/api/settings")
async def get_settings():
    return {
        "config": database.get_app_config().as_dict(),
        "collector": database.collector_status(),
        "website": database.website_status(),
    }


@app.put("/api/settings")
async def update_settings(update: SettingsUpdate):
    config = database.update_app_config(AppConfig(**update.model_dump()))
    return {"config": config.as_dict()}


@app.put("/api/settings/password")
async def update_password(update: PasswordUpdate):
    if update.current_password == update.new_password:
        raise HTTPException(status_code=400, detail="新密码不能与当前密码相同")
    if not database.change_password(
        update.current_password,
        update.new_password,
    ):
        raise HTTPException(status_code=400, detail="当前密码错误")
    return session_response({"ok": True})


@app.get("/api/dashboard")
async def dashboard(
    month: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}$"),
    show_expired: bool = Query(default=False),
):
    config = database.get_app_config()
    payload = database.dashboard(
        month,
        config.monthly_quota_bytes,
        show_expired=show_expired,
    )
    payload["collector"] = database.collector_status()
    return payload


@app.get("/api/users/{identity_key:path}/devices")
async def user_devices(
    identity_key: str,
    month: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}$"),
    show_expired: bool = Query(default=False),
):
    return {
        "devices": database.devices_for(
            identity_key,
            month,
            show_expired=show_expired,
        )
    }


@app.get("/api/users/{identity_key:path}/websites")
async def user_websites(
    identity_key: str,
    day: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
):
    payload = database.websites_for_user(identity_key, day)
    if payload is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    return payload


@app.get("/api/devices/{device_id}/websites")
async def device_websites(
    device_id: str,
    day: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
):
    payload = database.websites_for_device(device_id, day)
    if payload is None:
        raise HTTPException(status_code=404, detail="设备不存在")
    return payload


@app.patch("/api/users/{identity_key:path}")
async def update_alias(identity_key: str, update: AliasUpdate):
    if not database.set_alias(identity_key, update.alias):
        raise HTTPException(status_code=404, detail="账号不存在")
    return {"ok": True}


@app.patch("/api/devices/{device_id}")
async def update_device_alias(device_id: str, update: AliasUpdate):
    if not database.set_device_alias(device_id, update.alias):
        raise HTTPException(status_code=404, detail="设备不存在")
    return {"ok": True}


@app.get("/api/policies")
async def quota_policies():
    return {"rules": database.quota_rules_overview()}


@app.put("/api/policies/{target_type}/{target_key}/enabled")
async def update_policy_enabled(
    target_type: str,
    target_key: str,
    update: PolicyEnabledUpdate,
):
    validate_target_type(target_type)
    policy = database.set_policy_enabled(
        target_type, target_key, update.enabled
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    return {"policy": policy}


@app.delete("/api/policies/{target_type}/{target_key}/rule")
async def delete_policy_bundle(target_type: str, target_key: str):
    validate_target_type(target_type)
    if not database.delete_policy_bundle(target_type, target_key):
        raise HTTPException(status_code=404, detail="规则不存在")
    return {"ok": True}


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
    return {"policy": policy}


@app.delete("/api/policies/{target_type}/{target_key}")
async def delete_quota_policy(target_type: str, target_key: str):
    validate_target_type(target_type)
    if not database.delete_quota_rule(target_type, target_key):
        raise HTTPException(status_code=404, detail="限额规则不存在")
    policy = database.quota_state(target_type, target_key)
    return {"policy": policy}


@app.post("/api/policies/{target_type}/{target_key}/unlock")
async def unlock_quota_policy(target_type: str, target_key: str):
    validate_target_type(target_type)
    policy = database.bypass_quota_for_current_month(target_type, target_key)
    if policy is None:
        raise HTTPException(status_code=404, detail="限额规则不存在")
    return {"policy": policy}


@app.put("/api/policies/{target_type}/{target_key}/block")
async def update_access_block(
    target_type: str,
    target_key: str,
    update: AccessBlockUpdate,
):
    validate_target_type(target_type)
    if update.permanent == (update.duration_seconds is not None):
        raise HTTPException(
            status_code=422,
            detail="请选择临时封禁时长或永久封禁",
        )
    policy = database.set_access_block(
        target_type,
        target_key,
        None if update.permanent else update.duration_seconds,
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="用户或设备不存在")
    return {"policy": policy}


@app.delete("/api/policies/{target_type}/{target_key}/block")
async def delete_access_block(target_type: str, target_key: str):
    validate_target_type(target_type)
    if not database.delete_access_block(target_type, target_key):
        raise HTTPException(status_code=404, detail="当前没有手动封禁")
    policy = database.quota_state(target_type, target_key)
    return {"policy": policy}


@app.get("/")
async def index():
    return FileResponse(BASE_DIR / "static" / "index.html")


app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        log_level="info",
    )
