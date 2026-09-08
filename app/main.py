from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
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
    LOG_DATABASE_PATH,
    valid_timezone,
)
from .database import Database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
SESSION_COOKIE = "tailscale_traffic_session"
SESSION_LIFETIME = 30 * 24 * 60 * 60
STARTED_AT = time.monotonic()
database = Database(DATABASE_PATH, CONFIG_PATH, LOG_DATABASE_PATH)
TRUSTED_PROXY_NETWORKS = (
    ip_network("127.0.0.0/8"),
    ip_network("::1/128"),
    ip_network("172.16.0.0/12"),
)


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


def _normalized_ip(value: str) -> str:
    candidate = value.strip().strip("[]")
    try:
        return str(ip_address(candidate))
    except ValueError:
        return ""


def _trusted_proxy(value: str) -> bool:
    try:
        address = ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in TRUSTED_PROXY_NETWORKS)


def client_ip(request: Request) -> str:
    direct = _normalized_ip(request.client.host) if request.client else ""
    if not direct or not _trusted_proxy(direct):
        return direct

    forwarded = [
        _normalized_ip(value)
        for value in request.headers.get("x-forwarded-for", "").split(",")
    ]
    forwarded = [value for value in forwarded if value]
    for value in reversed(forwarded):
        if not _trusted_proxy(value):
            return value
    real_ip = _normalized_ip(request.headers.get("x-real-ip", ""))
    return real_ip or (forwarded[0] if forwarded else direct)


def device_name(request: Request) -> str:
    user_agent = request.headers.get("user-agent", "")
    agent = user_agent.casefold()
    if "edg/" in agent:
        browser = "Edge"
    elif "firefox/" in agent:
        browser = "Firefox"
    elif "chrome/" in agent or "crios/" in agent:
        browser = "Chrome"
    elif "safari/" in agent:
        browser = "Safari"
    else:
        browser = "浏览器"
    if "iphone" in agent or "ipad" in agent:
        platform = "iOS"
    elif "android" in agent:
        platform = "Android"
    elif "windows" in agent:
        platform = "Windows"
    elif "macintosh" in agent or "mac os" in agent:
        platform = "macOS"
    elif "linux" in agent:
        platform = "Linux"
    else:
        platform = "未知设备"
    return f"{browser} · {platform}"


def valid_session(token: str) -> bool:
    return database.auth_session(token) is not None


def session_response(
    payload: dict,
    request: Request,
    *,
    remember: bool,
) -> JSONResponse:
    token = database.create_auth_session(
        device_name(request),
        request.headers.get("user-agent", ""),
        client_ip(request),
        remember,
    )
    response = JSONResponse(payload)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_LIFETIME if remember else None,
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
    token = request.cookies.get(SESSION_COOKIE, "")
    session = database.auth_session(
        token,
        device_name=device_name(request),
        user_agent=request.headers.get("user-agent", ""),
        ip_address=client_ip(request),
    )
    authenticated = session is not None
    request.state.auth_session = session
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
    remember: bool = False


class SetupRequest(BaseModel):
    password: str = Field(min_length=8, max_length=256)
    remember: bool = False


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


def audit(
    request: Request,
    category: str,
    action: str,
    message: str,
    *,
    level: str = "info",
) -> None:
    database.audit_log(
        category,
        action,
        message,
        level=level,
        ip_address=client_ip(request),
    )


def config_modified_at() -> str | None:
    try:
        modified = Path(database.config_path).stat().st_mtime
    except OSError:
        return None
    return datetime.fromtimestamp(modified, UTC).isoformat(timespec="seconds")


def project_version() -> str:
    try:
        return (PROJECT_DIR / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"


def validate_target_type(target_type: str) -> None:
    if target_type not in {"user", "device"}:
        raise HTTPException(status_code=404, detail="不支持的规则目标")


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
async def setup(credentials: SetupRequest, request: Request):
    if not database.initialize_password(credentials.password):
        raise HTTPException(status_code=409, detail="面板密码已经设置")
    audit(request, "auth", "setup", "控制面板密码已完成首次设置")
    return session_response(
        {"ok": True, "configured": True},
        request,
        remember=credentials.remember,
    )


@app.post("/api/login")
async def login(credentials: LoginRequest, request: Request):
    if not database.auth_configured():
        raise HTTPException(status_code=409, detail="请先设置面板密码")
    if not database.verify_password(credentials.password):
        audit(
            request,
            "auth",
            "login_failed",
            "面板密码验证失败",
            level="warning",
        )
        return JSONResponse({"detail": "密码错误"}, status_code=401)
    audit(request, "auth", "login", f"{device_name(request)} 登录成功")
    return session_response(
        {"ok": True}, request, remember=credentials.remember
    )


@app.post("/api/logout")
async def logout(request: Request):
    database.revoke_auth_token(request.cookies.get(SESSION_COOKIE, ""))
    audit(request, "auth", "logout", "当前设备已退出登录")
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/api/settings")
async def get_settings():
    return {
        "config": database.get_app_config().as_dict(),
        "config_modified_at": config_modified_at(),
        "collector": database.collector_status(),
        "website": database.website_status(),
        "version": project_version(),
    }


@app.put("/api/settings")
async def update_settings(update: SettingsUpdate, request: Request):
    config = database.update_app_config(AppConfig(**update.model_dump()))
    audit(request, "operation", "settings_updated", "运行配置已更新")
    return {
        "config": config.as_dict(),
        "config_modified_at": config_modified_at(),
    }


@app.put("/api/settings/password")
async def update_password(update: PasswordUpdate, request: Request):
    if update.current_password == update.new_password:
        raise HTTPException(status_code=400, detail="新密码不能与当前密码相同")
    if not database.change_password(
        update.current_password,
        update.new_password,
    ):
        raise HTTPException(status_code=400, detail="当前密码错误")
    current_session = request.state.auth_session or {}
    database.revoke_all_auth_sessions()
    audit(request, "auth", "password_changed", "面板密码已更新，旧会话已退出")
    return session_response(
        {"ok": True},
        request,
        remember=bool(current_session.get("remembered")),
    )


@app.get("/api/auth/sessions")
async def list_auth_sessions(request: Request):
    token = request.cookies.get(SESSION_COOKIE, "")
    return {"sessions": database.auth_sessions(token)}


@app.delete("/api/auth/sessions/{session_id}")
async def delete_auth_session(session_id: str, request: Request):
    sessions = database.auth_sessions(
        request.cookies.get(SESSION_COOKIE, "")
    )
    target = next(
        (item for item in sessions if item["session_id"] == session_id),
        None,
    )
    if not target or not database.revoke_auth_session(session_id):
        raise HTTPException(status_code=404, detail="登录设备不存在")
    audit(request, "auth", "session_revoked", f"已退出设备：{target['device_name']}")
    response = JSONResponse({"ok": True, "current": target["current"]})
    if target["current"]:
        response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.post("/api/auth/sessions/logout-all")
async def logout_all_sessions(request: Request):
    count = database.revoke_all_auth_sessions()
    audit(request, "auth", "logout_all", f"已退出全部 {count} 个登录会话")
    response = JSONResponse({"ok": True, "count": count})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/api/logs")
async def logs(
    day: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
    keyword: str = Query(default="", max_length=100),
):
    return {
        "logs": database.audit_logs(
            limit=10,
            day=day,
            keyword=keyword.strip(),
            per_category=True,
        )
    }


@app.delete("/api/logs")
async def clear_logs(request: Request):
    count = database.clear_audit_logs()
    audit(request, "operation", "logs_cleared", f"已清理 {count} 条日志")
    return {"ok": True, "count": count}


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
    payload["timezone"] = config.timezone
    payload["collector"] = database.collector_status()
    payload["recent_logs"] = database.audit_logs(limit=5)
    payload["version"] = project_version()
    payload["dashboard_uptime_seconds"] = int(time.monotonic() - STARTED_AT)
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
    period: str = Query(default="day", pattern=r"^(day|24h)$"),
):
    payload = database.websites_for_user(
        identity_key,
        day,
        recent_24h=period == "24h",
    )
    if payload is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    return payload


@app.get("/api/devices/{device_id}/websites")
async def device_websites(
    device_id: str,
    day: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
    period: str = Query(default="day", pattern=r"^(day|24h)$"),
):
    payload = database.websites_for_device(
        device_id,
        day,
        recent_24h=period == "24h",
    )
    if payload is None:
        raise HTTPException(status_code=404, detail="设备不存在")
    return payload


@app.patch("/api/users/{identity_key:path}")
async def update_alias(identity_key: str, update: AliasUpdate, request: Request):
    if not database.set_alias(identity_key, update.alias):
        raise HTTPException(status_code=404, detail="账号不存在")
    audit(request, "operation", "user_alias_updated", "账号备注已更新")
    return {"ok": True}


@app.patch("/api/devices/{device_id}")
async def update_device_alias(
    device_id: str, update: AliasUpdate, request: Request
):
    if not database.set_device_alias(device_id, update.alias):
        raise HTTPException(status_code=404, detail="设备不存在")
    audit(request, "operation", "device_alias_updated", "设备备注已更新")
    return {"ok": True}


@app.get("/api/policies")
async def quota_policies():
    return {"rules": database.quota_rules_overview()}


@app.put("/api/policies/{target_type}/{target_key}/enabled")
async def update_policy_enabled(
    target_type: str,
    target_key: str,
    update: PolicyEnabledUpdate,
    request: Request,
):
    validate_target_type(target_type)
    policy = database.set_policy_enabled(
        target_type, target_key, update.enabled
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    audit(request, "operation", "policy_toggled", "规则启用状态已更新")
    return {"policy": policy}


@app.put("/api/policies/{target_type}/{target_key}/{rule_type}/enabled")
async def update_individual_policy_enabled(
    target_type: str,
    target_key: str,
    rule_type: str,
    update: PolicyEnabledUpdate,
    request: Request,
):
    validate_target_type(target_type)
    if rule_type not in {"quota", "access"}:
        raise HTTPException(status_code=404, detail="不支持的规则类型")
    policy = database.set_rule_enabled(
        target_type,
        target_key,
        rule_type,
        update.enabled,
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="规则不存在")
    audit(request, "operation", "policy_toggled", "单项规则启用状态已更新")
    return {"policy": policy}


@app.delete("/api/policies/{target_type}/{target_key}/rule")
async def delete_policy_bundle(
    target_type: str, target_key: str, request: Request
):
    validate_target_type(target_type)
    if not database.delete_policy_bundle(target_type, target_key):
        raise HTTPException(status_code=404, detail="规则不存在")
    audit(request, "operation", "policy_deleted", "规则已删除")
    return {"ok": True}


@app.put("/api/policies/{target_type}/{target_key}")
async def update_quota_policy(
    target_type: str,
    target_key: str,
    update: QuotaRuleUpdate,
    request: Request,
):
    validate_target_type(target_type)
    policy = database.set_quota_rule(
        target_type,
        target_key,
        update.monthly_limit_bytes,
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="用户或设备不存在")
    audit(request, "operation", "quota_updated", "流量上限已更新")
    return {"policy": policy}


@app.delete("/api/policies/{target_type}/{target_key}")
async def delete_quota_policy(
    target_type: str, target_key: str, request: Request
):
    validate_target_type(target_type)
    if not database.delete_quota_rule(target_type, target_key):
        raise HTTPException(status_code=404, detail="限额规则不存在")
    policy = database.quota_state(target_type, target_key)
    audit(request, "operation", "quota_deleted", "流量上限已删除")
    return {"policy": policy}


@app.post("/api/policies/{target_type}/{target_key}/unlock")
async def unlock_quota_policy(
    target_type: str, target_key: str, request: Request
):
    validate_target_type(target_type)
    policy = database.bypass_quota_for_current_month(target_type, target_key)
    if policy is None:
        raise HTTPException(status_code=404, detail="限额规则不存在")
    audit(request, "operation", "quota_unlocked", "本月流量上限已手动解锁")
    return {"policy": policy}


@app.put("/api/policies/{target_type}/{target_key}/block")
async def update_access_block(
    target_type: str,
    target_key: str,
    update: AccessBlockUpdate,
    request: Request,
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
    audit(request, "operation", "access_block_updated", "手动封禁已更新")
    return {"policy": policy}


@app.delete("/api/policies/{target_type}/{target_key}/block")
async def delete_access_block(
    target_type: str, target_key: str, request: Request
):
    validate_target_type(target_type)
    if not database.delete_access_block(target_type, target_key):
        raise HTTPException(status_code=404, detail="当前没有手动封禁")
    policy = database.quota_state(target_type, target_key)
    audit(request, "operation", "access_block_removed", "手动封禁已解除")
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
