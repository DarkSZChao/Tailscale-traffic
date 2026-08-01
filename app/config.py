from __future__ import annotations

import fcntl
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DATABASE_PATH = "/data/traffic.db"
CONFIG_PATH = "/config.yaml"
TAILSCALE_SOCKET = "/var/run/tailscale/tailscaled.sock"
TAILSCALE_INTERFACE = "tailscale0"
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 8000


@dataclass(frozen=True)
class AppConfig:
    monthly_quota_gb: float = 3000
    collect_interval: int = 10
    website_retention_days: int = 180
    timezone: str = "America/Los_Angeles"

    @property
    def monthly_quota_bytes(self) -> int:
        return int(self.monthly_quota_gb * 1_000_000_000)

    def as_dict(self) -> dict:
        return asdict(self)


DEFAULT_CONFIG = AppConfig()

CONFIG_HEADER = """\
# Tailscale Traffic Monitor
# 此文件由控制面板“设置”页面管理，也可以在停止容器后手动编辑。
"""


def config_to_storage(config: AppConfig) -> dict[str, str]:
    return {
        "monthly_quota_gb": str(config.monthly_quota_gb),
        "collect_interval": str(config.collect_interval),
        "website_retention_days": str(config.website_retention_days),
        "timezone": config.timezone,
    }


def config_from_storage(values: dict[str, str]) -> AppConfig:
    defaults = config_to_storage(DEFAULT_CONFIG)
    merged = {**defaults, **values}
    try:
        config = AppConfig(
            monthly_quota_gb=max(0, float(merged["monthly_quota_gb"])),
            collect_interval=max(1, min(3600, int(merged["collect_interval"]))),
            website_retention_days=max(
                1,
                min(3650, int(merged["website_retention_days"])),
            ),
            timezone=merged["timezone"] or DEFAULT_CONFIG.timezone,
        )
    except (TypeError, ValueError):
        return DEFAULT_CONFIG
    try:
        ZoneInfo(config.timezone)
    except ZoneInfoNotFoundError:
        return AppConfig(**{**config.as_dict(), "timezone": DEFAULT_CONFIG.timezone})
    return config


def config_yaml(config: AppConfig) -> str:
    values = config_to_storage(config)
    return (
        CONFIG_HEADER
        + f"monthly_quota_gb: {values['monthly_quota_gb']}\n"
        + f"collect_interval: {values['collect_interval']}\n"
        + f"website_retention_days: {values['website_retention_days']}\n"
        + f"timezone: {values['timezone']}\n"
    )


def parse_config_yaml(content: str) -> AppConfig:
    values: dict[str, str] = {}
    allowed = set(config_to_storage(DEFAULT_CONFIG))
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition(":")
        key = key.strip()
        if not separator or key not in allowed:
            continue
        scalar = value.strip()
        if (
            len(scalar) >= 2
            and scalar[0] == scalar[-1]
            and scalar[0] in {"'", '"'}
        ):
            scalar = scalar[1:-1]
        values[key] = scalar
    return config_from_storage(values)


def load_app_config(path: str) -> AppConfig:
    config_path = Path(path)
    if not config_path.exists():
        save_app_config(path, DEFAULT_CONFIG)
        return DEFAULT_CONFIG
    with config_path.open("r", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
        content = handle.read()
    return parse_config_yaml(content)


def save_app_config(path: str, config: AppConfig) -> None:
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        handle.truncate()
        handle.write(config_yaml(config))
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(config_path, 0o644)


def valid_timezone(value: str) -> bool:
    try:
        ZoneInfo(value)
    except (ValueError, ZoneInfoNotFoundError):
        return False
    return True
