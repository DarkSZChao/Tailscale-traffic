from __future__ import annotations

import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_path: str = os.getenv("DATABASE_PATH", "data/traffic.db")
    tailscale_socket: str = os.getenv(
        "TAILSCALE_SOCKET", "/var/run/tailscale/tailscaled.sock"
    )
    tailscale_interface: str = os.getenv("TAILSCALE_INTERFACE", "tailscale0")
    collector_mode: str = os.getenv("COLLECTOR_MODE", "auto").strip().lower()
    collect_interval: int = max(5, int(os.getenv("COLLECT_INTERVAL", "10")))
    dashboard_password: str = os.getenv("DASHBOARD_PASSWORD", "")
    cookie_secure: bool = _env_bool("COOKIE_SECURE")
    monthly_quota_gb: float = max(0, float(os.getenv("MONTHLY_QUOTA_GB", "3000")))
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "4658"))
    demo: bool = _env_bool("TSM_DEMO")

    @property
    def monthly_quota_bytes(self) -> int:
        return int(self.monthly_quota_gb * 1_000_000_000)


settings = Settings()
