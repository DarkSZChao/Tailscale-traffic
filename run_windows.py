from __future__ import annotations

import os
from pathlib import Path


def load_local_env() -> None:
    env_path = Path(__file__).with_name(".env")
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


load_local_env()
os.environ["COLLECTOR_MODE"] = "windows-capture"
os.environ.setdefault("DATABASE_PATH", "data/windows-traffic.db")

import uvicorn

from app.config import settings
from app.main import app


if __name__ == "__main__":
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")
