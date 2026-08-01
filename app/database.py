from __future__ import annotations

import calendar
import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from typing import Iterable
from zoneinfo import ZoneInfo

from .config import (
    AppConfig,
    DEFAULT_CONFIG,
    config_from_storage,
    load_app_config,
    save_app_config,
)
from .firewall import Counter
from .tailscale import Peer


class Database:
    def __init__(self, path: str, config_path: str | None = None):
        self.path = path
        self._timezone_name = DEFAULT_CONFIG.timezone
        parent = os.path.dirname(os.path.abspath(path))
        self.config_path = config_path or os.path.join(parent, "config.yaml")
        os.makedirs(parent, exist_ok=True)
        self._initialize()
        self.get_app_config()

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        legacy_config: dict[str, str] = {}
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS identities (
                    identity_key TEXT PRIMARY KEY,
                    login_name TEXT NOT NULL DEFAULT '',
                    display_name TEXT NOT NULL DEFAULT '',
                    alias TEXT NOT NULL DEFAULT '',
                    network_scope TEXT NOT NULL DEFAULT 'unknown',
                    is_present INTEGER NOT NULL DEFAULT 1,
                    removed_at TEXT NOT NULL DEFAULT '',
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    family INTEGER NOT NULL,
                    identity_key TEXT NOT NULL REFERENCES identities(identity_key),
                    device_id TEXT NOT NULL,
                    device_name TEXT NOT NULL DEFAULT '',
                    dns_name TEXT NOT NULL DEFAULT '',
                    os_name TEXT NOT NULL DEFAULT '',
                    online INTEGER NOT NULL DEFAULT 0,
                    expired INTEGER NOT NULL DEFAULT 0,
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS usage_daily (
                    day TEXT NOT NULL,
                    identity_key TEXT NOT NULL REFERENCES identities(identity_key),
                    upload_bytes INTEGER NOT NULL DEFAULT 0,
                    download_bytes INTEGER NOT NULL DEFAULT 0,
                    upload_packets INTEGER NOT NULL DEFAULT 0,
                    download_packets INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (day, identity_key)
                );

                CREATE TABLE IF NOT EXISTS device_usage_daily (
                    day TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    upload_bytes INTEGER NOT NULL DEFAULT 0,
                    download_bytes INTEGER NOT NULL DEFAULT 0,
                    upload_packets INTEGER NOT NULL DEFAULT 0,
                    download_packets INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (day, device_id)
                );

                CREATE TABLE IF NOT EXISTS device_aliases (
                    device_id TEXT PRIMARY KEY,
                    alias TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS domains (
                    domain_id INTEGER PRIMARY KEY,
                    domain TEXT NOT NULL UNIQUE
                );

                CREATE TABLE IF NOT EXISTS device_domain_daily (
                    day TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    domain_id INTEGER NOT NULL REFERENCES domains(domain_id),
                    visit_count INTEGER NOT NULL DEFAULT 0,
                    upload_bytes INTEGER NOT NULL DEFAULT 0,
                    download_bytes INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (day, device_id, domain_id)
                );

                CREATE INDEX IF NOT EXISTS idx_device_domain_daily_device_day
                ON device_domain_daily(device_id, day);

                CREATE TABLE IF NOT EXISTS website_flow_state (
                    flow_key TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    upload_bytes INTEGER NOT NULL,
                    download_bytes INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS quota_rules (
                    target_type TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    monthly_limit_bytes INTEGER NOT NULL,
                    bypass_month TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (target_type, target_key),
                    CHECK (target_type IN ('user', 'device')),
                    CHECK (monthly_limit_bytes > 0)
                );

                CREATE TABLE IF NOT EXISTS access_blocks (
                    target_type TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    block_mode TEXT NOT NULL,
                    blocked_until TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (target_type, target_key),
                    CHECK (target_type IN ('user', 'device')),
                    CHECK (block_mode IN ('temporary', 'permanent'))
                );

                CREATE TABLE IF NOT EXISTS policy_states (
                    target_type TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (target_type, target_key),
                    CHECK (target_type IN ('user', 'device')),
                    CHECK (enabled IN (0, 1))
                );

                CREATE TABLE IF NOT EXISTS counter_state (
                    ip TEXT NOT NULL,
                    family INTEGER NOT NULL,
                    direction TEXT NOT NULL,
                    bytes INTEGER NOT NULL,
                    packets INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (ip, family, direction)
                );

                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS authentication (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    session_secret TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            legacy_table = db.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'app_config'
                """
            ).fetchone()
            if legacy_table:
                legacy_config = {
                    str(row["key"]): str(row["value"])
                    for row in db.execute(
                        "SELECT key, value FROM app_config"
                    ).fetchall()
                }
            identity_columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(identities)").fetchall()
            }
            if "network_scope" not in identity_columns:
                db.execute(
                    """
                    ALTER TABLE identities
                    ADD COLUMN network_scope TEXT NOT NULL DEFAULT 'unknown'
                    """
                )
            if "is_present" not in identity_columns:
                db.execute(
                    """
                    ALTER TABLE identities
                    ADD COLUMN is_present INTEGER NOT NULL DEFAULT 1
                    """
                )
            if "removed_at" not in identity_columns:
                db.execute(
                    """
                    ALTER TABLE identities
                    ADD COLUMN removed_at TEXT NOT NULL DEFAULT ''
                    """
                )
            device_columns = {
                row["name"]
                for row in db.execute("PRAGMA table_info(devices)").fetchall()
            }
            if "expired" not in device_columns:
                db.execute(
                    """
                    ALTER TABLE devices
                    ADD COLUMN expired INTEGER NOT NULL DEFAULT 0
                    """
                )
        if not os.path.exists(self.config_path):
            save_app_config(
                self.config_path,
                config_from_storage(legacy_config),
            )
        if legacy_table:
            with self.connect() as db:
                db.execute("DROP TABLE IF EXISTS app_config")

    def _local_now(self) -> datetime:
        return datetime.now(ZoneInfo(self._timezone_name))

    def _today(self) -> date:
        return self._local_now().date()

    def _now(self) -> str:
        return self._local_now().isoformat(timespec="seconds")

    def get_app_config(self) -> AppConfig:
        config = load_app_config(self.config_path)
        self._timezone_name = config.timezone
        return config

    def update_app_config(self, config: AppConfig) -> AppConfig:
        save_app_config(self.config_path, config)
        self._timezone_name = config.timezone
        return config

    @staticmethod
    def _password_digest(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )

    def auth_configured(self) -> bool:
        with self.connect() as db:
            row = db.execute(
                "SELECT 1 FROM authentication WHERE id = 1"
            ).fetchone()
        return row is not None

    def initialize_password(self, password: str) -> bool:
        salt = secrets.token_bytes(16)
        password_hash = self._password_digest(password, salt)
        session_secret = secrets.token_bytes(32)
        with self.connect() as db:
            result = db.execute(
                """
                INSERT OR IGNORE INTO authentication
                    (id, password_salt, password_hash, session_secret, updated_at)
                VALUES (1, ?, ?, ?, ?)
                """,
                (
                    base64.b64encode(salt).decode("ascii"),
                    base64.b64encode(password_hash).decode("ascii"),
                    base64.b64encode(session_secret).decode("ascii"),
                    self._now(),
                ),
            )
        return result.rowcount == 1

    def verify_password(self, password: str) -> bool:
        with self.connect() as db:
            row = db.execute(
                """
                SELECT password_salt, password_hash
                FROM authentication WHERE id = 1
                """
            ).fetchone()
        if not row:
            return False
        try:
            salt = base64.b64decode(row["password_salt"], validate=True)
            expected = base64.b64decode(row["password_hash"], validate=True)
        except (ValueError, TypeError):
            return False
        actual = self._password_digest(password, salt)
        return hmac.compare_digest(actual, expected)

    def change_password(self, current_password: str, new_password: str) -> bool:
        if not self.verify_password(current_password):
            return False
        salt = secrets.token_bytes(16)
        password_hash = self._password_digest(new_password, salt)
        session_secret = secrets.token_bytes(32)
        with self.connect() as db:
            db.execute(
                """
                UPDATE authentication
                SET password_salt = ?, password_hash = ?,
                    session_secret = ?, updated_at = ?
                WHERE id = 1
                """,
                (
                    base64.b64encode(salt).decode("ascii"),
                    base64.b64encode(password_hash).decode("ascii"),
                    base64.b64encode(session_secret).decode("ascii"),
                    self._now(),
                ),
            )
        return True

    def session_secret(self) -> bytes | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT session_secret FROM authentication WHERE id = 1"
            ).fetchone()
        if not row:
            return None
        try:
            return base64.b64decode(row["session_secret"], validate=True)
        except (ValueError, TypeError):
            return None

    def sync_peers(self, peers: Iterable[Peer]) -> None:
        peer_list = list(peers)
        present_user_keys = sorted(
            {
                peer.identity_key
                for peer in peer_list
                if peer.identity_key.startswith("user:")
            }
        )
        now = self._now()
        with self.connect() as db:
            db.execute("UPDATE devices SET online = 0")
            if present_user_keys:
                placeholders = ",".join("?" for _ in present_user_keys)
                db.execute(
                    f"""
                    UPDATE identities
                    SET is_present = 0,
                        removed_at = CASE
                            WHEN is_present = 1 THEN ?
                            ELSE removed_at
                        END
                    WHERE identity_key LIKE 'user:%'
                      AND identity_key NOT IN ({placeholders})
                    """,
                    (now, *present_user_keys),
                )
            else:
                db.execute(
                    """
                    UPDATE identities
                    SET is_present = 0,
                        removed_at = CASE
                            WHEN is_present = 1 THEN ?
                            ELSE removed_at
                        END
                    WHERE identity_key LIKE 'user:%'
                    """,
                    (now,),
                )
            for peer in peer_list:
                db.execute(
                    """
                    INSERT INTO identities
                        (identity_key, login_name, display_name,
                         network_scope, is_present, removed_at, last_seen)
                    VALUES (?, ?, ?, ?, 1, '', ?)
                    ON CONFLICT(identity_key) DO UPDATE SET
                        login_name = excluded.login_name,
                        display_name = excluded.display_name,
                        network_scope = excluded.network_scope,
                        is_present = 1,
                        removed_at = '',
                        last_seen = excluded.last_seen
                    """,
                    (
                        peer.identity_key,
                        peer.login_name,
                        peer.display_name,
                        peer.network_scope,
                        now,
                    ),
                )
                existing = db.execute(
                    """
                    SELECT identity_key, device_id FROM devices WHERE ip = ?
                    """,
                    (peer.ip,),
                ).fetchone()
                if (
                    existing
                    and existing["identity_key"] != peer.identity_key
                    and existing["identity_key"].startswith("unknown:")
                ):
                    old_key = existing["identity_key"]
                    db.execute(
                        """
                        INSERT INTO usage_daily
                            (day, identity_key, upload_bytes, download_bytes,
                             upload_packets, download_packets)
                        SELECT day, ?, upload_bytes, download_bytes,
                               upload_packets, download_packets
                        FROM usage_daily WHERE identity_key = ?
                        ON CONFLICT(day, identity_key) DO UPDATE SET
                            upload_bytes = upload_bytes + excluded.upload_bytes,
                            download_bytes = download_bytes + excluded.download_bytes,
                            upload_packets = upload_packets + excluded.upload_packets,
                            download_packets = download_packets + excluded.download_packets
                        """,
                        (peer.identity_key, old_key),
                    )
                    db.execute(
                        "DELETE FROM usage_daily WHERE identity_key = ?", (old_key,)
                    )
                if existing and existing["device_id"] != peer.device_id:
                    old_device_id = existing["device_id"]
                    db.execute(
                        """
                        INSERT INTO device_usage_daily
                            (day, device_id, upload_bytes, download_bytes,
                             upload_packets, download_packets)
                        SELECT day, ?, upload_bytes, download_bytes,
                               upload_packets, download_packets
                        FROM device_usage_daily WHERE device_id = ?
                        ON CONFLICT(day, device_id) DO UPDATE SET
                            upload_bytes = upload_bytes + excluded.upload_bytes,
                            download_bytes = download_bytes + excluded.download_bytes,
                            upload_packets = upload_packets + excluded.upload_packets,
                            download_packets = download_packets + excluded.download_packets
                        """,
                        (peer.device_id, old_device_id),
                    )
                    db.execute(
                        "DELETE FROM device_usage_daily WHERE device_id = ?",
                        (old_device_id,),
                    )
                    db.execute(
                        """
                        INSERT INTO device_domain_daily
                            (day, device_id, domain_id, visit_count,
                             upload_bytes, download_bytes, first_seen, last_seen)
                        SELECT day, ?, domain_id, visit_count,
                               upload_bytes, download_bytes, first_seen, last_seen
                        FROM device_domain_daily WHERE device_id = ?
                        ON CONFLICT(day, device_id, domain_id) DO UPDATE SET
                            visit_count = visit_count + excluded.visit_count,
                            upload_bytes = upload_bytes + excluded.upload_bytes,
                            download_bytes =
                                download_bytes + excluded.download_bytes,
                            first_seen = MIN(first_seen, excluded.first_seen),
                            last_seen = MAX(last_seen, excluded.last_seen)
                        """,
                        (peer.device_id, old_device_id),
                    )
                    db.execute(
                        "DELETE FROM device_domain_daily WHERE device_id = ?",
                        (old_device_id,),
                    )
                    db.execute(
                        """
                        UPDATE website_flow_state SET device_id = ?
                        WHERE device_id = ?
                        """,
                        (peer.device_id, old_device_id),
                    )
                db.execute(
                    """
                    INSERT INTO devices
                        (ip, family, identity_key, device_id, device_name,
                         dns_name, os_name, online, expired, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        family = excluded.family,
                        identity_key = excluded.identity_key,
                        device_id = excluded.device_id,
                        device_name = excluded.device_name,
                        dns_name = excluded.dns_name,
                        os_name = excluded.os_name,
                        online = excluded.online,
                        expired = excluded.expired,
                        last_seen = excluded.last_seen
                    """,
                    (
                        peer.ip,
                        peer.family,
                        peer.identity_key,
                        peer.device_id,
                        peer.device_name,
                        peer.dns_name,
                        peer.os_name,
                        int(peer.online),
                        int(peer.expired),
                        now,
                    ),
                )

    def known_addresses(self) -> list[tuple[str, int]]:
        with self.connect() as db:
            return [
                (row["ip"], row["family"])
                for row in db.execute("SELECT ip, family FROM devices").fetchall()
            ]

    def unresolved_addresses(self, addresses: Iterable[str]) -> list[str]:
        unique = sorted(set(addresses))
        if not unique:
            return []
        with self.connect() as db:
            unresolved = []
            for address in unique:
                row = db.execute(
                    "SELECT identity_key FROM devices WHERE ip = ?", (address,)
                ).fetchone()
                if not row or row["identity_key"].startswith("unknown:"):
                    unresolved.append(address)
            return unresolved

    def _ensure_unknown(
        self, db: sqlite3.Connection, counter: Counter
    ) -> tuple[str, str]:
        row = db.execute(
            "SELECT identity_key, device_id FROM devices WHERE ip = ?", (counter.ip,)
        ).fetchone()
        if row:
            return row["identity_key"], row["device_id"]

        now = self._now()
        identity_key = f"unknown:{counter.ip}"
        db.execute(
            """
            INSERT OR IGNORE INTO identities
                (identity_key, display_name, last_seen)
            VALUES (?, '未识别设备', ?)
            """,
            (identity_key, now),
        )
        db.execute(
            """
            INSERT OR IGNORE INTO devices
                (ip, family, identity_key, device_id, device_name, last_seen)
            VALUES (?, ?, ?, ?, '未识别设备', ?)
            """,
            (counter.ip, counter.family, identity_key, counter.ip, now),
        )
        return identity_key, counter.ip

    def record_counters(self, counters: Iterable[Counter]) -> tuple[int, int]:
        today = self._today().isoformat()
        now = self._now()
        added_upload = 0
        added_download = 0
        with self.connect() as db:
            for counter in counters:
                identity_key, device_id = self._ensure_unknown(db, counter)
                previous = db.execute(
                    """
                    SELECT bytes, packets FROM counter_state
                    WHERE ip = ? AND family = ? AND direction = ?
                    """,
                    (counter.ip, counter.family, counter.direction),
                ).fetchone()

                if previous and counter.bytes >= previous["bytes"]:
                    byte_delta = counter.bytes - previous["bytes"]
                    packet_delta = max(0, counter.packets - previous["packets"])
                else:
                    # 防火墙规则在主机重启后会归零，当前值就是新的增量。
                    byte_delta = counter.bytes
                    packet_delta = counter.packets

                db.execute(
                    """
                    INSERT INTO counter_state
                        (ip, family, direction, bytes, packets, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip, family, direction) DO UPDATE SET
                        bytes = excluded.bytes,
                        packets = excluded.packets,
                        updated_at = excluded.updated_at
                    """,
                    (
                        counter.ip,
                        counter.family,
                        counter.direction,
                        counter.bytes,
                        counter.packets,
                        now,
                    ),
                )

                if not byte_delta and not packet_delta:
                    continue

                upload_bytes = byte_delta if counter.direction == "upload" else 0
                download_bytes = byte_delta if counter.direction == "download" else 0
                upload_packets = (
                    packet_delta if counter.direction == "upload" else 0
                )
                download_packets = (
                    packet_delta if counter.direction == "download" else 0
                )
                db.execute(
                    """
                    INSERT INTO usage_daily
                        (day, identity_key, upload_bytes, download_bytes,
                         upload_packets, download_packets)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(day, identity_key) DO UPDATE SET
                        upload_bytes = upload_bytes + excluded.upload_bytes,
                        download_bytes = download_bytes + excluded.download_bytes,
                        upload_packets = upload_packets + excluded.upload_packets,
                        download_packets = download_packets + excluded.download_packets
                    """,
                    (
                        today,
                        identity_key,
                        upload_bytes,
                        download_bytes,
                        upload_packets,
                        download_packets,
                    ),
                )
                db.execute(
                    """
                    INSERT INTO device_usage_daily
                        (day, device_id, upload_bytes, download_bytes,
                         upload_packets, download_packets)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(day, device_id) DO UPDATE SET
                        upload_bytes = upload_bytes + excluded.upload_bytes,
                        download_bytes = download_bytes + excluded.download_bytes,
                        upload_packets = upload_packets + excluded.upload_packets,
                        download_packets = download_packets + excluded.download_packets
                    """,
                    (
                        today,
                        device_id,
                        upload_bytes,
                        download_bytes,
                        upload_packets,
                        download_packets,
                    ),
                )
                added_upload += upload_bytes
                added_download += download_bytes

            db.execute(
                """
                INSERT INTO meta(key, value) VALUES ('last_collect', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (now,),
            )
        return added_upload, added_download

    def update_collector_status(
        self,
        mode: str,
        interval: int,
        error: str = "",
    ) -> None:
        values = {
            "collector_mode": mode,
            "collector_interval": str(interval),
            "collector_error": error[:1000],
            "collector_heartbeat": self._now(),
        }
        with self.connect() as db:
            db.executemany(
                """
                INSERT INTO meta(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                values.items(),
            )

    def collector_status(self) -> dict:
        keys = (
            "collector_mode",
            "collector_interval",
            "collector_error",
            "collector_heartbeat",
        )
        placeholders = ",".join("?" for _ in keys)
        with self.connect() as db:
            rows = db.execute(
                f"SELECT key, value FROM meta WHERE key IN ({placeholders})",
                keys,
            ).fetchall()
        values = {row["key"]: row["value"] for row in rows}
        mode = values.get("collector_mode", "linux-firewall")
        try:
            interval = max(1, int(values.get("collector_interval", "10")))
        except ValueError:
            interval = 10
        error = values.get("collector_error", "")
        heartbeat = values.get("collector_heartbeat")

        stale = True
        if heartbeat:
            try:
                seen_at = datetime.fromisoformat(heartbeat)
                now = datetime.now(seen_at.tzinfo)
                stale = now - seen_at > timedelta(
                    seconds=max(30, interval * 3)
                )
            except ValueError:
                pass

        if not heartbeat:
            display_error = "采集器尚未上报状态"
        elif stale:
            display_error = "采集器心跳已停止"
        else:
            display_error = error
        return {
            "healthy": bool(heartbeat and not stale and not error),
            "error": display_error,
            "mode": mode,
            "interval": interval,
            "heartbeat": heartbeat,
        }

    def update_website_status(self, enabled: bool, error: str = "") -> None:
        values = {
            "website_enabled": "1" if enabled else "0",
            "website_error": error[:1000],
            "website_heartbeat": self._now(),
        }
        with self.connect() as db:
            db.executemany(
                """
                INSERT INTO meta(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                values.items(),
            )

    def website_status(self) -> dict:
        interval = self.get_app_config().collect_interval
        keys = ("website_enabled", "website_error", "website_heartbeat")
        placeholders = ",".join("?" for _ in keys)
        with self.connect() as db:
            rows = db.execute(
                f"SELECT key, value FROM meta WHERE key IN ({placeholders})",
                keys,
            ).fetchall()
        values = {row["key"]: row["value"] for row in rows}
        enabled = values.get("website_enabled") == "1"
        error = values.get("website_error", "")
        heartbeat = values.get("website_heartbeat")
        stale = True
        if heartbeat:
            try:
                seen_at = datetime.fromisoformat(heartbeat)
                stale = datetime.now(seen_at.tzinfo) - seen_at > timedelta(
                    seconds=max(60, interval * 3)
                )
            except ValueError:
                pass
        if not heartbeat:
            display_error = "网站采集器尚未上报状态"
        elif not enabled:
            display_error = "网站统计已关闭"
        elif stale:
            display_error = "网站采集器心跳已停止"
        else:
            display_error = error
        return {
            "enabled": enabled,
            "healthy": bool(enabled and heartbeat and not stale and not error),
            "error": display_error,
            "heartbeat": heartbeat,
            "accuracy": "best-effort",
        }

    def record_website_flows(self, flows: Iterable[dict]) -> tuple[int, int]:
        today = self._today().isoformat()
        now = self._now()
        stale_before = (
            self._local_now() - timedelta(days=2)
        ).isoformat(timespec="seconds")
        added_upload = 0
        added_download = 0
        with self.connect() as db:
            for flow in flows:
                device = db.execute(
                    "SELECT device_id FROM devices WHERE ip = ?",
                    (flow["device_ip"],),
                ).fetchone()
                if not device:
                    continue
                device_id = device["device_id"]
                flow_key = str(flow["flow_key"])[:500]
                current_upload = max(0, int(flow["upload_bytes"]))
                current_download = max(0, int(flow["download_bytes"]))
                previous = db.execute(
                    """
                    SELECT destination, upload_bytes, download_bytes
                    FROM website_flow_state WHERE flow_key = ?
                    """,
                    (flow_key,),
                ).fetchone()
                reset = bool(
                    not previous
                    or current_upload < previous["upload_bytes"]
                    or current_download < previous["download_bytes"]
                )
                candidate_destination = str(flow["destination"])[:253]
                destination = candidate_destination
                if previous and not reset:
                    destination = str(previous["destination"])
                    try:
                        ipaddress.ip_address(destination)
                    except ValueError:
                        pass
                    else:
                        try:
                            ipaddress.ip_address(candidate_destination)
                        except ValueError:
                            destination = candidate_destination
                upload_delta = (
                    current_upload
                    if reset
                    else current_upload - int(previous["upload_bytes"])
                )
                download_delta = (
                    current_download
                    if reset
                    else current_download - int(previous["download_bytes"])
                )
                visit_delta = 1 if reset else 0

                db.execute(
                    """
                    INSERT INTO website_flow_state
                        (flow_key, device_id, destination, upload_bytes,
                         download_bytes, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(flow_key) DO UPDATE SET
                        device_id = excluded.device_id,
                        destination = excluded.destination,
                        upload_bytes = excluded.upload_bytes,
                        download_bytes = excluded.download_bytes,
                        updated_at = excluded.updated_at
                    """,
                    (
                        flow_key,
                        device_id,
                        destination,
                        current_upload,
                        current_download,
                        now,
                    ),
                )
                if not upload_delta and not download_delta and not visit_delta:
                    continue

                db.execute(
                    "INSERT OR IGNORE INTO domains(domain) VALUES (?)",
                    (destination,),
                )
                domain = db.execute(
                    "SELECT domain_id FROM domains WHERE domain = ?",
                    (destination,),
                ).fetchone()
                db.execute(
                    """
                    INSERT INTO device_domain_daily
                        (day, device_id, domain_id, visit_count,
                         upload_bytes, download_bytes, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(day, device_id, domain_id) DO UPDATE SET
                        visit_count = visit_count + excluded.visit_count,
                        upload_bytes = upload_bytes + excluded.upload_bytes,
                        download_bytes = download_bytes + excluded.download_bytes,
                        first_seen = MIN(first_seen, excluded.first_seen),
                        last_seen = MAX(last_seen, excluded.last_seen)
                    """,
                    (
                        today,
                        device_id,
                        domain["domain_id"],
                        visit_delta,
                        upload_delta,
                        download_delta,
                        now,
                        now,
                    ),
                )
                added_upload += upload_delta
                added_download += download_delta

            db.execute(
                "DELETE FROM website_flow_state WHERE updated_at < ?",
                (stale_before,),
            )
        return added_upload, added_download

    def cleanup_website_history(self, retention_days: int) -> None:
        today = self._today().isoformat()
        with self.connect() as db:
            last_cleanup = db.execute(
                "SELECT value FROM meta WHERE key = 'website_last_cleanup'"
            ).fetchone()
            if last_cleanup and last_cleanup["value"] == today:
                return
            cutoff = (
                self._today() - timedelta(days=max(1, retention_days))
            ).isoformat()
            db.execute(
                "DELETE FROM device_domain_daily WHERE day < ?",
                (cutoff,),
            )
            db.execute(
                """
                DELETE FROM domains
                WHERE NOT EXISTS (
                    SELECT 1 FROM device_domain_daily
                    WHERE device_domain_daily.domain_id = domains.domain_id
                )
                """
            )
            db.execute(
                """
                INSERT INTO meta(key, value)
                VALUES ('website_last_cleanup', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (today,),
            )

    def _website_day(self, day: str | None) -> str:
        selected_day = day or self._today().isoformat()
        try:
            return datetime.strptime(
                selected_day, "%Y-%m-%d"
            ).date().isoformat()
        except ValueError:
            return self._today().isoformat()

    @staticmethod
    def _website_payload(rows: Iterable[sqlite3.Row]) -> dict:
        websites = [
            {
                "destination": row["domain"],
                "visits": int(row["visit_count"]),
                "upload": int(row["upload_bytes"]),
                "download": int(row["download_bytes"]),
                "total": int(row["upload_bytes"]) + int(row["download_bytes"]),
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            }
            for row in rows
        ]
        return {
            "websites": websites,
            "summary": {
                "destinations": len(websites),
                "visits": sum(item["visits"] for item in websites),
                "upload": sum(item["upload"] for item in websites),
                "download": sum(item["download"] for item in websites),
                "total": sum(item["total"] for item in websites),
            },
        }

    def websites_for_device(self, device_id: str, day: str | None) -> dict | None:
        normalized_day = self._website_day(day)
        with self.connect() as db:
            device = db.execute(
                """
                SELECT d.device_id,
                       MAX(d.device_name) AS device_name,
                       MAX(COALESCE(a.alias, '')) AS alias,
                       MAX(CASE WHEN d.family = 4 THEN d.ip ELSE '' END) AS ipv4
                FROM devices AS d
                LEFT JOIN device_aliases AS a ON a.device_id = d.device_id
                WHERE d.device_id = ?
                GROUP BY d.device_id
                """,
                (device_id,),
            ).fetchone()
            if not device:
                return None
            rows = db.execute(
                """
                SELECT d.domain, u.visit_count, u.upload_bytes,
                       u.download_bytes, u.first_seen, u.last_seen
                FROM device_domain_daily AS u
                JOIN domains AS d ON d.domain_id = u.domain_id
                WHERE u.device_id = ? AND u.day = ?
                ORDER BY (u.upload_bytes + u.download_bytes) DESC,
                         u.visit_count DESC, d.domain
                """,
                (device_id, normalized_day),
            ).fetchall()

        return {
            "device_id": device_id,
            "device_name": self._device_display_name(
                device["device_name"],
                device["alias"],
                device["ipv4"],
            ),
            "day": normalized_day,
            **self._website_payload(rows),
            "tracking": self.website_status(),
        }

    def websites_for_user(
        self,
        identity_key: str,
        day: str | None,
    ) -> dict | None:
        normalized_day = self._website_day(day)
        with self.connect() as db:
            user = db.execute(
                """
                SELECT COALESCE(NULLIF(alias, ''),
                                NULLIF(display_name, ''),
                                NULLIF(login_name, ''),
                                identity_key) AS name
                FROM identities
                WHERE identity_key = ?
                """,
                (identity_key,),
            ).fetchone()
            if not user:
                return None
            device_count = int(
                db.execute(
                    """
                    SELECT COUNT(DISTINCT device_id) AS total
                    FROM devices
                    WHERE identity_key = ?
                    """,
                    (identity_key,),
                ).fetchone()["total"]
                or 0
            )
            rows = db.execute(
                """
                SELECT d.domain,
                       SUM(u.visit_count) AS visit_count,
                       SUM(u.upload_bytes) AS upload_bytes,
                       SUM(u.download_bytes) AS download_bytes,
                       MIN(u.first_seen) AS first_seen,
                       MAX(u.last_seen) AS last_seen
                FROM device_domain_daily AS u
                JOIN domains AS d ON d.domain_id = u.domain_id
                JOIN (
                    SELECT DISTINCT device_id
                    FROM devices
                    WHERE identity_key = ?
                ) AS user_devices ON user_devices.device_id = u.device_id
                WHERE u.day = ?
                GROUP BY u.domain_id, d.domain
                ORDER BY (SUM(u.upload_bytes) + SUM(u.download_bytes)) DESC,
                         SUM(u.visit_count) DESC, d.domain
                """,
                (identity_key, normalized_day),
            ).fetchall()

        return {
            "identity_key": identity_key,
            "user_name": str(user["name"]),
            "device_count": device_count,
            "day": normalized_day,
            **self._website_payload(rows),
            "tracking": self.website_status(),
        }

    def month_bounds(self, month: str | None) -> tuple[date, date, str]:
        today = self._today()
        try:
            selected = (
                datetime.strptime(month, "%Y-%m").date()
                if month
                else today.replace(day=1)
            )
        except ValueError:
            selected = today.replace(day=1)
        start = selected.replace(day=1)
        last_day = calendar.monthrange(start.year, start.month)[1]
        end = start.replace(day=last_day)
        return start, end, start.strftime("%Y-%m")

    @staticmethod
    def _target_exists(
        db: sqlite3.Connection, target_type: str, target_key: str
    ) -> bool:
        if target_type == "user":
            row = db.execute(
                "SELECT 1 FROM identities WHERE identity_key = ?",
                (target_key,),
            ).fetchone()
        elif target_type == "device":
            row = db.execute(
                "SELECT 1 FROM devices WHERE device_id = ? LIMIT 1",
                (target_key,),
            ).fetchone()
        else:
            return False
        return bool(row)

    @staticmethod
    def _target_usage(
        db: sqlite3.Connection,
        target_type: str,
        target_key: str,
        start: str,
        end: str,
    ) -> int:
        if target_type == "user":
            row = db.execute(
                """
                SELECT COALESCE(SUM(upload_bytes + download_bytes), 0) AS total
                FROM usage_daily
                WHERE identity_key = ? AND day BETWEEN ? AND ?
                """,
                (target_key, start, end),
            ).fetchone()
        else:
            row = db.execute(
                """
                SELECT COALESCE(SUM(upload_bytes + download_bytes), 0) AS total
                FROM device_usage_daily
                WHERE device_id = ? AND day BETWEEN ? AND ?
                """,
                (target_key, start, end),
            ).fetchone()
        return int(row["total"] or 0)

    @staticmethod
    def _target_present(
        db: sqlite3.Connection, target_type: str, target_key: str
    ) -> bool:
        if target_type == "user":
            row = db.execute(
                "SELECT is_present FROM identities WHERE identity_key = ?",
                (target_key,),
            ).fetchone()
        elif target_type == "device":
            row = db.execute(
                """
                SELECT MAX(i.is_present) AS is_present
                FROM devices AS d
                JOIN identities AS i ON i.identity_key = d.identity_key
                WHERE d.device_id = ?
                """,
                (target_key,),
            ).fetchone()
        else:
            return False
        return bool(row and row["is_present"])

    @staticmethod
    def _policy_enabled(
        db: sqlite3.Connection, target_type: str, target_key: str
    ) -> bool:
        row = db.execute(
            """
            SELECT enabled FROM policy_states
            WHERE target_type = ? AND target_key = ?
            """,
            (target_type, target_key),
        ).fetchone()
        return True if row is None else bool(row["enabled"])

    @staticmethod
    def _policy_exists(
        db: sqlite3.Connection, target_type: str, target_key: str
    ) -> bool:
        row = db.execute(
            """
            SELECT 1 FROM quota_rules
            WHERE target_type = ? AND target_key = ?
            UNION ALL
            SELECT 1 FROM access_blocks
            WHERE target_type = ? AND target_key = ?
            LIMIT 1
            """,
            (target_type, target_key, target_type, target_key),
        ).fetchone()
        return bool(row)

    @classmethod
    def _cleanup_policy_state(
        cls,
        db: sqlite3.Connection,
        target_type: str,
        target_key: str,
    ) -> None:
        if cls._policy_exists(db, target_type, target_key):
            return
        db.execute(
            """
            DELETE FROM policy_states
            WHERE target_type = ? AND target_key = ?
            """,
            (target_type, target_key),
        )

    def quota_state(self, target_type: str, target_key: str) -> dict | None:
        start, end, current_month = self.month_bounds(None)
        with self.connect() as db:
            if not self._target_exists(db, target_type, target_key):
                return None
            rule = db.execute(
                """
                SELECT monthly_limit_bytes, bypass_month
                FROM quota_rules
                WHERE target_type = ? AND target_key = ?
                """,
                (target_type, target_key),
            ).fetchone()
            access_block = db.execute(
                """
                SELECT block_mode, blocked_until
                FROM access_blocks
                WHERE target_type = ? AND target_key = ?
                """,
                (target_type, target_key),
            ).fetchone()
            usage = self._target_usage(
                db,
                target_type,
                target_key,
                start.isoformat(),
                end.isoformat(),
            )
            target_present = self._target_present(
                db, target_type, target_key
            )
            enabled = self._policy_enabled(db, target_type, target_key)

        limit = int(rule["monthly_limit_bytes"]) if rule else None
        exceeded = bool(limit is not None and usage >= limit)
        bypassed = bool(
            rule and exceeded and rule["bypass_month"] == current_month
        )
        quota_blocked = exceeded and not bypassed
        manual_blocked = self._access_block_active(
            access_block,
            self._local_now(),
        )
        return {
            "target_type": target_type,
            "target_key": target_key,
            "limit_bytes": limit,
            "usage_bytes": usage,
            "exceeded": exceeded,
            "bypassed": bypassed,
            "quota_blocked": quota_blocked,
            "manual_blocked": manual_blocked,
            "block_mode": (
                str(access_block["block_mode"]) if manual_blocked else None
            ),
            "block_until": (
                str(access_block["blocked_until"])
                if manual_blocked and access_block["block_mode"] == "temporary"
                else None
            ),
            "blocked": bool(
                enabled
                and target_present
                and (quota_blocked or manual_blocked)
            ),
            "enabled": enabled,
            "effective": bool(enabled and target_present),
            "target_removed": not target_present,
            "month": current_month,
        }

    @staticmethod
    def _access_block_active(
        access_block: sqlite3.Row | None,
        now: datetime,
    ) -> bool:
        if not access_block:
            return False
        if access_block["block_mode"] == "permanent":
            return True
        try:
            return datetime.fromisoformat(access_block["blocked_until"]) > now
        except (TypeError, ValueError):
            return False

    def set_access_block(
        self,
        target_type: str,
        target_key: str,
        duration_seconds: int | None = None,
    ) -> dict | None:
        if duration_seconds is not None and duration_seconds <= 0:
            raise ValueError("临时封禁时长必须大于 0")
        block_mode = "temporary" if duration_seconds is not None else "permanent"
        blocked_until = (
            (self._local_now() + timedelta(seconds=duration_seconds)).isoformat(
                timespec="seconds"
            )
            if duration_seconds is not None
            else ""
        )
        with self.connect() as db:
            if not self._target_exists(db, target_type, target_key):
                return None
            db.execute(
                """
                INSERT INTO access_blocks
                    (target_type, target_key, block_mode,
                     blocked_until, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(target_type, target_key) DO UPDATE SET
                    block_mode = excluded.block_mode,
                    blocked_until = excluded.blocked_until,
                    updated_at = excluded.updated_at
                """,
                (
                    target_type,
                    target_key,
                    block_mode,
                    blocked_until,
                    self._now(),
                ),
            )
        return self.quota_state(target_type, target_key)

    def delete_access_block(self, target_type: str, target_key: str) -> bool:
        with self.connect() as db:
            result = db.execute(
                """
                DELETE FROM access_blocks
                WHERE target_type = ? AND target_key = ?
                """,
                (target_type, target_key),
            )
            deleted = result.rowcount > 0
            if deleted:
                self._cleanup_policy_state(db, target_type, target_key)
            return deleted

    def set_quota_rule(
        self, target_type: str, target_key: str, monthly_limit_bytes: int
    ) -> dict | None:
        if monthly_limit_bytes <= 0:
            raise ValueError("流量上限必须大于 0")
        with self.connect() as db:
            if not self._target_exists(db, target_type, target_key):
                return None
            db.execute(
                """
                INSERT INTO quota_rules
                    (target_type, target_key, monthly_limit_bytes,
                     bypass_month, updated_at)
                VALUES (?, ?, ?, '', ?)
                ON CONFLICT(target_type, target_key) DO UPDATE SET
                    monthly_limit_bytes = excluded.monthly_limit_bytes,
                    bypass_month = '',
                    updated_at = excluded.updated_at
                """,
                (
                    target_type,
                    target_key,
                    int(monthly_limit_bytes),
                    self._now(),
                ),
            )
        return self.quota_state(target_type, target_key)

    def delete_quota_rule(self, target_type: str, target_key: str) -> bool:
        with self.connect() as db:
            result = db.execute(
                """
                DELETE FROM quota_rules
                WHERE target_type = ? AND target_key = ?
                """,
                (target_type, target_key),
            )
            deleted = result.rowcount > 0
            if deleted:
                self._cleanup_policy_state(db, target_type, target_key)
            return deleted

    def set_policy_enabled(
        self, target_type: str, target_key: str, enabled: bool
    ) -> dict | None:
        with self.connect() as db:
            if not self._policy_exists(db, target_type, target_key):
                return None
            db.execute(
                """
                INSERT INTO policy_states
                    (target_type, target_key, enabled, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(target_type, target_key) DO UPDATE SET
                    enabled = excluded.enabled,
                    updated_at = excluded.updated_at
                """,
                (target_type, target_key, int(enabled), self._now()),
            )
        return self.quota_state(target_type, target_key)

    def delete_policy_bundle(
        self, target_type: str, target_key: str
    ) -> bool:
        with self.connect() as db:
            quota = db.execute(
                """
                DELETE FROM quota_rules
                WHERE target_type = ? AND target_key = ?
                """,
                (target_type, target_key),
            )
            access = db.execute(
                """
                DELETE FROM access_blocks
                WHERE target_type = ? AND target_key = ?
                """,
                (target_type, target_key),
            )
            db.execute(
                """
                DELETE FROM policy_states
                WHERE target_type = ? AND target_key = ?
                """,
                (target_type, target_key),
            )
            return quota.rowcount > 0 or access.rowcount > 0

    def bypass_quota_for_current_month(
        self, target_type: str, target_key: str
    ) -> dict | None:
        current_month = self._today().strftime("%Y-%m")
        with self.connect() as db:
            result = db.execute(
                """
                UPDATE quota_rules
                SET bypass_month = ?, updated_at = ?
                WHERE target_type = ? AND target_key = ?
                """,
                (current_month, self._now(), target_type, target_key),
            )
            if not result.rowcount:
                return None
        return self.quota_state(target_type, target_key)

    def blocked_addresses(self) -> set[str]:
        start, end, current_month = self.month_bounds(None)
        now = self._local_now()
        blocked: set[str] = set()
        with self.connect() as db:
            rules = db.execute(
                """
                SELECT target_type, target_key, monthly_limit_bytes, bypass_month
                FROM quota_rules
                """
            ).fetchall()
            for rule in rules:
                if not self._policy_enabled(
                    db, rule["target_type"], rule["target_key"]
                ):
                    continue
                if not self._target_present(
                    db, rule["target_type"], rule["target_key"]
                ):
                    continue
                usage = self._target_usage(
                    db,
                    rule["target_type"],
                    rule["target_key"],
                    start.isoformat(),
                    end.isoformat(),
                )
                if (
                    usage < int(rule["monthly_limit_bytes"])
                    or rule["bypass_month"] == current_month
                ):
                    continue
                if rule["target_type"] == "user":
                    rows = db.execute(
                        "SELECT ip FROM devices WHERE identity_key = ?",
                        (rule["target_key"],),
                    ).fetchall()
                else:
                    rows = db.execute(
                        "SELECT ip FROM devices WHERE device_id = ?",
                        (rule["target_key"],),
                    ).fetchall()
                blocked.update(row["ip"] for row in rows)
            access_blocks = db.execute(
                """
                SELECT target_type, target_key, block_mode, blocked_until
                FROM access_blocks
                """
            ).fetchall()
            for access_block in access_blocks:
                if not self._policy_enabled(
                    db,
                    access_block["target_type"],
                    access_block["target_key"],
                ):
                    continue
                if not self._target_present(
                    db,
                    access_block["target_type"],
                    access_block["target_key"],
                ):
                    continue
                if not self._access_block_active(access_block, now):
                    continue
                if access_block["target_type"] == "user":
                    rows = db.execute(
                        "SELECT ip FROM devices WHERE identity_key = ?",
                        (access_block["target_key"],),
                    ).fetchall()
                else:
                    rows = db.execute(
                        "SELECT ip FROM devices WHERE device_id = ?",
                        (access_block["target_key"],),
                    ).fetchall()
                blocked.update(row["ip"] for row in rows)
        return blocked

    def quota_rules_overview(self) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT target_type, target_key
                FROM quota_rules
                UNION
                SELECT target_type, target_key
                FROM access_blocks
                ORDER BY target_type, target_key
                """
            ).fetchall()
            targets = []
            for row in rows:
                if row["target_type"] == "user":
                    target = db.execute(
                        """
                        SELECT COALESCE(NULLIF(alias, ''),
                                        NULLIF(display_name, ''),
                                        NULLIF(login_name, ''),
                                        identity_key) AS name,
                               login_name, network_scope, is_present
                        FROM identities WHERE identity_key = ?
                        """,
                        (row["target_key"],),
                    ).fetchone()
                    subtitle = (
                        str(target["login_name"] or row["target_key"])
                        if target
                        else row["target_key"]
                    )
                    target_removed = bool(
                        target and not target["is_present"]
                    )
                else:
                    target = db.execute(
                        """
                        SELECT MAX(d.device_name) AS name,
                               MAX(d.os_name) AS os_name,
                               MAX(COALESCE(a.alias, '')) AS alias,
                               MAX(i.is_present) AS is_present,
                               MAX(
                                   CASE WHEN d.family = 4 THEN d.ip ELSE '' END
                               ) AS ipv4,
                               MAX(
                                   CASE WHEN d.family = 6 THEN d.ip ELSE '' END
                               ) AS ipv6
                        FROM devices AS d
                        JOIN identities AS i
                             ON i.identity_key = d.identity_key
                        LEFT JOIN device_aliases AS a
                               ON a.device_id = d.device_id
                        WHERE d.device_id = ?
                        """,
                        (row["target_key"],),
                    ).fetchone()
                    subtitle = (
                        str(target["ipv4"] or target["ipv6"] or "未知 IP")
                        if target
                        else "未知 IP"
                    )
                    target_removed = bool(
                        target and not target["is_present"]
                    )
                targets.append(
                    {
                        "target_type": row["target_type"],
                        "target_key": row["target_key"],
                        "target_name": (
                            self._device_display_name(
                                target["name"],
                                target["alias"],
                                target["ipv4"],
                            )
                            if target and row["target_type"] == "device"
                            else str(target["name"])
                            if target
                            else row["target_key"]
                        ),
                        "subtitle": subtitle,
                        "target_removed": target_removed,
                    }
                )

        result = []
        for target in targets:
            state = self.quota_state(
                target["target_type"], target["target_key"]
            )
            if not state:
                continue
            if state["limit_bytes"] is None and not state["manual_blocked"]:
                continue
            result.append({**target, "policy": state})
        result.sort(
            key=lambda item: (
                not item["policy"]["blocked"],
                item["target_type"],
                item["target_name"].casefold(),
            )
        )
        return result

    def dashboard(
        self,
        month: str | None,
        quota_bytes: int,
        show_expired: bool = False,
    ) -> dict:
        start, end, normalized_month = self.month_bounds(month)
        with self.connect() as db:
            usage_rows = db.execute(
                """
                SELECT
                    i.identity_key,
                    COALESCE(NULLIF(i.alias, ''), NULLIF(i.display_name, ''),
                             NULLIF(i.login_name, ''), i.identity_key) AS name,
                    i.login_name,
                    i.network_scope,
                    i.is_present,
                    i.removed_at,
                    COALESCE(SUM(u.upload_bytes), 0) AS upload,
                    COALESCE(SUM(u.download_bytes), 0) AS download
                FROM identities i
                LEFT JOIN usage_daily u
                    ON u.identity_key = i.identity_key
                   AND u.day BETWEEN ? AND ?
                WHERE EXISTS (
                    SELECT 1 FROM devices d
                    WHERE d.identity_key = i.identity_key
                )
                GROUP BY i.identity_key
                HAVING i.is_present = 1
                    OR COALESCE(SUM(u.upload_bytes + u.download_bytes), 0) > 0
                ORDER BY
                    CASE i.network_scope
                        WHEN 'external' THEN 0
                        WHEN 'tailnet' THEN 1
                        ELSE 2
                    END,
                    COALESCE(SUM(u.upload_bytes + u.download_bytes), 0) DESC
                """,
                (start.isoformat(), end.isoformat()),
            ).fetchall()

            device_rows = db.execute(
                """
                SELECT identity_key, COUNT(DISTINCT device_id) AS devices,
                       MAX(online) AS online, MAX(last_seen) AS last_seen
                FROM devices GROUP BY identity_key
                """
            ).fetchall()
            devices = {row["identity_key"]: dict(row) for row in device_rows}

            daily_raw = db.execute(
                """
                SELECT day, SUM(upload_bytes) AS upload,
                       SUM(download_bytes) AS download
                FROM usage_daily
                WHERE day BETWEEN ? AND ?
                GROUP BY day ORDER BY day
                """,
                (start.isoformat(), end.isoformat()),
            ).fetchall()
            daily_map = {row["day"]: row for row in daily_raw}
            last_collect = db.execute(
                "SELECT value FROM meta WHERE key = 'last_collect'"
            ).fetchone()

        users = []
        total_upload = 0
        total_download = 0
        scope_totals = {"tailnet": 0, "external": 0, "unknown": 0}
        for row in usage_rows:
            device = devices.get(row["identity_key"], {})
            upload = int(row["upload"] or 0)
            download = int(row["download"] or 0)
            total_upload += upload
            total_download += download
            network_scope = (
                row["network_scope"]
                if row["network_scope"] in scope_totals
                else "unknown"
            )
            scope_totals[network_scope] += upload + download
            users.append(
                {
                    "key": row["identity_key"],
                    "name": row["name"],
                    "login_name": row["login_name"],
                    "network_scope": network_scope,
                    "removed": not bool(row["is_present"]),
                    "removed_at": row["removed_at"] or None,
                    "upload": upload,
                    "download": download,
                    "total": upload + download,
                    "devices": int(device.get("devices") or 0),
                    "online": bool(device.get("online")),
                    "last_seen": device.get("last_seen"),
                    "policy": self.quota_state("user", row["identity_key"]),
                }
            )

        daily = []
        cursor = start
        while cursor <= end:
            row = daily_map.get(cursor.isoformat())
            daily.append(
                {
                    "day": cursor.isoformat(),
                    "upload": int(row["upload"] or 0) if row else 0,
                    "download": int(row["download"] or 0) if row else 0,
                }
            )
            cursor += timedelta(days=1)

        total = total_upload + total_download
        now = self._today()
        elapsed_days = (
            min(now, end).day if start.year == now.year and start.month == now.month
            else end.day
        )
        forecast = int(total / max(1, elapsed_days) * end.day)
        for user in users:
            user["device_items"] = self.devices_for(
                user["key"],
                normalized_month,
                show_expired=show_expired,
            )

        return {
            "month": normalized_month,
            "period": {"start": start.isoformat(), "end": end.isoformat()},
            "summary": {
                "upload": total_upload,
                "download": total_download,
                "total": total,
                "quota": quota_bytes,
                "remaining": max(0, quota_bytes - total),
                "usage_ratio": total / quota_bytes if quota_bytes else 0,
                "forecast": forecast,
                "tailnet_total": scope_totals["tailnet"],
                "external_total": scope_totals["external"],
                "unknown_total": scope_totals["unknown"],
            },
            "users": users,
            "daily": daily,
            "last_collect": last_collect["value"] if last_collect else None,
        }

    def devices_for(
        self,
        identity_key: str,
        month: str | None = None,
        *,
        show_expired: bool = False,
    ) -> list[dict]:
        start, end, _ = self.month_bounds(month)
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT d.device_id, d.ip, d.family, d.device_name,
                       d.dns_name, d.os_name, d.online, d.expired,
                       d.last_seen, COALESCE(a.alias, '') AS alias
                FROM devices AS d
                LEFT JOIN device_aliases AS a ON a.device_id = d.device_id
                WHERE d.identity_key = ?
                ORDER BY d.device_name, d.device_id, d.family
                """,
                (identity_key,),
            ).fetchall()
            usage_rows = db.execute(
                """
                SELECT device_id, SUM(upload_bytes) AS upload,
                       SUM(download_bytes) AS download
                FROM device_usage_daily
                WHERE day BETWEEN ? AND ?
                  AND device_id IN (
                      SELECT DISTINCT device_id
                      FROM devices
                      WHERE identity_key = ?
                  )
                GROUP BY device_id
                """,
                (start.isoformat(), end.isoformat(), identity_key),
            ).fetchall()
            usage = {
                row["device_id"]: {
                    "upload": int(row["upload"] or 0),
                    "download": int(row["download"] or 0),
                }
                for row in usage_rows
            }

        grouped: dict[str, dict] = {}
        for row in rows:
            key = row["device_id"] or row["ip"]
            device = grouped.setdefault(
                key,
                {
                    "device_id": key,
                    "device_name": "",
                    "source_device_name": row["device_name"],
                    "alias": row["alias"],
                    "dns_name": row["dns_name"],
                    "os_name": row["os_name"],
                    "online": False,
                    "expired": False,
                    "last_seen": row["last_seen"],
                    "addresses": [],
                },
            )
            device["online"] = device["online"] or bool(row["online"])
            device["expired"] = device["expired"] or bool(row["expired"])
            device["last_seen"] = max(device["last_seen"], row["last_seen"])
            if not device["os_name"] and row["os_name"]:
                device["os_name"] = row["os_name"]
            device["addresses"].append(
                {"ip": row["ip"], "family": int(row["family"])}
            )

        devices = list(grouped.values())
        for device in devices:
            device["addresses"].sort(key=lambda item: (item["family"], item["ip"]))
            ipv4 = next(
                (
                    address["ip"]
                    for address in device["addresses"]
                    if address["family"] == 4
                ),
                "",
            )
            device["device_name"] = self._device_display_name(
                device.pop("source_device_name"),
                device["alias"],
                ipv4,
            )
            device_usage = usage.get(
                device["device_id"], {"upload": 0, "download": 0}
            )
            device["upload"] = device_usage["upload"]
            device["download"] = device_usage["download"]
            device["total"] = (
                device_usage["upload"] + device_usage["download"]
            )
            device["policy"] = self.quota_state("device", device["device_id"])
        if not show_expired:
            devices = [
                device
                for device in devices
                if not device["expired"] or device["total"] > 0
            ]
        devices.sort(
            key=lambda device: (
                -device["total"],
                not device["online"],
                device["device_name"].casefold(),
                device["device_id"],
            )
        )
        return devices

    @staticmethod
    def _device_display_name(
        source_name: str | None,
        alias: str | None,
        ipv4: str | None,
    ) -> str:
        custom_name = str(alias or "").strip()
        if custom_name:
            return custom_name
        raw_name = str(source_name or "").strip()
        if raw_name.casefold() == "device-of-shared-to-user":
            try:
                suffix = int(str(ipv4 or "").rsplit(".", 1)[-1])
            except ValueError:
                return "SHARED-DEVICE"
            return f"SHARED-DEVICE-{suffix:03d}"
        return (raw_name or str(ipv4 or "") or "未知设备").upper()

    def set_device_alias(self, device_id: str, alias: str) -> bool:
        custom_name = alias.strip()[:80]
        with self.connect() as db:
            exists = db.execute(
                "SELECT 1 FROM devices WHERE device_id = ? LIMIT 1",
                (device_id,),
            ).fetchone()
            if not exists:
                return False
            if custom_name:
                db.execute(
                    """
                    INSERT INTO device_aliases(device_id, alias, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(device_id) DO UPDATE SET
                        alias = excluded.alias,
                        updated_at = excluded.updated_at
                    """,
                    (device_id, custom_name, self._now()),
                )
            else:
                db.execute(
                    "DELETE FROM device_aliases WHERE device_id = ?",
                    (device_id,),
                )
        return True

    def set_alias(self, identity_key: str, alias: str) -> bool:
        with self.connect() as db:
            result = db.execute(
                "UPDATE identities SET alias = ? WHERE identity_key = ?",
                (alias.strip()[:80], identity_key),
            )
            return result.rowcount > 0
