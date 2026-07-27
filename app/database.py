from __future__ import annotations

import calendar
import os
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from typing import Iterable

from .firewall import Counter
from .tailscale import Peer


class Database:
    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self._initialize()

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
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS identities (
                    identity_key TEXT PRIMARY KEY,
                    login_name TEXT NOT NULL DEFAULT '',
                    display_name TEXT NOT NULL DEFAULT '',
                    alias TEXT NOT NULL DEFAULT '',
                    network_scope TEXT NOT NULL DEFAULT 'unknown',
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
                """
            )
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

    @staticmethod
    def _now() -> str:
        return datetime.now().astimezone().isoformat(timespec="seconds")

    def sync_peers(self, peers: Iterable[Peer]) -> None:
        now = self._now()
        with self.connect() as db:
            db.execute("UPDATE devices SET online = 0")
            for peer in peers:
                db.execute(
                    """
                    INSERT INTO identities
                        (identity_key, login_name, display_name,
                         network_scope, last_seen)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(identity_key) DO UPDATE SET
                        login_name = excluded.login_name,
                        display_name = excluded.display_name,
                        network_scope = excluded.network_scope,
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
                    INSERT INTO devices
                        (ip, family, identity_key, device_id, device_name,
                         dns_name, os_name, online, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        family = excluded.family,
                        identity_key = excluded.identity_key,
                        device_id = excluded.device_id,
                        device_name = excluded.device_name,
                        dns_name = excluded.dns_name,
                        os_name = excluded.os_name,
                        online = excluded.online,
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
        today = date.today().isoformat()
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

    @staticmethod
    def month_bounds(month: str | None) -> tuple[date, date, str]:
        today = date.today()
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
            usage = self._target_usage(
                db,
                target_type,
                target_key,
                start.isoformat(),
                end.isoformat(),
            )

        limit = int(rule["monthly_limit_bytes"]) if rule else None
        exceeded = bool(limit is not None and usage >= limit)
        bypassed = bool(
            rule and exceeded and rule["bypass_month"] == current_month
        )
        return {
            "target_type": target_type,
            "target_key": target_key,
            "limit_bytes": limit,
            "usage_bytes": usage,
            "exceeded": exceeded,
            "bypassed": bypassed,
            "blocked": exceeded and not bypassed,
            "month": current_month,
        }

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
            return result.rowcount > 0

    def bypass_quota_for_current_month(
        self, target_type: str, target_key: str
    ) -> dict | None:
        current_month = date.today().strftime("%Y-%m")
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
        blocked: set[str] = set()
        with self.connect() as db:
            rules = db.execute(
                """
                SELECT target_type, target_key, monthly_limit_bytes, bypass_month
                FROM quota_rules
                """
            ).fetchall()
            for rule in rules:
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
        return blocked

    def quota_rules_overview(self) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT target_type, target_key
                FROM quota_rules
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
                               network_scope
                        FROM identities WHERE identity_key = ?
                        """,
                        (row["target_key"],),
                    ).fetchone()
                    subtitle = (
                        "外部分享用户"
                        if target and target["network_scope"] == "external"
                        else "本 Tailnet 用户"
                    )
                else:
                    target = db.execute(
                        """
                        SELECT MAX(device_name) AS name, MAX(os_name) AS os_name
                        FROM devices WHERE device_id = ?
                        """,
                        (row["target_key"],),
                    ).fetchone()
                    subtitle = (
                        f"{target['os_name'] or '未知系统'} · 单设备规则"
                        if target
                        else "单设备规则"
                    )
                targets.append(
                    {
                        "target_type": row["target_type"],
                        "target_key": row["target_key"],
                        "target_name": (
                            str(target["name"]).upper()
                            if target and row["target_type"] == "device"
                            else str(target["name"])
                            if target
                            else row["target_key"]
                        ),
                        "subtitle": subtitle,
                    }
                )

        result = []
        for target in targets:
            state = self.quota_state(
                target["target_type"], target["target_key"]
            )
            if not state:
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

    def dashboard(self, month: str | None, quota_bytes: int) -> dict:
        start, end, normalized_month = self.month_bounds(month)
        with self.connect() as db:
            usage_rows = db.execute(
                """
                SELECT
                    u.identity_key,
                    COALESCE(NULLIF(i.alias, ''), NULLIF(i.display_name, ''),
                             NULLIF(i.login_name, ''), u.identity_key) AS name,
                    i.login_name,
                    i.network_scope,
                    SUM(u.upload_bytes) AS upload,
                    SUM(u.download_bytes) AS download
                FROM usage_daily u
                JOIN identities i ON i.identity_key = u.identity_key
                WHERE u.day BETWEEN ? AND ?
                GROUP BY u.identity_key
                ORDER BY SUM(u.upload_bytes + u.download_bytes) DESC
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
        now = date.today()
        elapsed_days = (
            min(now, end).day if start.year == now.year and start.month == now.month
            else end.day
        )
        forecast = int(total / max(1, elapsed_days) * end.day)
        for user in users:
            user["device_items"] = self.devices_for(
                user["key"], normalized_month
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
        self, identity_key: str, month: str | None = None
    ) -> list[dict]:
        start, end, _ = self.month_bounds(month)
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT device_id, ip, family, device_name, dns_name, os_name,
                       online, last_seen
                FROM devices WHERE identity_key = ?
                ORDER BY device_name, device_id, family
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
                    "device_name": (row["device_name"] or row["ip"]).upper(),
                    "dns_name": row["dns_name"],
                    "os_name": row["os_name"],
                    "online": False,
                    "last_seen": row["last_seen"],
                    "addresses": [],
                },
            )
            device["online"] = device["online"] or bool(row["online"])
            device["last_seen"] = max(device["last_seen"], row["last_seen"])
            if not device["os_name"] and row["os_name"]:
                device["os_name"] = row["os_name"]
            device["addresses"].append(
                {"ip": row["ip"], "family": int(row["family"])}
            )

        devices = list(grouped.values())
        for device in devices:
            device["addresses"].sort(key=lambda item: (item["family"], item["ip"]))
            device_usage = usage.get(
                device["device_id"], {"upload": 0, "download": 0}
            )
            device["upload"] = device_usage["upload"]
            device["download"] = device_usage["download"]
            device["total"] = (
                device_usage["upload"] + device_usage["download"]
            )
            device["policy"] = self.quota_state("device", device["device_id"])
        devices.sort(
            key=lambda device: (
                not device["online"],
                device["device_name"].casefold(),
                device["device_id"],
            )
        )
        return devices

    def set_alias(self, identity_key: str, alias: str) -> bool:
        with self.connect() as db:
            result = db.execute(
                "UPDATE identities SET alias = ? WHERE identity_key = ?",
                (alias.strip()[:80], identity_key),
            )
            return result.rowcount > 0

    def seed_demo(self) -> None:
        if self.dashboard(None, 1)["users"]:
            return
        today = date.today()
        identities = [
            ("user:demo-alice", "alice@example.com", "Alice", "小林"),
            ("user:demo-bob", "bob@example.com", "Bob", "阿杰"),
            ("user:demo-carol", "carol@example.com", "Carol", "Mika"),
        ]
        with self.connect() as db:
            now = self._now()
            for index, (key, login, display, alias) in enumerate(identities, 1):
                db.execute(
                    """
                    INSERT INTO identities
                        (identity_key, login_name, display_name, alias,
                         network_scope, last_seen)
                    VALUES (?, ?, ?, ?, 'external', ?)
                    """,
                    (key, login, display, alias, now),
                )
                db.execute(
                    """
                    INSERT INTO devices
                        (ip, family, identity_key, device_id, device_name,
                         os_name, online, last_seen)
                    VALUES (?, 4, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"100.64.0.{index + 10}",
                        key,
                        f"demo-{index}",
                        ["MacBook-Air", "Pixel-9", "Windows-PC"][index - 1],
                        ["macOS", "android", "windows"][index - 1],
                        int(index < 3),
                        now,
                    ),
                )
            for offset in range(today.day):
                day = today.replace(day=offset + 1).isoformat()
                for index, (key, *_rest) in enumerate(identities, 1):
                    upload = (110_000_000 + (offset * 37_000_000)) * index
                    download = (620_000_000 + (offset * 91_000_000)) * index
                    db.execute(
                        """
                        INSERT INTO usage_daily
                            (day, identity_key, upload_bytes, download_bytes)
                        VALUES (?, ?, ?, ?)
                        """,
                        (day, key, upload, download),
                    )
                    db.execute(
                        """
                        INSERT INTO device_usage_daily
                            (day, device_id, upload_bytes, download_bytes)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(day, device_id) DO UPDATE SET
                            upload_bytes = excluded.upload_bytes,
                            download_bytes = excluded.download_bytes
                        """,
                        (day, f"demo-{index}", upload, download),
                    )
            db.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('last_collect', ?)",
                (now,),
            )
