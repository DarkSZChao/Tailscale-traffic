from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from starlette.requests import Request

import app.main as main
from app.database import Database
from app.firewall import Counter
from app.main import SESSION_COOKIE, app


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Database(
            str(Path(self.temp_dir.name) / "traffic.db")
        )
        main.database = self.database

    def tearDown(self):
        self.temp_dir.cleanup()

    @staticmethod
    def request_from(
        client_ip: str,
        headers: dict[str, str] | None = None,
    ) -> Request:
        return Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/",
                "raw_path": b"/",
                "query_string": b"",
                "headers": [
                    (key.lower().encode(), value.encode())
                    for key, value in (headers or {}).items()
                ],
                "client": (client_ip, 12345),
                "server": ("testserver", 80),
                "scheme": "http",
            }
        )

    def test_client_ip_uses_headers_only_from_trusted_proxy(self):
        proxied = self.request_from(
            "172.20.0.1",
            {"X-Forwarded-For": "100.64.0.11, 172.20.0.2"},
        )
        self.assertEqual(main.client_ip(proxied), "100.64.0.11")

        spoofed = self.request_from(
            "192.0.2.10",
            {"X-Forwarded-For": "100.64.0.12"},
        )
        self.assertEqual(main.client_ip(spoofed), "192.0.2.10")

    def test_session_refresh_and_recognized_device_name(self):
        self.database.record_counters(
            [Counter("100.64.0.11", 4, "download", 1, 100)]
        )
        self.assertTrue(self.database.set_device_alias("100.64.0.11", "工作电脑"))
        token = self.database.create_auth_session(
            "浏览器 · 未知设备",
            "old-agent",
            "172.20.0.1",
            False,
        )

        refreshed = self.database.auth_session(
            token,
            device_name="Chrome · Windows",
            user_agent="new-agent",
            ip_address="100.64.0.11",
        )
        self.assertEqual(refreshed["device_name"], "Chrome · Windows")
        self.assertEqual(refreshed["ip_address"], "100.64.0.11")

        session = self.database.auth_sessions(token)[0]
        self.assertEqual(session["recognized_device_name"], "工作电脑")

    def test_first_setup_login_settings_password_and_logout(self):
        self.database.record_counters(
            [Counter("100.64.0.11", 4, "download", 1, 100)]
        )
        with TestClient(app) as client:
            auth_status = client.get("/api/auth/status")
            self.assertEqual(auth_status.status_code, 200)
            self.assertFalse(auth_status.json()["configured"])

            protected = client.get("/", follow_redirects=False)
            self.assertEqual(protected.status_code, 303)
            self.assertEqual(protected.headers["location"], "/login")

            unconfigured_api = client.get("/api/dashboard")
            self.assertEqual(unconfigured_api.status_code, 428)

            setup = client.post(
                "/api/setup", json={"password": "测试密码-only"}
            )
            self.assertEqual(setup.status_code, 200)
            self.assertIn(SESSION_COOKIE, client.cookies)
            self.assertNotIn(
                "secure",
                setup.headers["set-cookie"].casefold(),
            )

            duplicate_setup = client.post(
                "/api/setup", json={"password": "另一个足够长的面板密码"}
            )
            self.assertEqual(duplicate_setup.status_code, 409)

            client.cookies.clear()
            wrong = client.post("/api/login", json={"password": "wrong"})
            self.assertEqual(wrong.status_code, 401)
            self.assertNotIn(SESSION_COOKIE, wrong.cookies)

            logged_in = client.post(
                "/api/login", json={"password": "测试密码-only"}
            )
            self.assertEqual(logged_in.status_code, 200)
            self.assertIn(SESSION_COOKIE, client.cookies)
            self.assertNotIn(
                "max-age",
                logged_in.headers["set-cookie"].casefold(),
            )

            sessions = client.get("/api/auth/sessions")
            self.assertEqual(sessions.status_code, 200)
            self.assertEqual(len(sessions.json()["sessions"]), 2)
            self.assertEqual(
                sum(item["current"] for item in sessions.json()["sessions"]),
                1,
            )

            logs = client.get("/api/logs")
            self.assertEqual(logs.status_code, 200)
            self.assertTrue(logs.json()["logs"])
            with sqlite3.connect(self.database.path) as traffic_db:
                audit_table = traffic_db.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'audit_logs'
                    """
                ).fetchone()
            self.assertIsNone(audit_table)
            with sqlite3.connect(self.database.log_path) as log_db:
                log_count = log_db.execute(
                    "SELECT COUNT(*) FROM audit_logs"
                ).fetchone()[0]
            self.assertGreater(log_count, 0)

            dashboard = client.get("/api/dashboard")
            self.assertEqual(dashboard.status_code, 200)
            self.assertEqual(
                dashboard.json()["timezone"],
                "UTC",
            )

            device_alias = client.patch(
                "/api/devices/100.64.0.11",
                json={"alias": "测试设备"},
            )
            self.assertEqual(device_alias.status_code, 200)
            dashboard = client.get("/api/dashboard")
            self.assertEqual(
                dashboard.json()["users"][0]["device_items"][0]["device_name"],
                "测试设备",
            )

            settings = client.get("/api/settings")
            self.assertEqual(settings.status_code, 200)
            self.assertIsNotNone(settings.json()["config_modified_at"])
            config = settings.json()["config"]
            config.update(
                {
                    "collect_interval": 1,
                    "monthly_quota_gb": 2500,
                    "timezone": "Asia/Shanghai",
                }
            )
            updated = client.put("/api/settings", json=config)
            self.assertEqual(updated.status_code, 200)
            self.assertEqual(
                updated.json()["config"]["collect_interval"],
                1,
            )

            websites = client.get(
                "/api/devices/100.64.0.11/websites?day=2026-07-28"
            )
            self.assertEqual(websites.status_code, 200)
            self.assertEqual(websites.json()["websites"], [])

            recent_websites = client.get(
                "/api/devices/100.64.0.11/websites?period=24h"
            )
            self.assertEqual(recent_websites.status_code, 200)
            self.assertEqual(recent_websites.json()["period"], "24h")
            self.assertIsNone(recent_websites.json()["day"])

            user_websites = client.get(
                "/api/users/unknown:100.64.0.11/websites?day=2026-07-28"
            )
            self.assertEqual(user_websites.status_code, 200)
            self.assertEqual(user_websites.json()["device_count"], 1)
            self.assertEqual(user_websites.json()["websites"], [])

            invalid_period = client.get(
                "/api/devices/100.64.0.11/websites?period=week"
            )
            self.assertEqual(invalid_period.status_code, 422)

            policy = client.put(
                "/api/policies/user/unknown:100.64.0.11",
                json={"monthly_limit_bytes": 1},
            )
            self.assertEqual(policy.status_code, 200)
            self.assertTrue(policy.json()["policy"]["blocked"])

            policies = client.get("/api/policies")
            self.assertEqual(policies.status_code, 200)
            self.assertEqual(len(policies.json()["rules"]), 1)

            disabled = client.put(
                "/api/policies/user/unknown:100.64.0.11/enabled",
                json={"enabled": False},
            )
            self.assertEqual(disabled.status_code, 200)
            self.assertFalse(disabled.json()["policy"]["enabled"])
            self.assertFalse(disabled.json()["policy"]["blocked"])

            enabled = client.put(
                "/api/policies/user/unknown:100.64.0.11/enabled",
                json={"enabled": True},
            )
            self.assertEqual(enabled.status_code, 200)
            self.assertTrue(enabled.json()["policy"]["enabled"])

            quota_disabled = client.put(
                "/api/policies/user/unknown:100.64.0.11/quota/enabled",
                json={"enabled": False},
            )
            self.assertEqual(quota_disabled.status_code, 200)
            self.assertFalse(
                quota_disabled.json()["policy"]["quota_enabled"]
            )

            quota_enabled = client.put(
                "/api/policies/user/unknown:100.64.0.11/quota/enabled",
                json={"enabled": True},
            )
            self.assertEqual(quota_enabled.status_code, 200)
            self.assertTrue(quota_enabled.json()["policy"]["quota_enabled"])

            unlocked = client.post(
                "/api/policies/user/unknown:100.64.0.11/unlock"
            )
            self.assertEqual(unlocked.status_code, 200)
            self.assertTrue(unlocked.json()["policy"]["bypassed"])

            deleted = client.delete(
                "/api/policies/user/unknown:100.64.0.11"
            )
            self.assertEqual(deleted.status_code, 200)
            self.assertIsNone(deleted.json()["policy"]["limit_bytes"])

            temporary_block = client.put(
                "/api/policies/user/unknown:100.64.0.11/block",
                json={"duration_seconds": 3600},
            )
            self.assertEqual(temporary_block.status_code, 200)
            self.assertTrue(
                temporary_block.json()["policy"]["manual_blocked"]
            )
            self.assertEqual(
                temporary_block.json()["policy"]["block_mode"],
                "temporary",
            )

            removed_block = client.delete(
                "/api/policies/user/unknown:100.64.0.11/block"
            )
            self.assertEqual(removed_block.status_code, 200)
            self.assertFalse(
                removed_block.json()["policy"]["manual_blocked"]
            )

            permanent_block = client.put(
                "/api/policies/user/unknown:100.64.0.11/block",
                json={"permanent": True},
            )
            self.assertEqual(permanent_block.status_code, 200)
            self.assertEqual(
                permanent_block.json()["policy"]["block_mode"],
                "permanent",
            )
            deleted_bundle = client.delete(
                "/api/policies/user/unknown:100.64.0.11/rule"
            )
            self.assertEqual(deleted_bundle.status_code, 200)
            self.assertEqual(client.get("/api/policies").json()["rules"], [])

            with TestClient(app) as old_session:
                old_login = old_session.post(
                    "/api/login",
                    json={"password": "测试密码-only"},
                )
                self.assertEqual(old_login.status_code, 200)

                changed = client.put(
                    "/api/settings/password",
                    json={
                        "current_password": "测试密码-only",
                        "new_password": "更新后的测试密码",
                    },
                )
                self.assertEqual(changed.status_code, 200)
                self.assertEqual(
                    old_session.get("/api/dashboard").status_code,
                    401,
                )
                self.assertEqual(
                    client.get("/api/dashboard").status_code,
                    200,
                )

            logged_out = client.post("/api/logout")
            self.assertEqual(logged_out.status_code, 200)
            self.assertNotIn(SESSION_COOKIE, client.cookies)
            self.assertEqual(client.get("/api/dashboard").status_code, 401)

    def test_remembered_session_and_logout_all(self):
        with TestClient(app) as client:
            setup = client.post(
                "/api/setup",
                json={"password": "测试密码-only", "remember": True},
            )
            self.assertEqual(setup.status_code, 200)
            self.assertIn("max-age=2592000", setup.headers["set-cookie"].casefold())

            sessions = client.get("/api/auth/sessions").json()["sessions"]
            self.assertEqual(len(sessions), 1)
            self.assertTrue(sessions[0]["remembered"])

            logout_all = client.post("/api/auth/sessions/logout-all")
            self.assertEqual(logout_all.status_code, 200)
            self.assertEqual(logout_all.json()["count"], 1)
            self.assertEqual(client.get("/api/dashboard").status_code, 401)

    def test_legacy_audit_logs_are_migrated_to_log_database(self):
        legacy_dir = Path(self.temp_dir.name) / "legacy"
        legacy_dir.mkdir()
        traffic_path = legacy_dir / "traffic.db"
        with sqlite3.connect(traffic_path) as traffic_db:
            traffic_db.execute(
                """
                CREATE TABLE audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    category TEXT NOT NULL,
                    level TEXT NOT NULL,
                    action TEXT NOT NULL,
                    message TEXT NOT NULL,
                    ip_address TEXT NOT NULL DEFAULT ''
                )
                """
            )
            traffic_db.execute(
                """
                INSERT INTO audit_logs
                    (created_at, category, level, action, message, ip_address)
                VALUES ('2026-09-06T00:00:00+00:00', 'auth', 'info',
                        'login', '旧日志', '127.0.0.1')
                """
            )

        migrated = Database(str(traffic_path))
        self.assertEqual(migrated.audit_logs()[0]["message"], "旧日志")
        with sqlite3.connect(traffic_path) as traffic_db:
            old_table = traffic_db.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'audit_logs'
                """
            ).fetchone()
        self.assertIsNone(old_table)


if __name__ == "__main__":
    unittest.main()
