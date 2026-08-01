from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

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

            dashboard = client.get("/api/dashboard")
            self.assertEqual(dashboard.status_code, 200)

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

            user_websites = client.get(
                "/api/users/unknown:100.64.0.11/websites?day=2026-07-28"
            )
            self.assertEqual(user_websites.status_code, 200)
            self.assertEqual(user_websites.json()["device_count"], 1)
            self.assertEqual(user_websites.json()["websites"], [])

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


if __name__ == "__main__":
    unittest.main()
