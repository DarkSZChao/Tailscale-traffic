from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ["TSM_DEMO"] = "true"
os.environ["DASHBOARD_PASSWORD"] = "测试密码-only"
os.environ["DATABASE_PATH"] = str(
    Path(tempfile.gettempdir()) / "tailscale-traffic-auth-test.db"
)

from fastapi.testclient import TestClient

from app.main import SESSION_COOKIE, app


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        database = Path(os.environ["DATABASE_PATH"])
        for suffix in ("", "-shm", "-wal"):
            Path(f"{database}{suffix}").unlink(missing_ok=True)

    def test_password_only_login_and_logout(self):
        with TestClient(app) as client:
            protected = client.get("/", follow_redirects=False)
            self.assertEqual(protected.status_code, 303)
            self.assertEqual(protected.headers["location"], "/login")

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
            self.assertFalse(
                dashboard.json()["collector"]["enforcement_supported"]
            )

            policy = client.put(
                "/api/policies/user/user:demo-alice",
                json={"monthly_limit_bytes": 1},
            )
            self.assertEqual(policy.status_code, 200)
            self.assertTrue(policy.json()["policy"]["blocked"])

            policies = client.get("/api/policies")
            self.assertEqual(policies.status_code, 200)
            self.assertEqual(len(policies.json()["rules"]), 1)
            self.assertFalse(policies.json()["enforcement_supported"])

            unlocked = client.post(
                "/api/policies/user/user:demo-alice/unlock"
            )
            self.assertEqual(unlocked.status_code, 200)
            self.assertTrue(unlocked.json()["policy"]["bypassed"])

            deleted = client.delete(
                "/api/policies/user/user:demo-alice"
            )
            self.assertEqual(deleted.status_code, 200)
            self.assertIsNone(deleted.json()["policy"]["limit_bytes"])

            logged_out = client.post("/api/logout")
            self.assertEqual(logged_out.status_code, 200)
            self.assertNotIn(SESSION_COOKIE, client.cookies)
            self.assertEqual(client.get("/api/dashboard").status_code, 401)


if __name__ == "__main__":
    unittest.main()
