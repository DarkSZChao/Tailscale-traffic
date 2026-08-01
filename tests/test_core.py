from __future__ import annotations

import tempfile
import unittest
import ipaddress
import sqlite3
import struct
from datetime import date
from pathlib import Path
from unittest.mock import patch

from app.collector import Collector
from app.config import AppConfig
from app.database import Database
from app.firewall import Counter, Firewall
from app.tailscale import Peer, TailscaleClient
from app.website_collector import (
    DnsCache,
    parse_conntrack_line,
    parse_dns_response,
    parse_http_host,
    parse_tls_sni,
    parse_transport_packet,
)


class FakeTailscaleClient(TailscaleClient):
    def __init__(self, payload):
        self.payload = payload

    def status(self):
        return self.payload


class TailscaleTests(unittest.TestCase):
    def test_status_maps_user_and_each_ip(self):
        client = FakeTailscaleClient(
            {
                "User": {
                    "90071992547409931": {
                        "LoginName": "friend@example.com",
                        "DisplayName": "Friend",
                    }
                },
                "Peer": {
                    "node-key": {
                        "ID": "n123",
                        "HostName": "phone",
                        "DNSName": "phone.example.ts.net.",
                        "OS": "android",
                        "Online": True,
                        "ShareeNode": True,
                        "Expired": True,
                        "UserID": 90071992547409931,
                        "TailscaleIPs": [
                            "100.64.1.2",
                            "fd7a:115c:a1e0::1234",
                        ],
                    }
                },
            }
        )

        peers = client.peers()
        self.assertEqual(len(peers), 2)
        self.assertEqual(peers[0].identity_key, "user:90071992547409931")
        self.assertEqual(peers[0].login_name, "friend@example.com")
        self.assertEqual({peer.family for peer in peers}, {4, 6})
        self.assertEqual({peer.network_scope for peer in peers}, {"external"})
        self.assertEqual({peer.expired for peer in peers}, {True})

    def test_whois_maps_external_shared_user(self):
        class FakeWhoisClient(TailscaleClient):
            def __init__(self):
                self.requested_path = ""

            def _get(self, path):
                self.requested_path = path
                return {
                    "Node": {
                        "ID": "n-shared",
                        "ComputedName": "friend-phone",
                        "Name": "friend-phone.example.ts.net.",
                        "Hostinfo": {"OS": "iOS", "Hostname": "friend-phone"},
                    },
                    "UserProfile": {
                        "ID": 42,
                        "LoginName": "friend@example.com",
                        "DisplayName": "Friend",
                    },
                }

        client = FakeWhoisClient()
        peer = client.whois("fd7a:115c:a1e0::42")
        self.assertEqual(peer.identity_key, "user:42")
        self.assertEqual(peer.device_id, "n-shared")
        self.assertEqual(peer.network_scope, "external")
        self.assertIn(
            "%5Bfd7a%3A115c%3Aa1e0%3A%3A42%5D%3A1",
            client.requested_path,
        )

    def test_status_ignores_peer_removed_from_latest_network_map(self):
        client = FakeTailscaleClient(
            {
                "User": {
                    "42": {
                        "LoginName": "removed@example.com",
                        "DisplayName": "Removed",
                    }
                },
                "Peer": {
                    "old-node-key": {
                        "ID": "old-node",
                        "UserID": 42,
                        "InNetworkMap": False,
                        "ShareeNode": True,
                        "TailscaleIPs": ["100.64.1.9"],
                    }
                },
            }
        )

        self.assertEqual(client.peers(), [])


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.temp_dir.name) / "traffic.db"))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_app_config_and_password_are_persisted(self):
        updated = AppConfig(
            monthly_quota_gb=2500,
            collect_interval=1,
            website_retention_days=30,
            timezone="Asia/Shanghai",
        )
        self.db.update_app_config(updated)
        reopened = Database(self.db.path)
        self.assertEqual(reopened.get_app_config(), updated)
        config_path = Path(self.temp_dir.name) / "config.yaml"
        self.assertTrue(config_path.exists())
        self.assertIn(
            "collect_interval: 1",
            config_path.read_text(encoding="utf-8"),
        )
        with reopened.connect() as connection:
            legacy_table = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'app_config'
                """
            ).fetchone()
        self.assertIsNone(legacy_table)

        self.assertFalse(reopened.auth_configured())
        self.assertTrue(reopened.initialize_password("测试面板密码"))
        self.assertFalse(reopened.initialize_password("另一个面板密码"))
        self.assertTrue(reopened.verify_password("测试面板密码"))
        previous_secret = reopened.session_secret()
        self.assertTrue(
            reopened.change_password("测试面板密码", "更新后的面板密码")
        )
        self.assertFalse(reopened.verify_password("测试面板密码"))
        self.assertTrue(reopened.verify_password("更新后的面板密码"))
        self.assertNotEqual(previous_secret, reopened.session_secret())

    def test_legacy_database_config_is_migrated_to_yaml(self):
        legacy_dir = Path(self.temp_dir.name) / "legacy"
        legacy_dir.mkdir()
        legacy_path = legacy_dir / "traffic.db"
        connection = sqlite3.connect(legacy_path)
        connection.executescript(
            """
            CREATE TABLE app_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO app_config VALUES
                ('collect_interval', '3', ''),
                ('timezone', 'Asia/Shanghai', '');
            """
        )
        connection.commit()
        connection.close()

        migrated = Database(str(legacy_path))
        config = migrated.get_app_config()
        self.assertEqual(config.collect_interval, 3)
        self.assertEqual(config.timezone, "Asia/Shanghai")
        self.assertTrue((legacy_dir / "config.yaml").exists())
        with migrated.connect() as database:
            table = database.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'app_config'
                """
            ).fetchone()
        self.assertIsNone(table)

    def test_counter_deltas_and_reset_are_accumulated(self):
        first = Counter("100.64.1.2", 4, "upload", 10, 1000)
        second = Counter("100.64.1.2", 4, "upload", 15, 1750)
        reset = Counter("100.64.1.2", 4, "upload", 2, 200)

        self.db.record_counters([first])
        self.db.record_counters([second])
        self.db.record_counters([reset])

        dashboard = self.db.dashboard(date.today().strftime("%Y-%m"), 10_000)
        self.assertEqual(dashboard["summary"]["upload"], 1950)
        self.assertEqual(dashboard["summary"]["download"], 0)
        self.assertEqual(len(dashboard["users"]), 1)

    def test_alias_changes_dashboard_name(self):
        self.db.record_counters(
            [Counter("100.64.1.3", 4, "download", 2, 500)]
        )
        key = "unknown:100.64.1.3"
        self.assertTrue(self.db.set_alias(key, "小林"))
        dashboard = self.db.dashboard(None, 10_000)
        self.assertEqual(dashboard["users"][0]["name"], "小林")

    def test_unknown_usage_moves_when_whois_resolves_identity(self):
        address = "100.64.1.4"
        self.db.record_counters(
            [Counter(address, 4, "download", 2, 500)]
        )
        self.db.sync_peers(
            [
                Peer(
                    ip=address,
                    family=4,
                    identity_key="user:42",
                    login_name="friend@example.com",
                    display_name="Friend",
                    device_id="node-42",
                    device_name="phone",
                    dns_name="phone.example.ts.net",
                    os_name="android",
                    online=True,
                )
            ]
        )
        dashboard = self.db.dashboard(None, 10_000)
        self.assertEqual(len(dashboard["users"]), 1)
        self.assertEqual(dashboard["users"][0]["key"], "user:42")
        self.assertEqual(dashboard["users"][0]["download"], 500)

    def test_devices_merge_ipv4_and_ipv6(self):
        peers = [
            Peer(
                ip=ip,
                family=family,
                identity_key="user:42",
                login_name="friend@example.com",
                display_name="Friend",
                device_id="node-42",
                device_name="Phone-Pro",
                dns_name="phone-pro.example.ts.net",
                os_name="android",
                online=True,
            )
            for ip, family in [
                ("100.64.1.4", 4),
                ("fd7a:115c:a1e0::42", 6),
            ]
        ]
        self.db.sync_peers(peers)
        self.db.record_counters(
            [
                Counter("100.64.1.4", 4, "download", 2, 700),
                Counter("fd7a:115c:a1e0::42", 6, "upload", 1, 300),
            ]
        )
        devices = self.db.devices_for("user:42")
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["device_name"], "PHONE-PRO")
        self.assertEqual(len(devices[0]["addresses"]), 2)
        self.assertEqual(devices[0]["download"], 700)
        self.assertEqual(devices[0]["upload"], 300)
        self.assertEqual(devices[0]["total"], 1_000)
        dashboard = self.db.dashboard(None, 10_000)
        self.assertEqual(dashboard["users"][0]["device_items"][0]["total"], 1_000)

    def test_shared_device_uses_ipv4_suffix_and_persistent_alias(self):
        self.db.sync_peers(
            [
                Peer(
                    ip=ip,
                    family=family,
                    identity_key="user:shared",
                    login_name="friend@example.com",
                    display_name="Friend",
                    device_id="node-shared",
                    device_name="device-of-shared-to-user",
                    dns_name="",
                    os_name="",
                    online=True,
                    network_scope="external",
                )
                for ip, family in [
                    ("100.94.69.21", 4),
                    ("fd7a:115c:a1e0::8b01:a128", 6),
                ]
            ]
        )
        devices = self.db.devices_for("user:shared")
        self.assertEqual(devices[0]["device_name"], "SHARED-DEVICE-021")
        self.assertEqual(devices[0]["alias"], "")

        self.assertTrue(self.db.set_device_alias("node-shared", "朋友的手机"))
        reopened = Database(self.db.path)
        renamed = reopened.devices_for("user:shared")
        self.assertEqual(renamed[0]["device_name"], "朋友的手机")
        self.assertEqual(renamed[0]["alias"], "朋友的手机")
        self.assertEqual(
            reopened.websites_for_device("node-shared", None)["device_name"],
            "朋友的手机",
        )

        self.assertTrue(reopened.set_device_alias("node-shared", ""))
        restored = reopened.devices_for("user:shared")
        self.assertEqual(restored[0]["device_name"], "SHARED-DEVICE-021")
        self.assertFalse(reopened.set_device_alias("missing-device", "备注"))

    def test_devices_are_sorted_by_usage_before_online_state_and_name(self):
        self.db.sync_peers(
            [
                Peer(
                    ip="100.64.1.10",
                    family=4,
                    identity_key="user:42",
                    login_name="friend@example.com",
                    display_name="Friend",
                    device_id="node-light",
                    device_name="A-light",
                    dns_name="",
                    os_name="ios",
                    online=True,
                ),
                Peer(
                    ip="100.64.1.11",
                    family=4,
                    identity_key="user:42",
                    login_name="friend@example.com",
                    display_name="Friend",
                    device_id="node-heavy",
                    device_name="Z-heavy",
                    dns_name="",
                    os_name="ios",
                    online=False,
                ),
            ]
        )
        self.db.record_counters(
            [
                Counter("100.64.1.10", 4, "download", 1, 100),
                Counter("100.64.1.11", 4, "download", 1, 900),
            ]
        )
        devices = self.db.devices_for("user:42")
        self.assertEqual(
            [device["device_id"] for device in devices],
            ["node-heavy", "node-light"],
        )

    def test_expired_zero_usage_devices_are_hidden_unless_requested(self):
        self.db.sync_peers(
            [
                Peer(
                    ip="100.64.1.20",
                    family=4,
                    identity_key="user:42",
                    login_name="friend@example.com",
                    display_name="Friend",
                    device_id="node-active-zero",
                    device_name="Active Zero",
                    dns_name="",
                    os_name="ios",
                    online=True,
                ),
                Peer(
                    ip="100.64.1.21",
                    family=4,
                    identity_key="user:42",
                    login_name="friend@example.com",
                    display_name="Friend",
                    device_id="node-expired-used",
                    device_name="Expired Used",
                    dns_name="",
                    os_name="ios",
                    online=False,
                    expired=True,
                ),
                Peer(
                    ip="100.64.1.22",
                    family=4,
                    identity_key="user:42",
                    login_name="friend@example.com",
                    display_name="Friend",
                    device_id="node-expired-zero",
                    device_name="Expired Zero",
                    dns_name="",
                    os_name="ios",
                    online=False,
                    expired=True,
                ),
            ]
        )
        self.db.record_counters(
            [Counter("100.64.1.21", 4, "download", 1, 500)]
        )

        visible = self.db.devices_for("user:42")
        self.assertEqual(
            [device["device_id"] for device in visible],
            ["node-expired-used", "node-active-zero"],
        )
        self.assertTrue(visible[0]["expired"])

        all_devices = self.db.devices_for("user:42", show_expired=True)
        self.assertEqual(
            [device["device_id"] for device in all_devices],
            [
                "node-expired-used",
                "node-active-zero",
                "node-expired-zero",
            ],
        )
        self.assertTrue(all_devices[-1]["expired"])

    def test_dashboard_separates_tailnet_and_external_usage(self):
        peers = [
            Peer(
                ip="100.64.1.5",
                family=4,
                identity_key="user:tailnet",
                login_name="owner@example.com",
                display_name="Owner",
                device_id="node-tailnet",
                device_name="owner-phone",
                dns_name="",
                os_name="android",
                online=True,
                network_scope="tailnet",
            ),
            Peer(
                ip="100.64.1.6",
                family=4,
                identity_key="user:external",
                login_name="friend@example.com",
                display_name="Friend",
                device_id="node-external",
                device_name="friend-phone",
                dns_name="",
                os_name="ios",
                online=True,
                network_scope="external",
            ),
            Peer(
                ip="100.64.1.7",
                family=4,
                identity_key="user:external-heavy",
                login_name="heavy-friend@example.com",
                display_name="Heavy Friend",
                device_id="node-external-heavy",
                device_name="heavy-friend-phone",
                dns_name="",
                os_name="ios",
                online=True,
                network_scope="external",
            ),
            Peer(
                ip="100.64.1.8",
                family=4,
                identity_key="user:external-zero",
                login_name="idle-friend@example.com",
                display_name="Idle Friend",
                device_id="node-external-zero",
                device_name="idle-friend-phone",
                dns_name="",
                os_name="ios",
                online=False,
                network_scope="external",
            ),
        ]
        self.db.sync_peers(peers)
        self.db.record_counters(
            [
                Counter("100.64.1.5", 4, "upload", 1, 300),
                Counter("100.64.1.6", 4, "download", 1, 100),
                Counter("100.64.1.7", 4, "download", 1, 200),
            ]
        )
        dashboard = self.db.dashboard(None, 10_000)
        self.assertEqual(dashboard["summary"]["tailnet_total"], 300)
        self.assertEqual(dashboard["summary"]["external_total"], 300)
        self.assertEqual(
            [user["key"] for user in dashboard["users"]],
            [
                "user:external-heavy",
                "user:external",
                "user:external-zero",
                "user:tailnet",
            ],
        )
        idle = next(
            user
            for user in dashboard["users"]
            if user["key"] == "user:external-zero"
        )
        self.assertEqual(idle["total"], 0)
        self.assertEqual(idle["device_items"][0]["total"], 0)
        scopes = {user["key"]: user["network_scope"] for user in dashboard["users"]}
        self.assertEqual(scopes["user:tailnet"], "tailnet")
        self.assertEqual(scopes["user:external"], "external")

    def test_removed_user_is_hidden_without_selected_month_usage(self):
        peer = Peer(
            ip="100.64.1.9",
            family=4,
            identity_key="user:removed-zero",
            login_name="removed-zero@example.com",
            display_name="Removed Zero",
            device_id="node-removed-zero",
            device_name="old-phone",
            dns_name="",
            os_name="ios",
            online=False,
            network_scope="external",
        )
        self.db.sync_peers([peer])
        self.assertEqual(len(self.db.dashboard(None, 10_000)["users"]), 1)

        self.db.sync_peers([])
        dashboard = self.db.dashboard(None, 10_000)
        self.assertEqual(dashboard["users"], [])

    def test_removed_user_with_usage_is_marked_and_restored_if_seen_again(self):
        peer = Peer(
            ip="100.64.1.10",
            family=4,
            identity_key="user:removed-used",
            login_name="removed-used@example.com",
            display_name="Removed Used",
            device_id="node-removed-used",
            device_name="old-phone",
            dns_name="",
            os_name="ios",
            online=True,
            network_scope="external",
        )
        self.db.sync_peers([peer])
        self.db.record_counters(
            [Counter("100.64.1.10", 4, "download", 1, 500)]
        )

        self.db.sync_peers([])
        removed = self.db.dashboard(None, 10_000)["users"][0]
        self.assertTrue(removed["removed"])
        self.assertIsNotNone(removed["removed_at"])
        self.assertEqual(removed["total"], 500)

        self.db.sync_peers([peer])
        restored = self.db.dashboard(None, 10_000)["users"][0]
        self.assertFalse(restored["removed"])
        self.assertIsNone(restored["removed_at"])

    def test_collector_status_is_shared_through_database(self):
        initial = self.db.collector_status()
        self.assertFalse(initial["healthy"])

        self.db.update_collector_status("linux-firewall", 10)
        healthy = self.db.collector_status()
        self.assertTrue(healthy["healthy"])
        self.assertEqual(healthy["interval"], 10)

        self.db.update_collector_status(
            "linux-firewall",
            10,
            "iptables unavailable",
        )
        failed = self.db.collector_status()
        self.assertFalse(failed["healthy"])
        self.assertEqual(failed["error"], "iptables unavailable")

    def test_website_flows_are_aggregated_by_device_domain_and_day(self):
        self.db.sync_peers(
            [
                Peer(
                    ip="100.64.4.2",
                    family=4,
                    identity_key="user:website",
                    login_name="friend@example.com",
                    display_name="Friend",
                    device_id="node-website",
                    device_name="phone",
                    dns_name="",
                    os_name="ios",
                    online=True,
                    network_scope="external",
                )
            ]
        )
        base = {
            "flow_key": "tcp|100.64.4.2|93.184.216.34|50000|443",
            "device_ip": "100.64.4.2",
            "destination": "example.com",
        }
        self.db.record_website_flows(
            [{**base, "upload_bytes": 100, "download_bytes": 200}]
        )
        self.db.record_website_flows(
            [{**base, "upload_bytes": 150, "download_bytes": 350}]
        )
        self.db.record_website_flows(
            [
                {
                    **base,
                    "flow_key": "tcp|100.64.4.2|93.184.216.34|50001|443",
                    "upload_bytes": 20,
                    "download_bytes": 80,
                }
            ]
        )

        payload = self.db.websites_for_device("node-website", None)
        self.assertEqual(payload["summary"]["destinations"], 1)
        self.assertEqual(payload["summary"]["visits"], 2)
        self.assertEqual(payload["summary"]["upload"], 170)
        self.assertEqual(payload["summary"]["download"], 430)
        self.assertEqual(payload["websites"][0]["destination"], "example.com")

        self.db.sync_peers(
            [
                Peer(
                    ip="100.64.4.3",
                    family=4,
                    identity_key="user:website",
                    login_name="friend@example.com",
                    display_name="Friend",
                    device_id="node-website-2",
                    device_name="tablet",
                    dns_name="",
                    os_name="android",
                    online=True,
                    network_scope="external",
                )
            ]
        )
        self.db.record_website_flows(
            [
                {
                    "flow_key": "tcp|100.64.4.3|93.184.216.34|50002|443",
                    "device_ip": "100.64.4.3",
                    "destination": "example.com",
                    "upload_bytes": 50,
                    "download_bytes": 70,
                }
            ]
        )
        user_payload = self.db.websites_for_user("user:website", None)
        self.assertEqual(user_payload["device_count"], 2)
        self.assertEqual(user_payload["summary"]["destinations"], 1)
        self.assertEqual(user_payload["summary"]["visits"], 3)
        self.assertEqual(user_payload["summary"]["upload"], 220)
        self.assertEqual(user_payload["summary"]["download"], 500)

    def test_device_quota_blocks_all_device_addresses_and_can_be_bypassed(self):
        peers = [
            Peer(
                ip=ip,
                family=family,
                identity_key="user:42",
                login_name="friend@example.com",
                display_name="Friend",
                device_id="node-42",
                device_name="phone",
                dns_name="",
                os_name="ios",
                online=True,
                network_scope="external",
            )
            for ip, family in [
                ("100.64.1.7", 4),
                ("fd7a:115c:a1e0::47", 6),
            ]
        ]
        self.db.sync_peers(peers)
        self.db.record_counters(
            [Counter("100.64.1.7", 4, "download", 1, 1_000)]
        )
        state = self.db.set_quota_rule("device", "node-42", 500)
        self.assertTrue(state["blocked"])
        rules = self.db.quota_rules_overview()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["target_name"], "PHONE")
        self.assertEqual(rules[0]["subtitle"], "100.64.1.7")
        self.assertEqual(rules[0]["policy"]["limit_bytes"], 500)
        self.assertEqual(
            self.db.blocked_addresses(),
            {"100.64.1.7", "fd7a:115c:a1e0::47"},
        )

        state = self.db.bypass_quota_for_current_month("device", "node-42")
        self.assertTrue(state["bypassed"])
        self.assertFalse(state["blocked"])
        self.assertEqual(self.db.blocked_addresses(), set())

        self.assertTrue(self.db.delete_quota_rule("device", "node-42"))
        self.assertIsNone(
            self.db.quota_state("device", "node-42")["limit_bytes"]
        )

    def test_user_quota_blocks_every_device_for_that_user(self):
        for index in (1, 2):
            address = f"100.64.2.{index}"
            self.db.sync_peers(
                [
                    Peer(
                        ip=address,
                        family=4,
                        identity_key="user:42",
                        login_name="friend@example.com",
                        display_name="Friend",
                        device_id=f"node-{index}",
                        device_name=f"phone-{index}",
                        dns_name="",
                        os_name="ios",
                        online=True,
                        network_scope="external",
                    )
                ]
            )
            self.db.record_counters(
                [Counter(address, 4, "upload", 1, 400 * index)]
            )
        state = self.db.set_quota_rule("user", "user:42", 1_000)
        self.assertTrue(state["blocked"])
        self.assertEqual(
            self.db.blocked_addresses(),
            {"100.64.2.1", "100.64.2.2"},
        )

    def test_removed_user_rule_is_retained_but_not_effective(self):
        peer = Peer(
            ip="100.64.2.9",
            family=4,
            identity_key="user:removed-rule",
            login_name="removed-rule@example.com",
            display_name="Removed Rule",
            device_id="node-removed-rule",
            device_name="old-phone",
            dns_name="",
            os_name="ios",
            online=True,
            network_scope="external",
        )
        self.db.sync_peers([peer])
        self.db.record_counters(
            [Counter("100.64.2.9", 4, "download", 1, 1_000)]
        )
        self.db.set_quota_rule("user", "user:removed-rule", 500)
        self.assertEqual(self.db.blocked_addresses(), {"100.64.2.9"})

        self.db.sync_peers([])
        rules = self.db.quota_rules_overview()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["subtitle"], "removed-rule@example.com")
        self.assertTrue(rules[0]["target_removed"])
        self.assertTrue(rules[0]["policy"]["target_removed"])
        self.assertFalse(rules[0]["policy"]["effective"])
        self.assertFalse(rules[0]["policy"]["blocked"])
        self.assertEqual(self.db.blocked_addresses(), set())

    def test_rule_can_be_disabled_reenabled_and_deleted_as_bundle(self):
        peer = Peer(
            ip="100.64.2.10",
            family=4,
            identity_key="user:toggle-rule",
            login_name="toggle-rule@example.com",
            display_name="Toggle Rule",
            device_id="node-toggle-rule",
            device_name="phone",
            dns_name="",
            os_name="ios",
            online=True,
            network_scope="external",
        )
        self.db.sync_peers([peer])
        self.db.record_counters(
            [Counter("100.64.2.10", 4, "download", 1, 1_000)]
        )
        self.db.set_quota_rule("user", "user:toggle-rule", 500)
        self.db.set_access_block("user", "user:toggle-rule")

        disabled = self.db.set_policy_enabled(
            "user", "user:toggle-rule", False
        )
        self.assertFalse(disabled["enabled"])
        self.assertFalse(disabled["effective"])
        self.assertFalse(disabled["blocked"])
        self.assertEqual(self.db.blocked_addresses(), set())

        enabled = self.db.set_policy_enabled(
            "user", "user:toggle-rule", True
        )
        self.assertTrue(enabled["enabled"])
        self.assertTrue(enabled["effective"])
        self.assertTrue(enabled["blocked"])
        self.assertEqual(self.db.blocked_addresses(), {"100.64.2.10"})

        self.assertTrue(
            self.db.delete_policy_bundle("user", "user:toggle-rule")
        )
        self.assertEqual(self.db.quota_rules_overview(), [])
        state = self.db.quota_state("user", "user:toggle-rule")
        self.assertIsNone(state["limit_bytes"])
        self.assertFalse(state["manual_blocked"])
        self.assertTrue(state["enabled"])
        self.assertFalse(
            self.db.delete_policy_bundle("user", "user:toggle-rule")
        )

    def test_temporary_and_permanent_access_blocks(self):
        peers = [
            Peer(
                ip=ip,
                family=family,
                identity_key="user:block",
                login_name="blocked@example.com",
                display_name="Blocked User",
                device_id="node-block",
                device_name="blocked-phone",
                dns_name="",
                os_name="ios",
                online=True,
                network_scope="external",
            )
            for ip, family in [
                ("100.64.3.7", 4),
                ("fd7a:115c:a1e0::37", 6),
            ]
        ]
        self.db.sync_peers(peers)

        state = self.db.set_access_block("device", "node-block", 3600)
        self.assertTrue(state["manual_blocked"])
        self.assertEqual(state["block_mode"], "temporary")
        self.assertIsNotNone(state["block_until"])
        self.assertEqual(
            self.db.blocked_addresses(),
            {"100.64.3.7", "fd7a:115c:a1e0::37"},
        )

        with self.db.connect() as connection:
            connection.execute(
                """
                UPDATE access_blocks
                SET blocked_until = '2000-01-01T00:00:00+00:00'
                WHERE target_type = 'device' AND target_key = 'node-block'
                """
            )
        state = self.db.quota_state("device", "node-block")
        self.assertFalse(state["manual_blocked"])
        self.assertFalse(state["blocked"])
        self.assertEqual(self.db.blocked_addresses(), set())

        state = self.db.set_access_block("user", "user:block")
        self.assertTrue(state["manual_blocked"])
        self.assertEqual(state["block_mode"], "permanent")
        self.assertEqual(
            self.db.blocked_addresses(),
            {"100.64.3.7", "fd7a:115c:a1e0::37"},
        )
        self.assertTrue(self.db.delete_access_block("user", "user:block"))
        self.assertFalse(
            self.db.quota_state("user", "user:block")["manual_blocked"]
        )


class CollectorTests(unittest.TestCase):
    def test_managed_collector_reloads_interval(self):
        class FakeFirewall:
            def __init__(self, interface):
                self.interface = interface

        with tempfile.TemporaryDirectory() as temp_dir:
            db = Database(str(Path(temp_dir) / "traffic.db"))
            with patch("app.collector.Firewall", FakeFirewall):
                collector = Collector(db, object())
                collector._configure_runtime()
                self.assertEqual(collector.interval, 10)
                self.assertEqual(collector.firewall.interface, "tailscale0")
                self.assertIsNotNone(collector.website_collector)

                changed = AppConfig(
                    collect_interval=1,
                    website_retention_days=30,
                )
                db.update_app_config(changed)
                collector._configure_runtime()
                self.assertEqual(collector.interval, 1)
                self.assertEqual(collector.firewall.interface, "tailscale0")
                self.assertEqual(
                    collector.website_collector.retention_days,
                    30,
                )

    def test_hidden_shared_peer_is_discovered_with_whois(self):
        class FakeTailscale:
            def peers(self):
                return []

            def whois(self, address):
                return Peer(
                    ip=address,
                    family=4,
                    identity_key="user:shared-friend",
                    login_name="shared@example.com",
                    display_name="Shared Friend",
                    device_id="shared-node",
                    device_name="shared-phone",
                    dns_name="",
                    os_name="ios",
                    online=True,
                    network_scope="external",
                )

        class FakeFirewall:
            def __init__(self):
                self.blocked = None

            def ensure(self):
                pass

            def counters(self):
                return [Counter("100.64.2.3", 4, "download", 5, 2048)]

            def set_blocked(self, addresses):
                self.blocked = addresses

        with tempfile.TemporaryDirectory() as temp_dir:
            db = Database(str(Path(temp_dir) / "traffic.db"))
            firewall = FakeFirewall()
            collector = Collector(db, FakeTailscale(), firewall, 10)
            collector.collect()
            dashboard = db.dashboard(None, 10_000)
            self.assertEqual(dashboard["users"][0]["key"], "user:shared-friend")
            self.assertEqual(dashboard["users"][0]["download"], 2048)
            self.assertEqual(
                dashboard["users"][0]["network_scope"], "external"
            )
            self.assertEqual(firewall.blocked, set())


class FirewallParserTests(unittest.TestCase):
    def test_save_line_parser_supports_ipv4_and_ipv6(self):
        ipv4 = "add tsm_upload4 100.64.1.2 packets 12 bytes 3456"
        ipv6 = "add tsm_download6 fd7a:115c:a1e0::1 packets 7 bytes 890"
        match4 = Firewall.IPSET_LINE.search(ipv4)
        match6 = Firewall.IPSET_LINE.search(ipv6)
        self.assertIsNotNone(match4)
        self.assertIsNotNone(match6)
        self.assertEqual(match4.group("bytes"), "3456")
        self.assertEqual(match6.group("ip"), "fd7a:115c:a1e0::1")

    def test_block_set_update_uses_atomic_swap_and_ignores_public_ips(self):
        class FakeFirewall(Firewall):
            def __init__(self):
                super().__init__("tailscale0")
                self.ipset_calls = []

            def _run_ipset(self, args):
                self.ipset_calls.append(args)
                return type("Result", (), {"returncode": 0})()

        firewall = FakeFirewall()
        firewall.set_blocked(
            {"100.64.1.8", "fd7a:115c:a1e0::48", "8.8.8.8"}
        )
        add_calls = [
            call for call in firewall.ipset_calls if call[0] == "add"
        ]
        self.assertEqual(len(add_calls), 2)
        self.assertTrue(
            any(call[:3] == ["swap", "tsm_block4_next", "tsm_block4"]
                for call in firewall.ipset_calls)
        )


class WebsiteParserTests(unittest.TestCase):
    def test_vps_dns_mapping_is_available_to_other_devices(self):
        cache = DnsCache()
        cache.add(
            "100.81.5.63",
            "101.33.20.165",
            "api.bilibili.com",
            120,
        )
        self.assertEqual(
            cache.resolve("100.110.9.27", "101.33.20.165"),
            "api.bilibili.com",
        )

    def test_http_host_is_parsed_without_retaining_path(self):
        payload = (
            b"GET /video/secret-path HTTP/1.1\r\n"
            b"Host: www.bilibili.com\r\n"
            b"User-Agent: test\r\n\r\n"
        )
        self.assertEqual(parse_http_host(payload), "www.bilibili.com")

    def test_tls_client_hello_sni_is_parsed(self):
        hostname = b"www.bilibili.com"
        server_name = (
            len(hostname) + 3
        ).to_bytes(2, "big") + b"\x00" + len(hostname).to_bytes(
            2,
            "big",
        ) + hostname
        extension = (
            b"\x00\x00"
            + len(server_name).to_bytes(2, "big")
            + server_name
        )
        body = (
            b"\x03\x03"
            + bytes(32)
            + b"\x00"
            + b"\x00\x02\x13\x01"
            + b"\x01\x00"
            + len(extension).to_bytes(2, "big")
            + extension
        )
        handshake = b"\x01" + len(body).to_bytes(3, "big") + body
        record = (
            b"\x16\x03\x01"
            + len(handshake).to_bytes(2, "big")
            + handshake
        )
        self.assertEqual(parse_tls_sni(record), "www.bilibili.com")

    def test_ipv4_tcp_packet_is_parsed_for_flow_mapping(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        source = ipaddress.ip_address("100.110.9.27").packed
        destination = ipaddress.ip_address("93.184.216.34").packed
        tcp = struct.pack(
            "!HHLLBBHHH",
            51000,
            80,
            1,
            0,
            5 << 4,
            0x18,
            65535,
            0,
            0,
        )
        total_length = 20 + len(tcp) + len(payload)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            total_length,
            1,
            0,
            64,
            6,
            0,
            source,
            destination,
        )
        packet = parse_transport_packet(ip_header + tcp + payload)
        self.assertIsNotNone(packet)
        self.assertEqual(packet.flow_key, "tcp|100.110.9.27|93.184.216.34|51000|80")
        self.assertEqual(parse_http_host(packet.payload), "example.com")

    def test_conntrack_exit_flow_is_parsed(self):
        line = (
            "ipv4 2 tcp 6 431999 ESTABLISHED "
            "src=100.64.4.2 dst=93.184.216.34 sport=50000 dport=443 "
            "packets=10 bytes=1200 "
            "src=93.184.216.34 dst=203.0.113.10 sport=443 dport=50000 "
            "packets=12 bytes=4800 [ASSURED] mark=0 use=1"
        )
        flow = parse_conntrack_line(line)
        self.assertIsNotNone(flow)
        self.assertEqual(flow.device_ip, "100.64.4.2")
        self.assertEqual(flow.destination, "93.184.216.34")
        self.assertEqual(flow.upload_bytes, 1200)
        self.assertEqual(flow.download_bytes, 4800)

    def test_tailnet_to_tailnet_conntrack_flow_is_ignored(self):
        line = (
            "udp 17 20 src=100.64.4.2 dst=100.64.4.3 "
            "sport=1234 dport=5678 packets=1 bytes=80 "
            "src=100.64.4.3 dst=100.64.4.2 sport=5678 dport=1234 "
            "packets=1 bytes=80"
        )
        self.assertIsNone(parse_conntrack_line(line))

    def test_docker_dnat_conntrack_flow_is_recorded(self):
        line = (
            "ipv4 2 tcp 6 80 TIME_WAIT "
            "src=100.105.163.8 dst=100.81.5.63 "
            "sport=55551 dport=4656 packets=13 bytes=1458 "
            "src=172.20.0.2 dst=172.20.0.1 "
            "sport=8000 dport=55551 packets=14 bytes=12592 "
            "[ASSURED] mark=0 use=1"
        )
        flow = parse_conntrack_line(line)
        self.assertIsNotNone(flow)
        self.assertEqual(flow.device_ip, "100.105.163.8")
        self.assertEqual(flow.destination, "docker://100.81.5.63:4656")
        self.assertEqual(flow.upload_bytes, 1458)
        self.assertEqual(flow.download_bytes, 12592)

    def test_dns_a_response_maps_answer_to_query_name(self):
        name = b"\x07example\x03com\x00"
        payload = (
            b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            + name
            + b"\x00\x01\x00\x01"
            + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
            + b"\x5d\xb8\xd8\x22"
        )
        domain, answers = parse_dns_response(payload)
        self.assertEqual(domain, "example.com")
        self.assertEqual(answers, [("93.184.216.34", 60)])


if __name__ == "__main__":
    unittest.main()
