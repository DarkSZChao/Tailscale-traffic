from __future__ import annotations

import tempfile
import unittest
from datetime import date
from pathlib import Path

from app.collector import Collector
from app.database import Database
from app.firewall import Counter, Firewall
from app.tailscale import Peer, TailscaleClient
from app.windows_capture import counter_from_capture_frame


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


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.temp_dir.name) / "traffic.db"))

    def tearDown(self):
        self.temp_dir.cleanup()

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
        ]
        self.db.sync_peers(peers)
        self.db.record_counters(
            [
                Counter("100.64.1.5", 4, "upload", 1, 100),
                Counter("100.64.1.6", 4, "download", 1, 300),
            ]
        )
        dashboard = self.db.dashboard(None, 10_000)
        self.assertEqual(dashboard["summary"]["tailnet_total"], 100)
        self.assertEqual(dashboard["summary"]["external_total"], 300)
        scopes = {user["key"]: user["network_scope"] for user in dashboard["users"]}
        self.assertEqual(scopes["user:tailnet"], "tailnet")
        self.assertEqual(scopes["user:external"], "external")

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


class CollectorTests(unittest.TestCase):
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


class WindowsCaptureParserTests(unittest.TestCase):
    @staticmethod
    def ipv4_frame(source: str, destination: str, length: int = 120) -> bytes:
        packet = bytearray(length)
        packet[0] = 0x45
        packet[2:4] = length.to_bytes(2, "big")
        packet[12:16] = __import__("ipaddress").ip_address(source).packed
        packet[16:20] = __import__("ipaddress").ip_address(destination).packed
        return b"\x00\x00\x00\x00" + packet

    def test_exit_upload_and_download_are_counted(self):
        upload = counter_from_capture_frame(
            self.ipv4_frame("100.64.1.2", "8.8.8.8")
        )
        download = counter_from_capture_frame(
            self.ipv4_frame("8.8.8.8", "100.64.1.2", 240)
        )
        self.assertIsNotNone(upload)
        self.assertEqual(upload.direction, "upload")
        self.assertEqual(upload.bytes, 120)
        self.assertIsNotNone(download)
        self.assertEqual(download.direction, "download")
        self.assertEqual(download.bytes, 240)

    def test_tailnet_peer_traffic_is_ignored(self):
        counter = counter_from_capture_frame(
            self.ipv4_frame("100.64.1.2", "100.64.1.3")
        )
        self.assertIsNone(counter)

    def test_local_exit_node_address_is_ignored(self):
        counter = counter_from_capture_frame(
            self.ipv4_frame("100.64.1.2", "8.8.8.8"),
            frozenset({"100.64.1.2"}),
        )
        self.assertIsNone(counter)


if __name__ == "__main__":
    unittest.main()
