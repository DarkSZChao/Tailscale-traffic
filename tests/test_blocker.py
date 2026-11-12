from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from app.blocker import Blocker, nft_transaction, tailscale_addresses
from app.database import Database
from app.tailscale import Peer


class BlockerTests(unittest.TestCase):
    def test_read_only_policy_excludes_unverified_devices_of_same_user(self):
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / "traffic.db")
            db = Database(path)
            shared = Peer("100.64.1.2", 4, "user:test", "", "", "node-shared", "", "", "", True,
                          network_scope="external", sharee_node=True)
            other = replace(shared, ip="100.64.1.3", device_id="node-other", sharee_node=False)
            db.sync_peers([shared, other])
            db.set_access_block("user", shared.identity_key)
            db.set_access_block("device", other.device_id)
            reader = Database(path, read_only=True)
            self.assertEqual(reader.blocked_addresses(), {shared.ip})
            self.assertFalse(db.quota_state("device", other.device_id)["blocked"])
            # A hidden shared device still needs WhoIs refresh while blocked.
            self.assertIn(shared.ip, db.whois_candidates([], {other.ip}))
            db.sync_peers([other])
            self.assertEqual(reader.blocked_addresses(), set())

    def test_public_and_docker_addresses_never_enter_the_table(self):
        addresses = {"100.64.1.2", "fd7a:115c:a1e0::3", "8.8.8.8", "172.18.0.2", "bad"}
        rules = nft_transaction(tailscale_addresses(addresses))
        for value in ("100.64.1.2", "fd7a:115c:a1e0::3"):
            self.assertIn(value, rules)
        for value in ("8.8.8.8", "172.18.0.2", "bad", "hook input"):
            self.assertNotIn(value, rules)
        self.assertIn("hook forward priority -10", rules)

    @patch("app.blocker.run_command")
    def test_failed_update_keeps_previous_state_and_can_retry(self, command):
        blocker = Blocker()
        original = {"100.64.1.2"}
        blocker.sync(original)
        blocker.sync(original)
        self.assertEqual(command.call_count, 1)
        command.side_effect = RuntimeError("invalid batch")
        with self.assertRaises(RuntimeError):
            blocker.sync(set())
        self.assertEqual(blocker.applied, tailscale_addresses(original))
        command.side_effect = None
        blocker.sync(set())
        self.assertEqual(blocker.applied, frozenset())
