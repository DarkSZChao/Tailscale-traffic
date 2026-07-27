from __future__ import annotations

import logging
import threading
from datetime import datetime

from .database import Database
from .firewall import Firewall
from .tailscale import TailscaleClient

logger = logging.getLogger(__name__)


class Collector:
    mode = "linux-firewall"
    supports_enforcement = True

    def __init__(
        self,
        database: Database,
        tailscale: TailscaleClient,
        firewall: Firewall,
        interval: int,
    ):
        self.database = database
        self.tailscale = tailscale
        self.firewall = firewall
        self.interval = interval
        self.last_error = ""
        self.last_success: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name="traffic-collector", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def collect(self) -> None:
        peers = self.tailscale.peers()
        self.firewall.ensure()
        counters = self.firewall.counters()
        unresolved = self.database.unresolved_addresses(
            counter.ip for counter in counters
        )
        for address in unresolved:
            try:
                peers.append(self.tailscale.whois(address))
            except Exception as exc:
                logger.warning("无法识别 Tailscale 地址 %s: %s", address, exc)
        self.database.sync_peers(peers)
        self.database.record_counters(counters)
        self.apply_policies()
        self.last_success = datetime.now().astimezone().isoformat(timespec="seconds")
        self.last_error = ""

    def apply_policies(self) -> None:
        self.firewall.set_blocked(self.database.blocked_addresses())

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.collect()
            except Exception as exc:
                self.last_error = str(exc)
                logger.exception("采集流量失败")
            self._stop.wait(self.interval)
