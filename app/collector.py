from __future__ import annotations

import logging
from threading import Event
from typing import TYPE_CHECKING

from .config import AppConfig, TAILSCALE_INTERFACE
from .database import Database
from .firewall import Firewall
from .tailscale import TailscaleClient

if TYPE_CHECKING:
    from .website_collector import WebsiteCollector

logger = logging.getLogger(__name__)


class Collector:
    mode = "linux-firewall"

    def __init__(
        self,
        database: Database,
        tailscale: TailscaleClient,
        firewall: Firewall | None = None,
        interval: int | None = None,
        website_collector: WebsiteCollector | None = None,
    ):
        self.database = database
        self.tailscale = tailscale
        self._managed_runtime = firewall is None
        initial_config = database.get_app_config()
        self.firewall = firewall or Firewall(TAILSCALE_INTERFACE)
        self.interval = interval or initial_config.collect_interval
        self.website_collector = website_collector
        self._runtime_config: AppConfig | None = (
            None if self._managed_runtime else initial_config
        )
        self._running = False
        self.last_error = ""
        self.last_success: str | None = None
        self._stop = Event()

    def run_forever(self) -> None:
        self._running = True
        self._configure_runtime()
        if self.website_collector and not self._managed_runtime:
            self.website_collector.start()
        try:
            self._loop()
        finally:
            if self.website_collector:
                self.website_collector.stop()
            self._running = False

    def stop(self) -> None:
        self._stop.set()

    def collect(self) -> None:
        self._configure_runtime()
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
        if self.website_collector:
            try:
                self.website_collector.collect()
            except Exception as exc:
                self.database.update_website_status(True, str(exc))
                logger.exception("采集网站流量失败")
        self.apply_policies()
        self.last_success = self.database._now()
        self.last_error = ""
        self.database.update_collector_status(self.mode, self.interval)

    def _configure_runtime(self) -> None:
        if not self._managed_runtime:
            return
        config = self.database.get_app_config()
        self.interval = config.collect_interval

        if self.website_collector is None:
            from .website_collector import WebsiteCollector

            self.website_collector = WebsiteCollector(
                self.database,
                TAILSCALE_INTERFACE,
                config.website_retention_days,
            )
            if self._running:
                self.website_collector.start()
        elif self.website_collector:
            self.website_collector.retention_days = (
                config.website_retention_days
            )

        self._runtime_config = config

    def apply_policies(self) -> None:
        self.firewall.set_blocked(self.database.blocked_addresses())

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.collect()
            except Exception as exc:
                self.last_error = str(exc)
                try:
                    self.database.update_collector_status(
                        self.mode,
                        self.interval,
                        self.last_error,
                    )
                except Exception:
                    logger.exception("保存采集器状态失败")
                logger.exception("采集流量失败")
            self._stop.wait(self.interval)
