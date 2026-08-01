from __future__ import annotations

import argparse
import logging
import signal

from .collector import Collector
from .config import CONFIG_PATH, DATABASE_PATH, TAILSCALE_SOCKET
from .database import Database
from .tailscale import TailscaleClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def create_collector() -> Collector:
    database = Database(DATABASE_PATH, CONFIG_PATH)
    return Collector(
        database,
        TailscaleClient(TAILSCALE_SOCKET),
    )


def healthcheck() -> int:
    status = Database(DATABASE_PATH, CONFIG_PATH).collector_status()
    if status["healthy"]:
        return 0
    logger.error(status["error"])
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args()
    if args.healthcheck:
        return healthcheck()

    collector = create_collector()

    def stop_collector(_signum, _frame) -> None:
        collector.stop()

    signal.signal(signal.SIGTERM, stop_collector)
    signal.signal(signal.SIGINT, stop_collector)
    collector.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
