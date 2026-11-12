from __future__ import annotations

import argparse
import ipaddress
import logging
from pathlib import Path
import signal
import subprocess
from threading import Event
import time

from .config import CONFIG_PATH, DATABASE_PATH, TAILSCALE_INTERFACE
from .database import Database

TABLE = "tsm_shared_block"
READY = Path("/run/tsm-blocker-ready")
INTERVAL = 5
RECHECK_INTERVAL = 60
TAILSCALE_NETWORKS = {
    4: ipaddress.ip_network("100.64.0.0/10"),
    6: ipaddress.ip_network("fd7a:115c:a1e0::/48"),
}
logger = logging.getLogger(__name__)


def tailscale_addresses(addresses: set[str]) -> frozenset:
    selected = set()
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address not in TAILSCALE_NETWORKS[address.version] or getattr(address, "scope_id", None):
            continue
        selected.add(address)
    return frozenset(selected)


def nft_transaction(addresses: frozenset) -> str:
    # Add is idempotent; the delete and replacement are part of the same batch.
    # A failed batch leaves the previous table intact.
    lines = [f"add table inet {TABLE}", f"delete table inet {TABLE}", f"table inet {TABLE} {{"]
    for family, address_type in ((4, "ipv4_addr"), (6, "ipv6_addr")):
        elements = ", ".join(str(ip) for ip in sorted(ip for ip in addresses if ip.version == family))
        lines.append(f"    set blocked{family} {{")
        lines.append(f"        type {address_type};")
        if elements:
            lines.append(f"        elements = {{ {elements} }};")
        lines.append("    }")
    lines.extend((
        "    chain forward {",
        "        type filter hook forward priority -10; policy accept;",
        f'        iifname "{TAILSCALE_INTERFACE}" ip saddr @blocked4 counter drop',
        f'        oifname "{TAILSCALE_INTERFACE}" ip daddr @blocked4 counter drop',
        f'        iifname "{TAILSCALE_INTERFACE}" ip6 saddr @blocked6 counter drop',
        f'        oifname "{TAILSCALE_INTERFACE}" ip6 daddr @blocked6 counter drop',
        "    }",
        "}",
    ))
    return "\n".join(lines) + "\n"


def run_command(args: list[str], *, input: str | None = None, check: bool = True):
    result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=12)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]}: {result.stderr.strip()}")
    return result


def table_exists() -> bool:
    return run_command(["nft", "list", "table", "inet", TABLE], check=False).returncode == 0


class Blocker:
    def __init__(self):
        self.applied: frozenset | None = None
        self.recheck_at = 0.0

    def sync(self, addresses: set[str]) -> None:
        desired = tailscale_addresses(addresses)
        now = time.monotonic()
        needs_update = desired != self.applied
        if not needs_update and now >= self.recheck_at:
            needs_update = not table_exists()
            self.recheck_at = now + RECHECK_INTERVAL
        if needs_update:
            run_command(["nft", "-f", "-"], input=nft_transaction(desired))
            self.applied = desired
            self.recheck_at = now + RECHECK_INTERVAL
            logger.info("封禁名单已更新：%d 个 Tailscale 地址", len(desired))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args()
    if args.healthcheck:
        try:
            return int(time.time() - READY.stat().st_mtime > 3 * INTERVAL or not table_exists())
        except OSError:
            return 1

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    READY.unlink(missing_ok=True)
    stop = Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    blocker = Blocker()
    last_error = ""
    while not stop.is_set():
        try:
            # Re-read the project's timezone; no schema changes or policy writes.
            database = Database(DATABASE_PATH, CONFIG_PATH, read_only=True)
            blocker.sync(database.blocked_addresses())
            READY.touch()
            if last_error:
                logger.info("封禁同步已恢复")
            last_error = ""
        except Exception as exc:
            # Keep the last successfully installed table on DB or nft failure.
            if str(exc) != last_error:
                logger.exception("封禁同步失败，保留已生效的名单")
            last_error = str(exc)
        stop.wait(INTERVAL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
