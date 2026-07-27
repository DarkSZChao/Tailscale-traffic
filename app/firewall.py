from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class Counter:
    ip: str
    family: int
    direction: str
    packets: int
    bytes: int


class FirewallError(RuntimeError):
    pass


class Firewall:
    CHAINS = {"upload": "TSM_UPLOAD", "download": "TSM_DOWNLOAD"}
    SETS = {
        (4, "upload"): "tsm_upload4",
        (4, "download"): "tsm_download4",
        (6, "upload"): "tsm_upload6",
        (6, "download"): "tsm_download6",
    }
    BLOCK_SETS = {4: "tsm_block4", 6: "tsm_block6"}
    BLOCK_STAGING_SETS = {4: "tsm_block4_next", 6: "tsm_block6_next"}
    TAILSCALE_RANGES = {4: "100.64.0.0/10", 6: "fd7a:115c:a1e0::/48"}
    IPSET_LINE = re.compile(
        r"^add\s+(?P<set>\S+)\s+(?P<ip>\S+).*?"
        r"\bpackets\s+(?P<packets>\d+)\s+bytes\s+(?P<bytes>\d+)"
    )

    def __init__(self, interface: str):
        self.interface = interface

    @staticmethod
    def _binary(family: int, suffix: str = "") -> str:
        prefix = "ip6tables" if family == 6 else "iptables"
        return f"{prefix}{suffix}"

    def _run(
        self, family: int, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        command = [self._binary(family), "-w", "5", *args]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallError(f"无法执行 {command[0]}: {exc}") from exc
        if check and result.returncode:
            message = result.stderr.strip() or result.stdout.strip()
            raise FirewallError(f"{' '.join(command)} 失败: {message}")
        return result

    @staticmethod
    def _run_ipset(args: list[str]) -> subprocess.CompletedProcess[str]:
        command = ["ipset", *args]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallError(f"无法执行 ipset: {exc}") from exc
        if result.returncode:
            message = result.stderr.strip() or result.stdout.strip()
            raise FirewallError(f"{' '.join(command)} 失败: {message}")
        return result

    def ensure(self) -> None:
        for family in (4, 6):
            set_family = "inet6" if family == 6 else "inet"
            for set_name in (
                self.BLOCK_SETS[family],
                self.BLOCK_STAGING_SETS[family],
            ):
                self._run_ipset(
                    [
                        "create",
                        set_name,
                        "hash:ip",
                        "family",
                        set_family,
                        "-exist",
                    ]
                )

            for direction, chain in self.CHAINS.items():
                set_name = self.SETS[(family, direction)]
                self._run_ipset(
                    [
                        "create",
                        set_name,
                        "hash:ip",
                        "family",
                        set_family,
                        "counters",
                        "-exist",
                    ]
                )

                if self._run(family, ["-t", "filter", "-N", chain], check=False).returncode:
                    exists = self._run(
                        family, ["-t", "filter", "-L", chain], check=False
                    )
                    if exists.returncode:
                        raise FirewallError(f"无法创建防火墙计数链 {chain}")

                interface_flag = "-i" if direction == "upload" else "-o"
                jump = [
                    "-t",
                    "filter",
                    "-C",
                    "FORWARD",
                    interface_flag,
                    self.interface,
                    "-j",
                    chain,
                ]
                if self._run(family, jump, check=False).returncode:
                    self._run(
                        family,
                        [
                            "-t",
                            "filter",
                            "-I",
                            "FORWARD",
                            "1",
                            interface_flag,
                            self.interface,
                            "-j",
                            chain,
                        ],
                    )

                set_direction = "src" if direction == "upload" else "dst"
                block_rule = [
                    "-t",
                    "filter",
                    "-C",
                    chain,
                    "-m",
                    "set",
                    "--match-set",
                    self.BLOCK_SETS[family],
                    set_direction,
                    "-j",
                    "DROP",
                ]
                if self._run(family, block_rule, check=False).returncode:
                    self._run(
                        family,
                        [
                            "-t",
                            "filter",
                            "-I",
                            chain,
                            "1",
                            "-m",
                            "set",
                            "--match-set",
                            self.BLOCK_SETS[family],
                            set_direction,
                            "-j",
                            "DROP",
                        ],
                    )

                match_flag = "-s" if direction == "upload" else "-d"
                discover_rule = [
                    "-t",
                    "filter",
                    "-C",
                    chain,
                    match_flag,
                    self.TAILSCALE_RANGES[family],
                    "-j",
                    "SET",
                    "--add-set",
                    set_name,
                    set_direction,
                ]
                if self._run(family, discover_rule, check=False).returncode:
                    self._run(
                        family,
                        [
                            "-t",
                            "filter",
                            "-A",
                            chain,
                            match_flag,
                            self.TAILSCALE_RANGES[family],
                            "-j",
                            "SET",
                            "--add-set",
                            set_name,
                            set_direction,
                        ],
                    )

                counter_rule = [
                    "-t",
                    "filter",
                    "-C",
                    chain,
                    "-m",
                    "set",
                    "--match-set",
                    set_name,
                    set_direction,
                    "-j",
                    "RETURN",
                ]
                if self._run(family, counter_rule, check=False).returncode:
                    self._run(
                        family,
                        [
                            "-t",
                            "filter",
                            "-A",
                            chain,
                            "-m",
                            "set",
                            "--match-set",
                            set_name,
                            set_direction,
                            "-j",
                            "RETURN",
                        ],
                    )

    def counters(self) -> list[Counter]:
        counters: list[Counter] = []
        for (family, direction), set_name in self.SETS.items():
            result = self._run_ipset(["save", set_name])
            for line in result.stdout.splitlines():
                match = self.IPSET_LINE.search(line)
                if not match:
                    continue
                counters.append(
                    Counter(
                        ip=str(ipaddress.ip_address(match.group("ip"))),
                        family=family,
                        direction=direction,
                        packets=int(match.group("packets")),
                        bytes=int(match.group("bytes")),
                    )
                )
        return counters

    def set_blocked(self, addresses: set[str]) -> None:
        grouped: dict[int, list[str]] = {4: [], 6: []}
        for address in sorted(addresses):
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if ip not in ipaddress.ip_network(self.TAILSCALE_RANGES[ip.version]):
                continue
            grouped[ip.version].append(str(ip))

        for family in (4, 6):
            staging = self.BLOCK_STAGING_SETS[family]
            active = self.BLOCK_SETS[family]
            self._run_ipset(["flush", staging])
            for address in grouped[family]:
                self._run_ipset(["add", staging, address, "-exist"])
            self._run_ipset(["swap", staging, active])
            self._run_ipset(["flush", staging])
