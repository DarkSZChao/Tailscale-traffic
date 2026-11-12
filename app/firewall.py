from __future__ import annotations

import ipaddress
import re
import shlex
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

                set_direction = "src" if direction == "upload" else "dst"
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

            self._ensure_forward_jumps(family)

    def _ensure_forward_jumps(self, family: int) -> None:
        """Keep accounting ahead of Tailscale's ACCEPT rules.

        tailscaled can rebuild its ``ts-forward`` jump after this process has
        started.  Merely checking that our jumps exist is insufficient: an
        earlier ACCEPT in ``ts-forward`` bypasses accounting. Rewrite our two
        jumps only when they are no longer the first handlers.
        """
        desired = [
            ["-o", self.interface, "-j", self.CHAINS["download"]],
            ["-i", self.interface, "-j", self.CHAINS["upload"]],
        ]
        result = self._run(family, ["-t", "filter", "-S", "FORWARD"])
        forward_rules: list[list[str]] = []
        for line in result.stdout.splitlines():
            try:
                parts = shlex.split(line)
            except ValueError:
                continue
            if parts[:2] == ["-A", "FORWARD"]:
                forward_rules.append(parts[2:])
        if forward_rules[: len(desired)] == desired:
            return

        # Delete the exact legacy jumps once, then insert in reverse order at
        # position one so the final order matches ``desired``.
        for rule in desired:
            self._run(
                family,
                ["-t", "filter", "-D", "FORWARD", *rule],
                check=False,
            )
        for rule in reversed(desired):
            self._run(
                family,
                ["-t", "filter", "-I", "FORWARD", "1", *rule],
            )

    def remove_legacy_blocks(self) -> None:
        """Retire the old ipset filters after the independent nft table is ready."""
        for family in (4, 6):
            for direction, chain in self.CHAINS.items():
                side = "src" if direction == "upload" else "dst"
                rule = ["-m", "set", "--match-set", f"tsm_block{family}", side, "-j", "DROP"]
                lines = self._run(family, ["-S", chain]).stdout.splitlines()
                for line in lines:
                    if line == " ".join(["-A", chain, *rule]):
                        self._run(family, ["-D", chain, *rule])

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
