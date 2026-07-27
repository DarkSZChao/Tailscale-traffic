from __future__ import annotations

import ipaddress
import logging
import struct
import subprocess
import sys
import threading
from datetime import datetime
from typing import BinaryIO, Iterator

from .database import Database
from .firewall import Counter
from .tailscale import TailscaleCliClient

logger = logging.getLogger(__name__)

TAILSCALE_NETWORKS = {
    4: ipaddress.ip_network("100.64.0.0/10"),
    6: ipaddress.ip_network("fd7a:115c:a1e0::/48"),
}
PCAP_USER0 = 147


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def counter_from_capture_frame(
    frame: bytes,
    excluded_ips: frozenset[str] = frozenset(),
) -> Counter | None:
    """Convert a Tailscale USER0 capture frame into exit-node usage."""
    if len(frame) < 5:
        return None

    packet = frame[4:]
    family = packet[0] >> 4
    if family == 4:
        if len(packet) < 20:
            return None
        source = ipaddress.ip_address(packet[12:16])
        destination = ipaddress.ip_address(packet[16:20])
        byte_count = int.from_bytes(packet[2:4], "big")
        if byte_count < 20:
            return None
    elif family == 6:
        if len(packet) < 40:
            return None
        source = ipaddress.ip_address(packet[8:24])
        destination = ipaddress.ip_address(packet[24:40])
        byte_count = 40 + int.from_bytes(packet[4:6], "big")
    else:
        return None

    source_is_tailscale = source in TAILSCALE_NETWORKS[family]
    destination_is_tailscale = destination in TAILSCALE_NETWORKS[family]
    if source_is_tailscale and not destination_is_tailscale:
        address, direction = source, "upload"
    elif destination_is_tailscale and not source_is_tailscale:
        address, direction = destination, "download"
    else:
        return None

    if str(address) in excluded_ips:
        return None

    return Counter(
        ip=str(address),
        family=family,
        direction=direction,
        packets=1,
        bytes=byte_count,
    )


def iter_pcap_frames(stream: BinaryIO) -> Iterator[bytes]:
    header = _read_exact(stream, 24)
    if len(header) != 24:
        raise RuntimeError("Tailscale 抓包流缺少 PCAP 文件头")

    magic = header[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        endian = "<"
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        endian = ">"
    else:
        raise RuntimeError("Tailscale 抓包流不是受支持的 PCAP 格式")

    link_type = struct.unpack(f"{endian}I", header[20:24])[0]
    if link_type != PCAP_USER0:
        raise RuntimeError(f"不支持的 Tailscale 抓包链路类型: {link_type}")

    while True:
        record_header = _read_exact(stream, 16)
        if not record_header:
            return
        if len(record_header) != 16:
            raise RuntimeError("PCAP 数据记录头不完整")
        captured_length = struct.unpack(
            f"{endian}IIII", record_header
        )[2]
        frame = _read_exact(stream, captured_length)
        if len(frame) != captured_length:
            raise RuntimeError("PCAP 数据记录不完整")
        yield frame


class WindowsCaptureCollector:
    mode = "windows-capture"
    supports_enforcement = False

    def __init__(
        self,
        database: Database,
        tailscale: TailscaleCliClient,
        interval: int,
        executable: str = "tailscale",
    ):
        self.database = database
        self.tailscale = tailscale
        self.interval = interval
        self.executable = executable
        self.last_error = ""
        self.last_success: str | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._local_ips: frozenset[str] = frozenset()
        self._totals: dict[tuple[str, int, str], list[int]] = {}
        self._process: subprocess.Popen[bytes] | None = None
        self._reader_thread: threading.Thread | None = None
        self._collector_thread: threading.Thread | None = None

    def start(self) -> None:
        try:
            status = self.tailscale.status()
            self._local_ips = self.tailscale.local_ips_from_status(status)
            self.database.sync_peers(
                self.tailscale.peers_from_status(status, include_self=True)
            )
        except Exception as exc:
            self.last_error = f"无法读取本机 Tailscale 状态: {exc}"
            return

        creation_flags = (
            subprocess.CREATE_NO_WINDOW
            if sys.platform == "win32"
            else 0
        )
        try:
            self._process = subprocess.Popen(
                [self.executable, "debug", "capture", "--o", "-"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                creationflags=creation_flags,
            )
        except OSError as exc:
            self.last_error = f"无法启动 Tailscale 抓包: {exc}"
            return

        self._reader_thread = threading.Thread(
            target=self._read_capture,
            name="tailscale-capture-reader",
            daemon=True,
        )
        self._collector_thread = threading.Thread(
            target=self._collect_loop,
            name="traffic-collector",
            daemon=True,
        )
        self._reader_thread.start()
        self._collector_thread.start()

    def stop(self) -> None:
        self._stop.set()
        process = self._process
        if process and process.poll() is None:
            process.terminate()
        if self._reader_thread:
            self._reader_thread.join(timeout=5)
        try:
            self.collect()
        except Exception:
            logger.exception("保存最后一批 Windows 流量失败")
        if self._collector_thread:
            self._collector_thread.join(timeout=5)

    def _read_capture(self) -> None:
        process = self._process
        if not process or not process.stdout:
            return
        try:
            for frame in iter_pcap_frames(process.stdout):
                if self._stop.is_set():
                    return
                counter = counter_from_capture_frame(frame, self._local_ips)
                if not counter:
                    continue
                key = (counter.ip, counter.family, counter.direction)
                with self._lock:
                    total = self._totals.setdefault(key, [0, 0])
                    total[0] += counter.packets
                    total[1] += counter.bytes
        except Exception as exc:
            if not self._stop.is_set():
                self.last_error = str(exc)
                logger.exception("Windows Tailscale 抓包失败")
        finally:
            if not self._stop.is_set() and process.poll() is not None:
                message = ""
                if process.stderr:
                    message = process.stderr.read().decode(
                        "utf-8", errors="replace"
                    ).strip()
                self.last_error = message or "Tailscale 抓包进程已退出"

    def _snapshot(self) -> list[Counter]:
        with self._lock:
            return [
                Counter(
                    ip=ip,
                    family=family,
                    direction=direction,
                    packets=totals[0],
                    bytes=totals[1],
                )
                for (ip, family, direction), totals in self._totals.items()
            ]

    def collect(self) -> None:
        status = self.tailscale.status()
        self._local_ips = self.tailscale.local_ips_from_status(status)
        peers = self.tailscale.peers_from_status(status, include_self=True)
        counters = self._snapshot()
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
        self.last_success = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )
        if self._process and self._process.poll() is None:
            self.last_error = ""

    def apply_policies(self) -> None:
        # Windows 出口节点使用 userspace 转发，无法复用 Linux ipset 封锁。
        return

    def _collect_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.collect()
            except Exception as exc:
                self.last_error = str(exc)
                logger.exception("采集 Windows 流量失败")
            self._stop.wait(self.interval)
