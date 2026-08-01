from __future__ import annotations

import ctypes
import ipaddress
import logging
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass

from .database import Database

logger = logging.getLogger(__name__)

TAILSCALE_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),
)
MAX_CACHE_ENTRIES = 50_000


@dataclass(frozen=True)
class WebsiteFlow:
    flow_key: str
    device_ip: str
    destination: str
    upload_bytes: int
    download_bytes: int


@dataclass(frozen=True)
class TransportPacket:
    source: str
    destination: str
    protocol: str
    source_port: int
    destination_port: int
    payload: bytes

    @property
    def flow_key(self) -> str:
        return "|".join(
            (
                self.protocol,
                self.source,
                self.destination,
                str(self.source_port),
                str(self.destination_port),
            )
        )


def _is_tailscale(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    network = (
        TAILSCALE_NETWORKS[0]
        if ip.version == 4
        else TAILSCALE_NETWORKS[1]
    )
    return ip in network


def _host_port(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    port: str,
) -> str:
    host = f"[{ip}]" if ip.version == 6 else str(ip)
    return f"{host}:{port}"


def parse_conntrack_line(line: str) -> WebsiteFlow | None:
    parts = line.split()
    protocol = next(
        (part for part in parts[:4] if part in {"tcp", "udp"}),
        None,
    )
    if not protocol:
        return None
    tuples: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key == "src" and "src" in current:
            tuples.append(current)
            current = {}
        if key in {"src", "dst", "sport", "dport", "packets", "bytes"}:
            current[key] = value
    if current:
        tuples.append(current)
    if len(tuples) < 2:
        return None
    original, reply = tuples[:2]
    required = {"src", "dst", "sport", "dport", "bytes"}
    if not required.issubset(original) or "bytes" not in reply:
        return None
    try:
        source = ipaddress.ip_address(original["src"])
        destination = ipaddress.ip_address(original["dst"])
        reply_source = ipaddress.ip_address(reply.get("src", ""))
        upload = int(original["bytes"])
        download = int(reply["bytes"])
    except (ValueError, KeyError):
        return None
    if not _is_tailscale(source) or original["dport"] == "53":
        return None
    docker_dnat = bool(
        (reply_source != destination or reply.get("sport") != original["dport"])
        and not _is_tailscale(reply_source)
        and not reply_source.is_global
    )
    if docker_dnat:
        destination_label = (
            f"docker://{_host_port(destination, original['dport'])}"
        )
    elif _is_tailscale(destination) or not destination.is_global:
        return None
    else:
        destination_label = str(destination)
    flow_key = "|".join(
        (
            protocol,
            str(source),
            str(destination),
            original["sport"],
            original["dport"],
        )
    )
    return WebsiteFlow(
        flow_key=flow_key,
        device_ip=str(source),
        destination=destination_label,
        upload_bytes=upload,
        download_bytes=download,
    )


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    end_offset: int | None = None
    visited: set[int] = set()
    while offset < len(data):
        if offset in visited:
            raise ValueError("DNS 名称压缩指针循环")
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            return ".".join(labels), end_offset or offset
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("DNS 名称压缩指针不完整")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if end_offset is None:
                end_offset = offset + 2
            offset = pointer
            continue
        if length & 0xC0 or offset + 1 + length > len(data):
            raise ValueError("DNS 名称标签无效")
        offset += 1
        labels.append(
            data[offset : offset + length].decode("ascii", errors="ignore")
        )
        offset += length
    raise ValueError("DNS 名称越界")


def parse_dns_response(payload: bytes) -> tuple[str, list[tuple[str, int]]]:
    if len(payload) < 12:
        return "", []
    _identifier, flags, questions, answers = struct.unpack("!HHHH", payload[:8])
    if not flags & 0x8000 or not questions:
        return "", []
    offset = 12
    query_name = ""
    try:
        for index in range(questions):
            name, offset = _decode_dns_name(payload, offset)
            if offset + 4 > len(payload):
                return "", []
            offset += 4
            if index == 0:
                query_name = name.lower().rstrip(".")

        resolved: list[tuple[str, int]] = []
        for _ in range(answers):
            _name, offset = _decode_dns_name(payload, offset)
            if offset + 10 > len(payload):
                break
            record_type, record_class, ttl, size = struct.unpack(
                "!HHIH", payload[offset : offset + 10]
            )
            offset += 10
            value = payload[offset : offset + size]
            offset += size
            if record_class != 1:
                continue
            if record_type == 1 and len(value) == 4:
                resolved.append((str(ipaddress.ip_address(value)), ttl))
            elif record_type == 28 and len(value) == 16:
                resolved.append((str(ipaddress.ip_address(value)), ttl))
        return query_name, resolved
    except (UnicodeError, ValueError):
        return "", []


def _network_offset(frame: bytes) -> int | None:
    if frame and frame[0] >> 4 in {4, 6}:
        return 0
    if len(frame) > 4 and frame[4] >> 4 in {4, 6}:
        return 4
    if len(frame) >= 14 and frame[12:14] in {b"\x08\x00", b"\x86\xdd"}:
        return 14
    if len(frame) >= 16 and frame[14:16] in {b"\x08\x00", b"\x86\xdd"}:
        return 16
    if len(frame) >= 20 and frame[:2] in {b"\x08\x00", b"\x86\xdd"}:
        return 20
    return None


def parse_transport_packet(frame: bytes) -> TransportPacket | None:
    ip_offset = _network_offset(frame)
    if ip_offset is None or len(frame) <= ip_offset:
        return None
    version = frame[ip_offset] >> 4
    if version == 4:
        if len(frame) < ip_offset + 20:
            return None
        header_size = (frame[ip_offset] & 0x0F) * 4
        if header_size < 20:
            return None
        fragment = int.from_bytes(
            frame[ip_offset + 6 : ip_offset + 8],
            "big",
        )
        if fragment & 0x1FFF:
            return None
        protocol_number = frame[ip_offset + 9]
        source = str(
            ipaddress.ip_address(frame[ip_offset + 12 : ip_offset + 16])
        )
        destination = str(
            ipaddress.ip_address(frame[ip_offset + 16 : ip_offset + 20])
        )
        transport_offset = ip_offset + header_size
    elif version == 6:
        if len(frame) < ip_offset + 40:
            return None
        protocol_number = frame[ip_offset + 6]
        source = str(
            ipaddress.ip_address(frame[ip_offset + 8 : ip_offset + 24])
        )
        destination = str(
            ipaddress.ip_address(frame[ip_offset + 24 : ip_offset + 40])
        )
        transport_offset = ip_offset + 40
    else:
        return None

    if protocol_number not in {6, 17} or len(frame) < transport_offset + 8:
        return None
    source_port = int.from_bytes(
        frame[transport_offset : transport_offset + 2],
        "big",
    )
    destination_port = int.from_bytes(
        frame[transport_offset + 2 : transport_offset + 4],
        "big",
    )
    if protocol_number == 17:
        payload_offset = transport_offset + 8
        protocol = "udp"
    else:
        if len(frame) < transport_offset + 20:
            return None
        tcp_header_size = (frame[transport_offset + 12] >> 4) * 4
        if tcp_header_size < 20:
            return None
        payload_offset = transport_offset + tcp_header_size
        protocol = "tcp"
    if payload_offset > len(frame):
        return None
    return TransportPacket(
        source=source,
        destination=destination,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        payload=frame[payload_offset:],
    )


def _udp_dns_packet(frame: bytes) -> tuple[str, bytes] | None:
    packet = parse_transport_packet(frame)
    if not packet or packet.protocol != "udp" or packet.source_port != 53:
        return None
    try:
        destination = ipaddress.ip_address(packet.destination)
    except ValueError:
        return None
    if not _is_tailscale(destination):
        return None
    return packet.destination, packet.payload


def _normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if domain.startswith("[") and "]" in domain:
        domain = domain[1 : domain.index("]")]
    elif domain.count(":") == 1:
        domain = domain.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(domain)
        return ""
    except ValueError:
        pass
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if (
        not domain
        or len(domain) > 253
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            for label in domain.split(".")
        )
        or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-."
            for character in domain
        )
    ):
        return ""
    return domain


def parse_http_host(payload: bytes) -> str:
    if not payload or len(payload) > 65_535:
        return ""
    first_line, separator, remainder = payload.partition(b"\r\n")
    if not separator:
        return ""
    method = first_line.split(b" ", 1)[0].upper()
    if method not in {
        b"GET",
        b"POST",
        b"PUT",
        b"PATCH",
        b"DELETE",
        b"HEAD",
        b"OPTIONS",
        b"CONNECT",
        b"TRACE",
        b"PRI",
    }:
        return ""
    for line in remainder[:16_384].split(b"\r\n"):
        name, separator, value = line.partition(b":")
        if separator and name.strip().lower() == b"host":
            return _normalize_domain(
                value.strip().decode("ascii", errors="ignore")
            )
    return ""


def parse_tls_sni(payload: bytes) -> str:
    if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x01:
        return ""
    record_end = 5 + int.from_bytes(payload[3:5], "big")
    handshake_end = 9 + int.from_bytes(payload[6:9], "big")
    limit = min(len(payload), record_end, handshake_end)
    offset = 9
    if offset + 34 > limit:
        return ""
    offset += 34
    if offset >= limit:
        return ""
    session_size = payload[offset]
    offset += 1 + session_size
    if offset + 2 > limit:
        return ""
    cipher_size = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 2 + cipher_size
    if offset >= limit:
        return ""
    compression_size = payload[offset]
    offset += 1 + compression_size
    if offset + 2 > limit:
        return ""
    extensions_size = int.from_bytes(payload[offset : offset + 2], "big")
    offset += 2
    extensions_end = min(limit, offset + extensions_size)
    while offset + 4 <= extensions_end:
        extension_type = int.from_bytes(payload[offset : offset + 2], "big")
        extension_size = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        offset += 4
        extension_end = offset + extension_size
        if extension_end > extensions_end:
            return ""
        if extension_type == 0 and extension_size >= 5:
            name_offset = offset + 2
            while name_offset + 3 <= extension_end:
                name_type = payload[name_offset]
                name_size = int.from_bytes(
                    payload[name_offset + 1 : name_offset + 3],
                    "big",
                )
                name_offset += 3
                if name_offset + name_size > extension_end:
                    return ""
                if name_type == 0:
                    return _normalize_domain(
                        payload[name_offset : name_offset + name_size].decode(
                            "ascii",
                            errors="ignore",
                        )
                    )
                name_offset += name_size
        offset = extension_end
    return ""


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filters", ctypes.POINTER(_SockFilter)),
    ]


def _capture_filter() -> list[tuple[int, int, int, int]]:
    ld = 0x00
    ldx = 0x01
    st = 0x02
    alu = 0x04
    jmp = 0x05
    ret = 0x06
    misc = 0x07
    byte = 0x10
    half = 0x08
    absolute = 0x20
    indirect = 0x40
    memory = 0x60
    msh = 0xA0
    immediate = 0x00
    jeq = 0x10
    ja = 0x00
    and_op = 0x50
    rsh = 0x70
    add = 0x00
    x_source = 0x08
    tax = 0x00
    txa = 0x80

    items: list[tuple] = []
    labels: dict[str, int] = {}

    def mark(name: str) -> None:
        labels[name] = len(items)

    def statement(code: int, value: int = 0) -> None:
        items.append(("statement", code, value))

    def branch(code: int, value: int, yes: str, no: str) -> None:
        items.append(("branch", code, value, yes, no))

    def jump(target: str) -> None:
        items.append(("jump", jmp | ja, target))

    def payload_checks(prefix: str, indirect_load: bool) -> None:
        load_code = ld | byte | (indirect if indirect_load else absolute)
        value = 0 if indirect_load else 0
        mark(f"{prefix}_tls_payload")
        statement(load_code, value)
        branch(jmp | jeq, 0x16, "accept", "reject")

        mark(f"{prefix}_http_payload")
        statement(load_code, value)
        for index, character in enumerate((b"GPDHOCT")):
            next_label = f"{prefix}_http_{index + 1}"
            branch(
                jmp | jeq,
                character,
                "accept",
                next_label if index < 6 else "reject",
            )
            if index < 6:
                mark(next_label)

    statement(ld | byte | absolute, 0)
    statement(alu | and_op, 0xF0)
    branch(jmp | jeq, 0x40, "ipv4", "check_ipv6")
    mark("check_ipv6")
    branch(jmp | jeq, 0x60, "ipv6", "reject")

    mark("ipv4")
    statement(ld | byte | absolute, 9)
    branch(jmp | jeq, 17, "ipv4_udp", "ipv4_tcp_protocol")
    mark("ipv4_tcp_protocol")
    branch(jmp | jeq, 6, "ipv4_tcp", "reject")

    mark("ipv4_udp")
    statement(ldx | byte | msh, 0)
    statement(ld | half | indirect, 0)
    branch(jmp | jeq, 53, "accept", "reject")

    mark("ipv4_tcp")
    statement(ldx | byte | msh, 0)
    statement(misc | txa)
    statement(st, 0)
    statement(ld | half | indirect, 2)
    branch(jmp | jeq, 443, "ipv4_tls_offset", "ipv4_http_port")
    mark("ipv4_http_port")
    branch(jmp | jeq, 80, "ipv4_http_offset", "reject")

    mark("ipv4_tls_offset")
    statement(ld | byte | indirect, 12)
    statement(alu | rsh, 2)
    statement(st, 1)
    statement(ld | memory, 0)
    statement(ldx | memory, 1)
    statement(alu | add | x_source)
    statement(misc | tax)
    jump("ipv4_tls_payload")

    mark("ipv4_http_offset")
    statement(ld | byte | indirect, 12)
    statement(alu | rsh, 2)
    statement(st, 1)
    statement(ld | memory, 0)
    statement(ldx | memory, 1)
    statement(alu | add | x_source)
    statement(misc | tax)
    jump("ipv4_http_payload")

    payload_checks("ipv4", True)

    mark("ipv6")
    statement(ld | byte | absolute, 6)
    branch(jmp | jeq, 17, "ipv6_udp", "ipv6_tcp_protocol")
    mark("ipv6_tcp_protocol")
    branch(jmp | jeq, 6, "ipv6_tcp", "reject")

    mark("ipv6_udp")
    statement(ld | half | absolute, 40)
    branch(jmp | jeq, 53, "accept", "reject")

    mark("ipv6_tcp")
    statement(ld | half | absolute, 42)
    branch(jmp | jeq, 443, "ipv6_tls_offset", "ipv6_http_port")
    mark("ipv6_http_port")
    branch(jmp | jeq, 80, "ipv6_http_offset", "reject")

    mark("ipv6_tls_offset")
    statement(ld | byte | absolute, 52)
    statement(alu | rsh, 2)
    statement(alu | add, 40)
    statement(misc | tax)
    jump("ipv6_tls_payload")

    mark("ipv6_http_offset")
    statement(ld | byte | absolute, 52)
    statement(alu | rsh, 2)
    statement(alu | add, 40)
    statement(misc | tax)
    jump("ipv6_http_payload")

    payload_checks("ipv6", True)

    mark("accept")
    statement(ret, 65_535)
    mark("reject")
    statement(ret, 0)

    program: list[tuple[int, int, int, int]] = []
    for index, item in enumerate(items):
        if item[0] == "statement":
            _kind, code, value = item
            program.append((code, 0, 0, value))
        elif item[0] == "jump":
            _kind, code, target = item
            offset = labels[target] - index - 1
            program.append((code, 0, 0, offset))
        else:
            _kind, code, value, yes, no = item
            yes_offset = labels[yes] - index - 1
            no_offset = labels[no] - index - 1
            if not 0 <= yes_offset <= 255 or not 0 <= no_offset <= 255:
                raise ValueError("抓包过滤器跳转超出范围")
            program.append((code, yes_offset, no_offset, value))
    return program


def attach_capture_filter(capture: socket.socket) -> None:
    filter_items = _capture_filter()
    instructions = (_SockFilter * len(filter_items))(
        *(_SockFilter(*item) for item in filter_items)
    )
    program = _SockFprog(len(instructions), instructions)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.setsockopt(
        capture.fileno(),
        socket.SOL_SOCKET,
        getattr(socket, "SO_ATTACH_FILTER", 26),
        ctypes.byref(program),
        ctypes.sizeof(program),
    )
    if result != 0:
        raise OSError(ctypes.get_errno(), "无法附加内核抓包过滤器")


class DnsCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._values: dict[tuple[str, str], tuple[str, float]] = {}
        self._global_values: dict[str, tuple[str, float]] = {}

    @staticmethod
    def _trim(values: dict) -> None:
        while len(values) > MAX_CACHE_ENTRIES:
            values.pop(next(iter(values)))

    def add(
        self,
        device_ip: str,
        destination_ip: str,
        domain: str,
        ttl: int,
    ) -> None:
        domain = _normalize_domain(domain)
        if not domain or domain.endswith(".arpa"):
            return
        now = time.monotonic()
        expires = now + min(86_400, max(30, ttl))
        global_expires = now + min(300, max(30, ttl))
        key = (device_ip, destination_ip)
        with self._lock:
            self._values.pop(key, None)
            self._values[key] = (domain, expires)
            self._global_values.pop(destination_ip, None)
            self._global_values[destination_ip] = (domain, global_expires)
            self._trim(self._values)
            self._trim(self._global_values)

    def resolve(self, device_ip: str, destination_ip: str) -> str:
        now = time.monotonic()
        key = (device_ip, destination_ip)
        with self._lock:
            value = self._values.get(key)
            if value and value[1] >= now:
                return value[0]
            if value:
                self._values.pop(key, None)
            global_value = self._global_values.get(destination_ip)
            if global_value and global_value[1] >= now:
                return global_value[0]
            if global_value:
                self._global_values.pop(destination_ip, None)
        return destination_ip

    def prune(self) -> None:
        now = time.monotonic()
        with self._lock:
            for values in (self._values, self._global_values):
                expired = [
                    key
                    for key, (_domain, expires) in values.items()
                    if expires < now
                ]
                for key in expired:
                    values.pop(key, None)


class FlowDomainCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._values: dict[str, tuple[str, float]] = {}

    def add(self, flow_key: str, domain: str) -> None:
        domain = _normalize_domain(domain)
        if not domain:
            return
        with self._lock:
            self._values.pop(flow_key, None)
            self._values[flow_key] = (
                domain,
                time.monotonic() + 172_800,
            )
            while len(self._values) > MAX_CACHE_ENTRIES:
                self._values.pop(next(iter(self._values)))

    def resolve(self, flow_key: str) -> str | None:
        with self._lock:
            value = self._values.get(flow_key)
            if not value:
                return None
            if value[1] < time.monotonic():
                self._values.pop(flow_key, None)
                return None
            return value[0]

    def prune(self) -> None:
        now = time.monotonic()
        with self._lock:
            expired = [
                key
                for key, (_domain, expires) in self._values.items()
                if expires < now
            ]
            for key in expired:
                self._values.pop(key, None)


class WebsiteCollector:
    def __init__(
        self,
        database: Database,
        interface: str,
        retention_days: int,
    ):
        self.database = database
        self.interface = interface
        self.retention_days = retention_days
        self.dns_cache = DnsCache()
        self.flow_domains = FlowDomainCache()
        self.last_error = ""
        self._stop = threading.Event()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._capture_metadata,
            name="website-metadata-capture",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._socket:
            self._socket.close()
        if self._thread:
            self._thread.join(timeout=3)

    def _capture_metadata(self) -> None:
        try:
            capture = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_DGRAM,
                socket.htons(0x0003),
            )
            capture.bind((self.interface, 0))
            capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1_048_576)
            attach_capture_filter(capture)
            capture.settimeout(1)
            self._socket = capture
            while not self._stop.is_set():
                try:
                    frame = capture.recv(65_535)
                except TimeoutError:
                    continue
                packet = parse_transport_packet(frame)
                if not packet:
                    continue
                if packet.protocol == "udp" and packet.source_port == 53:
                    domain, answers = parse_dns_response(packet.payload)
                    for destination_ip, ttl in answers:
                        self.dns_cache.add(
                            packet.destination,
                            destination_ip,
                            domain,
                            ttl,
                        )
                    continue
                if (
                    packet.protocol != "tcp"
                    or packet.destination_port not in {80, 443}
                ):
                    continue
                try:
                    source = ipaddress.ip_address(packet.source)
                    destination = ipaddress.ip_address(packet.destination)
                except ValueError:
                    continue
                if (
                    not _is_tailscale(source)
                    or _is_tailscale(destination)
                    or not destination.is_global
                ):
                    continue
                domain = (
                    parse_tls_sni(packet.payload)
                    if packet.destination_port == 443
                    else parse_http_host(packet.payload)
                )
                if domain:
                    self.flow_domains.add(packet.flow_key, domain)
        except OSError as exc:
            if not self._stop.is_set():
                self.last_error = (
                    "网站元数据抓取不可用，将只显示目标 IP："
                    f"{exc}"
                )
                logger.warning(self.last_error)

    @staticmethod
    def _conntrack_lines() -> list[str]:
        try:
            result = subprocess.run(
                ["conntrack", "-L", "-o", "extended"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"无法读取 conntrack：{exc}") from exc
        if result.returncode:
            message = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(f"conntrack 读取失败：{message}")
        return result.stdout.splitlines()

    def collect(self) -> None:
        self.dns_cache.prune()
        self.flow_domains.prune()
        flows = []
        missing_accounting = False
        for line in self._conntrack_lines():
            if (
                "bytes=" not in line
                and (
                    "src=100." in line
                    or "src=fd7a:115c:a1e0:" in line.lower()
                )
            ):
                missing_accounting = True
            flow = parse_conntrack_line(line)
            if not flow:
                continue
            destination = self.flow_domains.resolve(flow.flow_key)
            if not destination:
                destination = self.dns_cache.resolve(
                    flow.device_ip,
                    flow.destination,
                )
            flows.append(
                {
                    "flow_key": flow.flow_key,
                    "device_ip": flow.device_ip,
                    "destination": destination,
                    "upload_bytes": flow.upload_bytes,
                    "download_bytes": flow.download_bytes,
                }
            )
        if missing_accounting:
            raise RuntimeError(
                "conntrack 未提供字节计数，请启用 "
                "net.netfilter.nf_conntrack_acct=1"
            )
        self.database.record_website_flows(flows)
        self.database.cleanup_website_history(self.retention_days)
        self.database.update_website_status(True, self.last_error)
