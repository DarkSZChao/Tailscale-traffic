from __future__ import annotations

import http.client
import ipaddress
import json
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode


@dataclass(frozen=True)
class Peer:
    ip: str
    family: int
    identity_key: str
    login_name: str
    display_name: str
    device_id: str
    device_name: str
    dns_name: str
    os_name: str
    online: bool
    network_scope: str = "tailnet"
    expired: bool = False


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 5):
        super().__init__("local-tailscaled.sock", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class TailscaleClient:
    def __init__(self, socket_path: str):
        self.socket_path = socket_path

    def _get(self, path: str) -> dict[str, Any]:
        connection = UnixHTTPConnection(self.socket_path)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read()
            if response.status != 200:
                raise RuntimeError(
                    f"Tailscale LocalAPI 返回 HTTP {response.status}: "
                    f"{body[:200].decode(errors='replace')}"
                )
            return json.loads(body)
        finally:
            connection.close()

    def status(self) -> dict[str, Any]:
        return self._get("/localapi/v0/status")

    @staticmethod
    def _device_name(
        hostname: object,
        dns_name: object,
        computed_name: object,
        fallback: object,
    ) -> str:
        hostname_text = str(hostname or "").rstrip(".")
        dns_text = str(dns_name or "").rstrip(".")
        if hostname_text.lower() in {"localhost", "localhost.localdomain"}:
            hostname_text = ""
        if hostname_text:
            return hostname_text
        if dns_text:
            return dns_text.split(".", 1)[0]
        return str(computed_name or fallback).rstrip(".")

    @classmethod
    def peers_from_status(
        cls,
        status: dict[str, Any],
        *,
        include_self: bool = False,
    ) -> list[Peer]:
        users = status.get("User") or {}
        result: list[Peer] = []
        devices = list((status.get("Peer") or {}).items())
        if include_self and status.get("Self"):
            devices.append(("self", status["Self"]))

        for device_id, raw in devices:
            if raw.get("InNetworkMap") is False:
                continue
            user_id = str(raw.get("UserID") or "")
            user = users.get(user_id) or {}
            login_name = str(user.get("LoginName") or "")
            device_name = cls._device_name(
                raw.get("HostName"),
                raw.get("DNSName"),
                "",
                device_id,
            )
            display_name = str(
                user.get("DisplayName") or login_name or device_name
            )
            identity_key = (
                f"user:{user_id}"
                if user_id and user_id != "0"
                else f"device:{device_id}"
            )
            network_scope = (
                "external" if bool(raw.get("ShareeNode")) else "tailnet"
            )

            for ip_text in raw.get("TailscaleIPs") or []:
                try:
                    ip = ipaddress.ip_address(ip_text)
                except ValueError:
                    continue
                result.append(
                    Peer(
                        ip=str(ip),
                        family=ip.version,
                        identity_key=identity_key,
                        login_name=login_name,
                        display_name=display_name,
                        device_id=str(raw.get("ID") or device_id),
                        device_name=device_name,
                        dns_name=str(raw.get("DNSName") or ""),
                        os_name=str(raw.get("OS") or ""),
                        online=bool(raw.get("Online")),
                        network_scope=network_scope,
                        expired=bool(raw.get("Expired")),
                    )
                )
        return result

    def peers(self) -> list[Peer]:
        return self.peers_from_status(self.status())

    def whois(self, ip_text: str) -> Peer:
        ip = ipaddress.ip_address(ip_text)
        address = f"[{ip}]:1" if ip.version == 6 else f"{ip}:1"
        payload = self._get(f"/localapi/v0/whois?{urlencode({'addr': address})}")
        return self._peer_from_whois(ip, payload)

    @staticmethod
    def _peer_from_whois(
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        payload: dict[str, Any],
    ) -> Peer:
        node = payload.get("Node") or {}
        user = payload.get("UserProfile") or {}
        user_id = str(user.get("ID") or "")
        node_id = str(node.get("StableID") or node.get("ID") or ip)
        hostinfo = node.get("Hostinfo") or {}
        login_name = str(user.get("LoginName") or "")
        device_name = TailscaleClient._device_name(
            hostinfo.get("Hostname"),
            node.get("Name"),
            node.get("ComputedName"),
            ip,
        )
        display_name = str(
            user.get("DisplayName") or login_name or device_name
        )
        identity_key = (
            f"user:{user_id}"
            if user_id and user_id != "0"
            else f"device:{node_id}"
        )
        return Peer(
            ip=str(ip),
            family=ip.version,
            identity_key=identity_key,
            login_name=login_name,
            display_name=display_name,
            device_id=node_id,
            device_name=device_name,
            dns_name=str(node.get("Name") or "").rstrip("."),
            os_name=str(hostinfo.get("OS") or ""),
            online=True,
            network_scope="external",
            expired=bool(node.get("Expired")),
        )
