"""
Local network information for the current machine (interfaces, DNS, local IP).
"""

from __future__ import annotations

import logging
import re
import socket
import subprocess
import sys
from typing import Any

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore


def _local_ip_guess() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception as e:
        logger.debug("local ip guess: %s", e)
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return None


def _interfaces_psutil() -> list[dict[str, Any]]:
    if not psutil:
        return []
    rows: list[dict[str, Any]] = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, plist in addrs.items():
            fam_addrs: dict[str, str] = {}
            for a in plist:
                fam = str(a.family)
                if "AF_INET" in fam or fam == "2":
                    if a.address and not a.address.startswith("127."):
                        fam_addrs["ipv4"] = a.address
                if "AF_INET6" in fam or fam == "30":
                    if a.address and not a.address.startswith("::1"):
                        fam_addrs["ipv6"] = a.address.split("%")[0]
            up = stats.get(name)
            rows.append(
                {
                    "name": name,
                    "ipv4": fam_addrs.get("ipv4"),
                    "ipv6": fam_addrs.get("ipv6"),
                    "is_up": bool(up and up.isup) if up else None,
                }
            )
    except Exception as e:
        logger.info("psutil interfaces: %s", e)
    return rows


def _dns_windows() -> list[str]:
    servers: list[str] = []
    try:
        out = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-DnsClientServerAddress -AddressFamily IPv4 "
                "| Where-Object { $_.ServerAddresses } "
                "| Select-Object -ExpandProperty ServerAddresses",
            ],
            capture_output=True,
            text=True,
            timeout=12,
        )
        if out.returncode == 0 and out.stdout:
            for line in out.stdout.splitlines():
                line = line.strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", line):
                    servers.append(line)
    except Exception as e:
        logger.debug("dns windows: %s", e)
    return list(dict.fromkeys(servers))


def _dns_unix_resolv() -> list[str]:
    servers: list[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except Exception:
        pass
    return servers


def analyze_network() -> dict[str, Any]:
    local_ip = _local_ip_guess()
    interfaces = _interfaces_psutil()
    if sys.platform.startswith("win"):
        dns = _dns_windows()
    else:
        dns = _dns_unix_resolv()

    ipv4_iface_count = sum(1 for row in interfaces if row.get("ipv4"))

    return {
        "local_ip": local_ip,
        "dns_servers": dns,
        "interfaces": interfaces,
        "psutil_available": bool(psutil),
        "ipv4_non_loopback_interface_count": ipv4_iface_count,
    }
