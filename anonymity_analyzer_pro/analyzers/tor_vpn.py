"""
Basic Tor exit check and VPN heuristics (read-only, educational).
Tor Project endpoint is sometimes slow; we use connect/read split timeouts and one retry.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests
from requests.exceptions import ReadTimeout, Timeout

logger = logging.getLogger(__name__)

TOR_CHECK_URL = "https://check.torproject.org/api/ip"
# (connect seconds, read seconds) — read often dominates for this host
TOR_DEFAULT_TIMEOUT = (12.0, 35.0)


def _sess(session: requests.Session | None) -> requests.Session:
    return session if session is not None else requests.Session()


def check_tor_exit(
    public_ip: str | None,
    timeout: float | tuple[float, float] = TOR_DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """
    Tor Project reports whether *this connection* appears to use Tor (source IP of this request).
    """
    sess = _sess(session)
    out: dict[str, Any] = {"checked": False, "is_tor": False, "raw": None, "error": None, "reported_ip": None}
    if isinstance(timeout, (int, float)):
        req_timeout: float | tuple[float, float] = (min(12.0, float(timeout)), float(timeout))
    else:
        req_timeout = timeout

    last_err: Exception | None = None
    for attempt in range(2):
        try:
            r = sess.get(TOR_CHECK_URL, timeout=req_timeout)
            r.raise_for_status()
            data = r.json()
            out["raw"] = data
            out["is_tor"] = bool(data.get("IsTor"))
            out["reported_ip"] = data.get("IP")
            out["checked"] = True
            if public_ip and out["reported_ip"] and str(out["reported_ip"]).strip() != str(public_ip).strip():
                out["note"] = "Tor check IP differs from ipify result — possible split routing or proxy timing."
            return out
        except (ReadTimeout, Timeout) as e:
            last_err = e
            logger.info("tor check timeout attempt %s: %s", attempt + 1, e)
            if attempt == 0:
                time.sleep(0.6)
                continue
        except Exception as e:
            last_err = e
            logger.info("tor check failed: %s", e)
            break

    out["error"] = str(last_err) if last_err else "Tor check failed."
    if last_err and isinstance(last_err, (ReadTimeout, Timeout)):
        out["hint"] = "Tor Project server was slow or unreachable — try Re-scan, or allow HTTPS to check.torproject.org through firewall/VPN."
    return out


def analyze_tor_and_vpn(
    ip_result: dict[str, Any],
    timeout: float | tuple[float, float] = TOR_DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    public_ip = ip_result.get("public_ip")
    tor = check_tor_exit(public_ip, timeout=timeout, session=session)
    return {
        "tor": tor,
        "vpn_likely": bool(ip_result.get("vpn_likely")),
        "vpn_reasons": list(ip_result.get("vpn_reasons") or []),
    }
