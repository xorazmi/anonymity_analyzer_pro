"""
Public IP and approximate geolocation (defensive / educational).
Uses a shared Session when provided; HTTPS-first geo fallback when HTTP API fails.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)

IPIFY_URL = "https://api.ipify.org"
IPIFY_FALLBACK = "https://api64.ipify.org"
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query,mobile,proxy,hosting"
IPWHO_URL = "https://ipwho.is/{ip}"


def _session(session: requests.Session | None) -> requests.Session:
    return session if session is not None else requests.Session()


def _get_public_ip(sess: requests.Session, timeout: float) -> str | None:
    for url in (IPIFY_URL, IPIFY_FALLBACK):
        try:
            r = sess.get(url, params={"format": "json"}, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            ip = str(data.get("ip") or "").strip()
            if ip:
                return ip
        except Exception as e:
            logger.debug("ipify json %s: %s", url, e)
        try:
            r = sess.get(url, timeout=timeout)
            r.raise_for_status()
            ip = r.text.strip()
            if ip and ("." in ip or ":" in ip):
                return ip
        except Exception as e:
            logger.debug("ipify text %s: %s", url, e)
    return None


def _normalize_ipwho(data: dict[str, Any], query_ip: str) -> dict[str, Any] | None:
    if not data.get("success"):
        return None
    conn = data.get("connection") or {}
    sec = data.get("security") or {}
    return {
        "status": "success",
        "query": data.get("ip") or query_ip,
        "country": data.get("country"),
        "countryCode": data.get("country_code"),
        "regionName": data.get("region"),
        "city": data.get("city"),
        "isp": conn.get("isp"),
        "org": conn.get("org"),
        "as": None,
        "mobile": bool(data.get("mobile")),
        "proxy": bool(sec.get("proxy")),
        "hosting": bool(sec.get("hosting")),
        "_geo_source": "ipwho.is (HTTPS)",
        "_security": sec,
    }


def _fetch_geo_ip_api(sess: requests.Session, ip: str, timeout: float) -> dict[str, Any] | None:
    try:
        r = sess.get(IP_API_URL.format(ip=ip), timeout=timeout)
        r.raise_for_status()
        geo = r.json()
        if geo.get("status") == "success":
            geo["_geo_source"] = "ip-api.com (HTTP)"
            return geo
    except Exception as e:
        logger.info("ip-api failed: %s", e)
    return None


def _fetch_geo_ipwho(sess: requests.Session, ip: str, timeout: float) -> dict[str, Any] | None:
    try:
        r = sess.get(IPWHO_URL.format(ip=ip), timeout=timeout)
        r.raise_for_status()
        data = r.json()
        norm = _normalize_ipwho(data, ip)
        return norm
    except Exception as e:
        logger.info("ipwho.is failed: %s", e)
    return None


def _vpn_proxy_heuristic(geo: dict[str, Any]) -> tuple[bool, list[str]]:
    """Basic heuristic only — not proof of VPN use."""
    reasons: list[str] = []
    isp = (geo.get("isp") or "").lower()
    org = (geo.get("org") or "").lower()
    as_field = (geo.get("as") or "").lower()
    sec = geo.get("_security") or {}

    if geo.get("proxy") or sec.get("proxy"):
        reasons.append("Geo/security data marks proxy-like characteristics.")
    if geo.get("hosting") or sec.get("hosting"):
        reasons.append("Traffic appears to originate from hosting/datacenter infrastructure (often VPN/cloud).")
    if sec.get("vpn"):
        reasons.append("ipwho.is security flags suggest VPN-style routing (heuristic).")
    if sec.get("tor"):
        reasons.append("ipwho.is suggests Tor-related network path (heuristic).")

    keywords = (
        "vpn",
        "proxy",
        "hosting",
        "datacenter",
        "data center",
        "cloud",
        "colo",
        "digitalocean",
        "ovh",
        "linode",
        "vultr",
        "hetzner",
        "amazon",
        "google cloud",
        "azure",
        "mullvad",
        "nordvpn",
        "expressvpn",
        "surfshark",
        "proton",
    )
    blob = f"{isp} {org} {as_field}"
    for kw in keywords:
        if kw in blob:
            reasons.append(f"Organization/ISP text suggests anonymization or hosting infrastructure (matched: '{kw}').")
            break

    likely = bool(reasons)
    return likely, reasons


def analyze_public_ip(timeout: float = 10.0, session: requests.Session | None = None) -> dict[str, Any]:
    """
    Returns dict with keys: ok, public_ip, geo, vpn_likely, vpn_reasons, error, geo_source.
    """
    out: dict[str, Any] = {
        "ok": False,
        "public_ip": None,
        "geo": {},
        "vpn_likely": False,
        "vpn_reasons": [],
        "error": None,
        "geo_source": None,
    }
    sess = _session(session)
    ip = _get_public_ip(sess, timeout=timeout)
    if not ip:
        out["error"] = "Could not determine public IP (network or API unavailable)."
        return out

    out["public_ip"] = ip
    geo = _fetch_geo_ip_api(sess, ip, timeout=timeout)
    if not geo:
        geo = _fetch_geo_ipwho(sess, ip, timeout=timeout)

    if not geo:
        out["error"] = f"Public IP is {ip}, but geolocation failed on all providers."
        out["ok"] = True
        return out

    out["geo"] = {k: v for k, v in geo.items() if not str(k).startswith("_")}
    out["geo_source"] = geo.get("_geo_source", "unknown")

    likely, reasons = _vpn_proxy_heuristic(geo)
    out["vpn_likely"] = likely
    out["vpn_reasons"] = reasons
    out["ok"] = True
    return out
