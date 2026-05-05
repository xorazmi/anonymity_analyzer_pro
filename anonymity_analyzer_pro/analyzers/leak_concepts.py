"""
Conceptual leak assessment (DNS path, WebRTC education, ambient signals) — no surveillance of others.
"""

from __future__ import annotations

from typing import Any


def assess_leaks(
    network: dict[str, Any],
    ip_result: dict[str, Any],
    tor_vpn: dict[str, Any],
    system: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Heuristic flags for educational display. Not a substitute for in-browser leak tests.
    """
    issues: list[str] = []
    notes: list[str] = []
    system = system or {}

    dns = network.get("dns_servers") or []
    if not dns:
        issues.append("dns_unknown")
        notes.append("DNS resolver list could not be read; misconfigured DNS can still leak browsing context to resolvers.")
    else:
        isp_like = True
        if tor_vpn.get("vpn_likely") or (tor_vpn.get("tor") or {}).get("is_tor"):
            isp_like = False
        public_resolvers = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"}
        hit_public = [d for d in dns if d in public_resolvers]
        if hit_public and not isp_like:
            issues.append("dns_tunnel_mismatch_risk")
            notes.append("Tunnel/anonymizer may be active, but DNS still targets well-known public resolvers — confirm DNS is inside the tunnel.")
        if hit_public and isp_like:
            issues.append("dns_plain")
            notes.append("Public DNS resolvers see domain lookups; combined with other signals this reduces privacy.")

    if ip_result.get("public_ip"):
        issues.append("public_ip_visible")
        notes.append("Any remote server you contact can see a public IP unless routed through a privacy tool.")

    # WebRTC: cannot inspect browser from this app
    issues.append("webrtc_browser_note")

    # Multiple routable interfaces increase correlation surface (VM, VPN adapter, Wi‑Fi, etc.)
    n_if = int(network.get("ipv4_non_loopback_interface_count") or 0)
    if n_if >= 3:
        issues.append("interface_surface")
        notes.append("Several active IPv4 interfaces were seen — extra paths (VPN adapters, VMs, tethering) can complicate leak behavior.")

    # Ambient signals always exist on a normal OS
    if system.get("default_locale") or system.get("timezone_offset_minutes") is not None:
        issues.append("ambient_locale_tz")
        notes.append("Locale and timezone are exposed to local software and frequently to remote sites (headers, JS) — useful for narrowing identity.")

    return {
        "issue_codes": list(dict.fromkeys(issues)),
        "notes": notes,
        "dns_servers": dns,
    }
