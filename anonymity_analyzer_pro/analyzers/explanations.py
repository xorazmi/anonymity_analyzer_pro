"""
Explanation engine: maps detected signals to educational text.
"""

from __future__ import annotations

from typing import Any

EXPLANATIONS: dict[str, dict[str, str]] = {
    "never_full_anonymity": {
        "title": "Why '100% anonymity' is not a coherent promise",
        "what": "Anonymity is not a single switch; it is reduced uncertainty about who did what, under assumptions that always have exceptions.",
        "why": "Residual data (timing, device traits, accounts, mistakes, legal process) survives even strong network-layer tools.",
        "real_world": "Investigations routinely combine many weak clues; no consumer tool advertises immunity because it would be false.",
    },
    "public_ip_visible": {
        "title": "Public IP visibility",
        "what": "Websites and APIs see an address that identifies your connection on the Internet.",
        "why": "That address is logged, sold in threat feeds, and can be combined with accounts or timestamps.",
        "real_world": "A forum admin, game server, or compromised site can store the IP you used when visiting.",
    },
    "dns_plain": {
        "title": "DNS resolver visibility",
        "what": "Your device asks a DNS server to translate domain names to IP addresses.",
        "why": "The resolver (or anyone on the path) can observe which domains you looked up unless DNS is inside the tunnel.",
        "real_world": "ISP or resolver logs have been used in civil and criminal cases to reconstruct activity patterns.",
    },
    "dns_unknown": {
        "title": "DNS configuration unclear",
        "what": "This tool could not reliably list your DNS servers.",
        "why": "Misconfigured VPNs sometimes send DNS outside the tunnel, a classic 'DNS leak' scenario.",
        "real_world": "Leak tests in the browser remain important; desktop tools cannot see every browser path.",
    },
    "dns_tunnel_mismatch_risk": {
        "title": "Possible DNS / tunnel path mismatch",
        "what": "Public resolvers (8.8.8.8, 1.1.1.1, etc.) are visible while anonymization heuristics also triggered.",
        "why": "If DNS does not follow the same encrypted path as web traffic, metadata can leave the tunnel.",
        "real_world": "Many 'VPN leak' stories are DNS or IPv6 split-routing — not Hollywood hacking, just configuration.",
    },
    "webrtc_browser_note": {
        "title": "WebRTC in the browser",
        "what": "WebRTC can reveal local and sometimes public addresses to JavaScript on web pages.",
        "why": "This desktop app cannot execute inside your browser; WebRTC behavior is separate from Python.",
        "real_world": "Use reputable browser leak tests and disable WebRTC if your threat model requires it.",
    },
    "fingerprint_unique": {
        "title": "System fingerprint surface",
        "what": "OS version, hostname, username, and hardware-derived constants distinguish this machine.",
        "why": "Even if IP changes, the same fingerprint can re-identify a user across sessions.",
        "real_world": "Large sites build statistical models from many small signals — not only cookies.",
    },
    "ambient_locale_tz": {
        "title": "Locale and timezone ambient signals",
        "what": "Your OS exposes language/region defaults and local time offset to programs — and often to remote servers.",
        "why": "These fields narrow the set of plausible users even when IP is shared or tunneled.",
        "real_world": "Ad tech and fraud systems routinely log language and coarse time signals alongside IP.",
    },
    "interface_surface": {
        "title": "Multiple active network interfaces",
        "what": "Several IPv4 interfaces can exist (Wi‑Fi, Ethernet, VPN virtual adapter, VM bridge).",
        "why": "Each path is a potential source of different routing, DNS, or IPv6 behavior — leaks are often mechanical, not magical.",
        "real_world": "Corporate laptops with always-on VPN plus Wi‑Fi are a frequent source of split-tunnel surprises.",
    },
    "vpn_heuristic": {
        "title": "VPN / hosting heuristic",
        "what": "Geolocation databases sometimes label ranges as hosting, proxy, or VPN-related.",
        "why": "This is probabilistic; false positives and negatives exist.",
        "real_world": "Streaming providers and fraud systems use similar signals — not court-grade proof.",
    },
    "tor_detected": {
        "title": "Tor-like path (for this check)",
        "what": "Tor Project's API indicated this application's outbound connection resembles Tor.",
        "why": "Tor helps network anonymity but does not erase application fingerprints or unsafe habits.",
        "real_world": "Logging into personal accounts over Tor can undo anonymity for that activity.",
    },
    "no_tor_no_vpn": {
        "title": "No strong tunnel signals",
        "what": "We did not detect Tor for this check, and VPN-style routing was not strongly suggested.",
        "why": "Your public IP likely reflects your ISP or organization directly.",
        "real_world": "Geo-IP databases often place residential users within a region or city.",
    },
}


def build_issue_explanations(
    ip_result: dict[str, Any],
    system: dict[str, Any],
    leaks: dict[str, Any],
    tor_vpn: dict[str, Any],
    fingerprint_meta: dict[str, Any],
) -> list[dict[str, str]]:
    """Ordered list of explanation dicts for the UI."""
    items: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(code: str) -> None:
        if code in seen:
            return
        seen.add(code)
        block = EXPLANATIONS.get(code)
        if block:
            items.append({"code": code, **block})

    add("never_full_anonymity")

    for code in leaks.get("issue_codes") or []:
        add(code)

    if int((fingerprint_meta or {}).get("uniqueness_score") or 0) >= 55:
        add("fingerprint_unique")

    if tor_vpn.get("vpn_likely"):
        add("vpn_heuristic")

    tor = tor_vpn.get("tor") or {}
    if tor.get("checked") and tor.get("is_tor"):
        add("tor_detected")
    elif tor.get("checked") and not tor.get("is_tor") and not tor_vpn.get("vpn_likely"):
        add("no_tor_no_vpn")

    if ip_result.get("public_ip"):
        add("public_ip_visible")

    add("webrtc_browser_note")

    return items


def _norm(s: str) -> str:
    return " ".join(s.lower().split())


def _too_similar(candidate: str, existing: list[str]) -> bool:
    """Drop bullets that repeat the same idea as an earlier line (simple substring heuristic)."""
    c = _norm(candidate)
    if len(c) < 24:
        return False
    for e in existing:
        n = _norm(e)
        if len(n) < 24:
            continue
        if c in n or n in c:
            return True
        # Shared long prefix = likely duplicate theme
        if c[:70] == n[:70]:
            return True
    return False


def build_warning_bullets(
    explanations: list[dict[str, str]],
    score_block: dict[str, Any],
) -> list[str]:
    """
    Short summary for the warning panel. Full teaching text stays in Explanation engine + export JSON.
    """
    bullets: list[str] = []
    imp = score_block.get("impossibility_statement")
    if imp:
        bullets.append(imp)

    # One compact line from the deeper list (rest is in score JSON / explanations UI).
    why_all = score_block.get("why_never_100") or []
    if why_all:
        bullets.append(why_all[0])

    # Issue-linked explanations only (skip global essay + webrtc note here — still in Explanation panel).
    skip_codes = {"never_full_anonymity", "webrtc_browser_note"}
    for ex in explanations:
        code = ex.get("code", "")
        if code in skip_codes:
            continue
        t = ex.get("title") or ""
        w = (ex.get("why") or "").strip()
        if not t or not w:
            continue
        if len(w) > 140:
            w = w[:137] + "…"
        line = f"{t}: {w}"
        if _too_similar(line, bullets):
            continue
        bullets.append(line)
        if len(bullets) >= 9:
            break

    bullets.append("Details: see “Explanation engine” below; export JSON for the full factor list.")
    return bullets
