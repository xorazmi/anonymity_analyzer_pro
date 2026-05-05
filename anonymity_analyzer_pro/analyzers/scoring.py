"""
Anonymity posture score (0–100 display): higher = stronger *relative* posture.
The model hard-caps the display and documents why literal 100% anonymity is impossible.
"""

from __future__ import annotations

from typing import Any

# No scan outcome may claim "full" anonymity — cap what the UI can show.
ABSOLUTE_DISPLAY_MAX = 82
MODEL_VERSION = "2.1-never-100"


def _level_from_score(score: int) -> str:
    if score < 35:
        return "LOW"
    if score < 70:
        return "MEDIUM"
    return "HIGH"


def _why_never_100() -> list[str]:
    return [
        "Information must leave your device to use the network — every packet carries metadata (timing, size, ordering).",
        "Accounts, payments, contracts, and support interactions create out-of-band identity that no VPN can erase.",
        "Software and hardware traits (OS build, fonts, drivers, behavior) persist across IP changes and enable statistical re-identification.",
        "Legal process, malware, misconfiguration, or insider risk can bypass any single privacy tool you trust today.",
        "Even Tor/VPN only shift trust — you still trust implementations, operators, and the mathematics within known limits.",
        "This score is a teaching model, not a guarantee: it cannot certify you against an adaptive adversary.",
    ]


def compute_anonymity_score(
    ip_result: dict[str, Any],
    system: dict[str, Any],
    network: dict[str, Any],
    tor_vpn: dict[str, Any],
    leaks: dict[str, Any],
    fingerprint_meta: dict[str, Any],
) -> dict[str, Any]:
    """
    Weighted heuristic with a hard ceiling so the UI never implies perfect anonymity.
    Calibrated so typical systems land in LOW–MEDIUM while Tor/VPN can reach HIGH under the cap.
    """
    score = 74.0
    factors: list[str] = []

    # Irreducible reality (the cap + narrative carry the "never 100%" lesson, not a pegged-zero score).
    score -= 4
    factors.append("Irreducible exposure: networked computers always emit some observable metadata.")

    geo = ip_result.get("geo") or {}
    city = (geo.get("city") or "").strip()
    if ip_result.get("public_ip"):
        score -= 5
        factors.append("Public IP is visible to services you use (unless split routing is perfect everywhere).")
    if city:
        score -= 3
        factors.append("Geolocation often reaches city-level — enough for many investigative and commercial use cases.")

    uniq = int((fingerprint_meta or {}).get("uniqueness_score") or 0)
    score -= min(14, uniq * 0.16)
    if uniq >= 55:
        factors.append("Stable system + ambient attributes are numerous — correlation across sessions is realistic.")

    codes = set(leaks.get("issue_codes") or [])
    if "dns_plain" in codes or "dns_unknown" in codes:
        score -= 4
        factors.append("DNS path is a metadata channel; mis-tunneled DNS is a classic real-world deanonymizer.")
    if "dns_tunnel_mismatch_risk" in codes:
        score -= 3
        factors.append("DNS may not follow the same path as traffic — a subtle but common configuration failure.")

    if "interface_surface" in codes:
        score -= 2
        factors.append("Multiple IPv4 interfaces increase the chance of split routing or accidental bypass.")

    if "ambient_locale_tz" in codes:
        score -= 2
        factors.append("Locale/timezone are ambient correlators for websites and native apps alike.")

    if geo.get("mobile"):
        score -= 2
        factors.append("Cellular paths often have different logging/retention properties than fixed broadband.")

    tor = tor_vpn.get("tor") or {}
    if tor.get("checked") and tor.get("is_tor"):
        score += 17
        factors.append("Tor Project check suggests Tor-like exit path for this app's traffic (+).")

    if tor_vpn.get("vpn_likely"):
        score += 11
        factors.append("Heuristics suggest VPN/hosting/proxy-style routing may be in use (+).")

    score = max(22.0, min(88.0, score))

    int_score = int(round(score))
    int_score = min(int_score, ABSOLUTE_DISPLAY_MAX)

    impossibility = (
        "100% anonymity is not a meaningful engineering target: residual signals, humans, and jurisdiction always remain. "
        f"This app caps the displayed score at {ABSOLUTE_DISPLAY_MAX}% to reinforce that limit."
    )

    return {
        "score": int_score,
        "level": _level_from_score(int_score),
        "raw_score_before_display_cap": round(score, 2),
        "display_ceiling": ABSOLUTE_DISPLAY_MAX,
        "true_100_possible": False,
        "factors": factors,
        "why_never_100": _why_never_100(),
        "impossibility_statement": impossibility,
        "model_version": MODEL_VERSION,
        "capped_note": "Display score is capped; 'perfect anonymity' is intentionally not representable.",
    }
