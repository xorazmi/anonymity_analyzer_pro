"""
Optimized scan orchestration: parallel independent probes, shared HTTP session, timings.
Educational / local system only.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .explanations import build_issue_explanations, build_warning_bullets
from .ip_analyzer import analyze_public_ip
from .leak_concepts import assess_leaks
from .network_analyzer import analyze_network
from .scoring import compute_anonymity_score
from .system_analyzer import analyze_system, fingerprint_uniqueness_estimate
from .tor_vpn import analyze_tor_and_vpn


def _build_session() -> requests.Session:
    """Pooled connections + single retry for flaky Wi‑Fi / captive portals."""
    s = requests.Session()
    s.headers.update({"User-Agent": "AnonymityAnalyzerPro/1.1 (educational; local self-scan)"})
    retry = Retry(total=1, connect=1, read=1, backoff_factor=0.2, status_forcelist=(502, 503, 504))
    adapter = HTTPAdapter(max_retries=retry, pool_connections=8, pool_maxsize=8)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def run_full_scan(
    timeout: float = 12.0,
    step_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """
    Run all analyzers with minimal wall-clock time:
    Phase A (parallel): public IP + geo, system fingerprint, network snapshot.
    Phase B: Tor/VPN (needs live request, uses same session where applicable).
    Phase C: leak model + scoring + explanations (CPU-only).
    """
    timings: dict[str, int] = {}
    timeline: list[str] = []

    def step(msg: str) -> None:
        timeline.append(f"[{time.strftime('%H:%M:%S')}] {msg}")
        if step_callback:
            step_callback(msg)

    session = _build_session()
    t_all = time.perf_counter()

    step("Phase A — parallel: public IP/geo, system, network…")
    t_a = time.perf_counter()
    with ThreadPoolExecutor(max_workers=3) as pool:
        fut_ip = pool.submit(analyze_public_ip, timeout, session)
        fut_sys = pool.submit(analyze_system)
        fut_net = pool.submit(analyze_network)
        ip_result = fut_ip.result()
        system = fut_sys.result()
        network = fut_net.result()
    timings["phase_a_parallel_ms"] = int((time.perf_counter() - t_a) * 1000)

    step("Phase B — Tor Project check + VPN heuristics consolidation…")
    t_b = time.perf_counter()
    # Tor Project API is often slower than ip/geo; use generous read timeout (see tor_vpn.TOR_DEFAULT_TIMEOUT).
    tor_vpn = analyze_tor_and_vpn(ip_result, session=session)
    timings["phase_b_tor_vpn_ms"] = int((time.perf_counter() - t_b) * 1000)

    step("Phase C — leak model, fingerprint estimate, scoring…")
    t_c = time.perf_counter()
    fp_meta = fingerprint_uniqueness_estimate(system)
    leaks = assess_leaks(network, ip_result, tor_vpn, system)
    score_block = compute_anonymity_score(ip_result, system, network, tor_vpn, leaks, fp_meta)
    explanations = build_issue_explanations(ip_result, system, leaks, tor_vpn, fp_meta)
    warnings = build_warning_bullets(explanations, score_block)
    timings["phase_c_compute_ms"] = int((time.perf_counter() - t_c) * 1000)

    timings["total_wall_ms"] = int((time.perf_counter() - t_all) * 1000)
    step(f"Done — wall time ~{timings['total_wall_ms']} ms (network-bound).")

    try:
        session.close()
    except Exception:
        pass

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "ip": ip_result,
        "tor_vpn": tor_vpn,
        "system": system,
        "fingerprint": fp_meta,
        "network": network,
        "leaks": leaks,
        "score": score_block,
        "explanations": explanations,
        "warnings": warnings,
        "timeline": timeline,
        "scan_meta": {
            "timings_ms": timings,
            "pipeline_version": "2.0",
        },
    }
