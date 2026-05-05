"""
Local system fingerprinting for the current user machine (educational context only).
"""

from __future__ import annotations

import getpass
import locale
import logging
import platform
import socket
import uuid
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


def _safe_username() -> str | None:
    try:
        return getpass.getuser()
    except Exception as e:
        logger.debug("username: %s", e)
        return None


def _ambient_context() -> dict[str, Any]:
    """Locale/timezone are common correlation signals (visible to apps and often to remote parties)."""
    ctx: dict[str, Any] = {}
    try:
        loc = locale.getlocale()
        if not loc or not loc[0]:
            loc = locale.getdefaultlocale()
        ctx["default_locale"] = loc[0] if loc else None
        ctx["preferred_encoding"] = loc[1] if loc and len(loc) > 1 else None
    except Exception as e:
        logger.debug("locale: %s", e)
        ctx["default_locale"] = None
        ctx["preferred_encoding"] = None
    try:
        dt = datetime.now().astimezone()
        ctx["timezone_label"] = str(dt.tzinfo) if dt.tzinfo else None
        off = dt.utcoffset()
        ctx["timezone_offset_minutes"] = int(off.total_seconds() // 60) if off is not None else None
    except Exception as e:
        logger.debug("timezone: %s", e)
        ctx["timezone_label"] = None
        ctx["timezone_offset_minutes"] = None
    return ctx


def _hardware_hint() -> dict[str, Any]:
    """
    Non-invasive hints that still illustrate fingerprinting concepts.
    Does not read serial numbers or TPM; uses OS-reported identifiers.
    """
    hints: dict[str, Any] = {}
    try:
        node = uuid.getnode()
        hints["uuid_node_hex"] = f"{node:012x}"
        hints["uuid_node_note"] = "Derived from network interface MAC when available; can correlate sessions."
    except Exception as e:
        logger.debug("uuid node: %s", e)
    try:
        hints["machine"] = platform.machine()
        hints["processor"] = platform.processor() or "(not reported by OS)"
    except Exception:
        pass
    return hints


def analyze_system() -> dict[str, Any]:
    amb = _ambient_context()
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "platform_pretty": platform.platform(),
        "architecture": platform.architecture()[0],
        "hostname": socket.gethostname(),
        "username": _safe_username(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "hardware_hints": _hardware_hint(),
        **amb,
    }


def fingerprint_uniqueness_estimate(system: dict[str, Any]) -> dict[str, Any]:
    """
    Rough educational score: more distinct stable fields => easier to stand out in logs.
    """
    hh = system.get("hardware_hints") or {}
    fields = [
        system.get("os"),
        system.get("os_release"),
        system.get("architecture"),
        system.get("hostname"),
        system.get("username"),
        hh.get("uuid_node_hex"),
        system.get("default_locale"),
        system.get("timezone_label"),
        system.get("timezone_offset_minutes"),
    ]
    populated = sum(1 for f in fields if f is not None and f != "")
    # Cap so the teaching model does not always peg "maximum uniqueness" on a normal PC.
    uniqueness = min(78, int(9 * populated + 10))
    return {
        "populated_fields": populated,
        "uniqueness_score": uniqueness,
        "note": "Higher values mean more stable, distinguishing attributes are visible to software on this device.",
    }
