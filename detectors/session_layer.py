# ids_project/detectors/session_layer.py
"""Session-layer intrusion detectors."""

from __future__ import annotations

from state import FAILED_ATTEMPTS, SESSION_IP_MAP


def check_brute_force(user_id: str) -> str | None:
    """Detect brute-force behavior from repeated failed login attempts."""

    if FAILED_ATTEMPTS.get(user_id, 0) >= 5:
        return "BRUTE_FORCE"
    return None


def check_session_hijacking(user_id: str, ip_address: str) -> str | None:
    """Detect session hijacking when user IP changes within an active session."""

    known_ip = SESSION_IP_MAP.get(user_id)
    if known_ip is None:
        SESSION_IP_MAP[user_id] = ip_address
        return None
    if known_ip != ip_address:
        return "SESSION_HIJACKING"
    return None
