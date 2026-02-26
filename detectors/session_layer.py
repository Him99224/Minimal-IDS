"""Session-layer detectors for brute-force and session-hijack activity."""

from collections import defaultdict, deque
import time
from typing import Deque, Dict, Optional

from scoring_engine import SESSION_IP_MAP

FAILED_ATTEMPTS: Dict[str, Deque[float]] = defaultdict(deque)
FAILED_WINDOW_SECONDS = 300
FAILED_THRESHOLD = 5


def check_brute_force(ip_address: str, user_id: Optional[str]) -> Optional[str]:
    """Track failed login attempts by IP and detect brute-force behavior.

    This function should be called only on failed login attempts.

    Args:
        ip_address: Source IP for the failed login attempt.
        user_id: Optional user id if known; may be None for pre-auth attempts.

    Returns:
        The threat type ``"BRUTE_FORCE"`` when attempts exceed threshold in the
        configured window; otherwise ``None``.
    """
    _ = user_id
    now_ts = time.time()
    attempts = FAILED_ATTEMPTS[ip_address]
    attempts.append(now_ts)

    while attempts and (now_ts - attempts[0]) > FAILED_WINDOW_SECONDS:
        attempts.popleft()

    if len(attempts) > FAILED_THRESHOLD:
        return "BRUTE_FORCE"
    return None


def reset_failed_attempts(ip_address: str) -> None:
    """Reset failed login-attempt tracking for a specific IP address."""
    FAILED_ATTEMPTS.pop(ip_address, None)


def check_session_hijack(jti: str, current_ip: str) -> Optional[str]:
    """Detect potential session hijacking by comparing token IP baseline.

    Args:
        jti: Token id from the active JWT.
        current_ip: Source IP of the current authenticated request.

    Returns:
        The threat type ``"SESSION_HIJACKING"`` when IP mismatch is detected,
        else ``None``.
    """
    original_ip = SESSION_IP_MAP.get(jti)
    if original_ip is None:
        return None

    if current_ip != original_ip:
        return "SESSION_HIJACKING"
    return None
