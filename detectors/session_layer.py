"""Session-layer intrusion detection detectors."""

from collections import defaultdict, deque
import time
from typing import Deque, Dict, Optional

from scoring_engine import SESSION_IP_MAP

FAILED_ATTEMPTS: Dict[str, Deque[float]] = defaultdict(deque)
BRUTE_FORCE_WINDOW_SECONDS = 300
BRUTE_FORCE_THRESHOLD = 5


def check_brute_force(ip_address: str, user_id: Optional[str]) -> Optional[str]:
    """Track failed login attempts per IP and flag likely brute force activity.

    This function is intended to be called only on failed login attempts.

    Args:
        ip_address: Request source IP address.
        user_id: Optional user identifier if known. For pre-auth failures this is None.

    Returns:
        "BRUTE_FORCE" when failures exceed threshold within the time window,
        otherwise None.
    """
    _ = user_id
    now_ts = time.time()
    attempts = FAILED_ATTEMPTS[ip_address]
    attempts.append(now_ts)

    while attempts and (now_ts - attempts[0]) > BRUTE_FORCE_WINDOW_SECONDS:
        attempts.popleft()

    if len(attempts) > BRUTE_FORCE_THRESHOLD:
        return "BRUTE_FORCE"
    return None


def reset_failed_attempts(ip_address: str) -> None:
    """Clear the failed-attempt tracker for a given IP address."""
    FAILED_ATTEMPTS.pop(ip_address, None)


def check_session_hijack(jti: str, current_ip: str) -> Optional[str]:
    """Detect potential session hijacking by comparing current and original IPs.

    Args:
        jti: JWT ID for the active token.
        current_ip: IP address observed for the current request.

    Returns:
        "SESSION_HIJACKING" when the active IP differs from issuance IP,
        otherwise None.
    """
    original_ip = SESSION_IP_MAP.get(jti)
    if original_ip is None:
        return None

    if current_ip != original_ip:
        return "SESSION_HIJACKING"
    return None
