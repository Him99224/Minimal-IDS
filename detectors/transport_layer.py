# ids_project/detectors/transport_layer.py
"""Transport-layer and payload detectors for IDS middleware."""

from __future__ import annotations

import re
import time
from typing import Optional
from urllib.parse import unquote

from config import WINDOW_SECONDS
from state import REQUEST_LOG


_SQL_PATTERNS: tuple[str, ...] = (
    r"'\s*or",
    r"1\s*=\s*1",
    r"union\s+select",
    r"drop\s+table",
    r"insert\s+into",
    r"--",
    r"/\*",
    r"xp_",
    r"exec\s*\(",
    r"cast\s*\(",
    r"convert\s*\(",
)

_XSS_PATTERNS: tuple[str, ...] = (
    r"<script",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"<iframe",
    r"<img\s+src",
    r"document\.cookie",
    r"eval\s*\(",
)

_COMMAND_PATTERNS: tuple[str, ...] = (
    r";\s*ls",
    r";\s*cat",
    r"&&\s*rm",
    r"\|\s*cat",
    r"\|\s*ls",
    r"\$\([^)]*\)",
    r"`[^`]+`",
    r"/etc/passwd",
    r"/bin/sh",
    r"/bin/bash",
)


def _matches_pattern(payload: str, patterns: tuple[str, ...]) -> bool:
    """Return whether the decoded payload matches any suspicious regex pattern."""

    return any(re.search(pattern, payload, re.IGNORECASE) for pattern in patterns)


def check_high_request_rate(ip_address: str, user_id: Optional[str]) -> Optional[str]:
    """Detect excessive request volume for an IP in the current sliding window."""

    _ = user_id
    now_ts = time.time()
    ip_queue = REQUEST_LOG[ip_address]
    while ip_queue and (now_ts - ip_queue[0]) > WINDOW_SECONDS:
        ip_queue.popleft()
    if len(ip_queue) > 20:
        return "HIGH_REQUEST_RATE"
    return None


def check_sql_injection(payload: str, user_id: str, ip: str) -> Optional[str]:
    """Detect SQL injection signatures in request payload content."""

    _ = (user_id, ip)
    decoded_payload = unquote(payload)
    if _matches_pattern(decoded_payload, _SQL_PATTERNS):
        return "SQL_INJECTION"
    return None


def check_xss(payload: str, user_id: str, ip: str) -> Optional[str]:
    """Detect XSS signatures in request payload content."""

    _ = (user_id, ip)
    decoded_payload = unquote(payload)
    if _matches_pattern(decoded_payload, _XSS_PATTERNS):
        return "XSS_INJECTION"
    return None


def check_command_injection(payload: str, user_id: str, ip: str) -> Optional[str]:
    """Detect command injection signatures in request payload content."""

    _ = (user_id, ip)
    decoded_payload = unquote(payload)
    if _matches_pattern(decoded_payload, _COMMAND_PATTERNS):
        return "COMMAND_INJECTION"
    return None
