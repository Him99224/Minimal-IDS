"""Detector package exports and shared detector protocol."""

from __future__ import annotations

from typing import Protocol


class PayloadDetector(Protocol):
    """Callable protocol for payload-based detector functions."""

    def __call__(self, payload: str, user_id: str, ip: str) -> str | None:
        """Return a threat type if suspicious behavior is detected."""


from detectors.session_layer import check_brute_force, check_session_hijacking
from detectors.transport_layer import (
    check_command_injection,
    check_high_request_rate,
    check_sql_injection,
    check_xss,
)

__all__ = [
    "PayloadDetector",
    "check_high_request_rate",
    "check_sql_injection",
    "check_xss",
    "check_command_injection",
    "check_brute_force",
    "check_session_hijacking",
]
