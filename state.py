# ids_project/state.py
"""Single source of truth for in-memory IDS runtime state."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque

from models import ThreatEvent

USER_SCORES: dict[str, float] = {}
BLOCKED_USERS: set[str] = set()
THREAT_LOG: list[ThreatEvent] = []
SESSION_IP_MAP: dict[str, str] = {}
REQUEST_LOG: dict[str, Deque[float]] = defaultdict(deque)
TOKEN_BLACKLIST: dict[str, float] = {}
FAILED_ATTEMPTS: dict[str, int] = defaultdict(int)
