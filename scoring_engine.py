"""In-memory threat scoring engine for an IDS."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Set
from uuid import UUID, uuid4


class SeverityLevel(str, Enum):
    """Supported severity levels for threats."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    SEVERE = "SEVERE"


@dataclass
class ThreatDefinition:
    """Static threat metadata used for point assignment."""

    severity: SeverityLevel
    points: float


@dataclass
class ThreatEvent:
    """Represents a recorded threat occurrence for a user."""

    event_id: UUID
    user_id: str
    ip_address: str
    threat_type: str
    severity: SeverityLevel
    points_added: float
    total_points_after: float
    timestamp: datetime
    is_auto_block: bool


THREAT_DEFINITIONS: Dict[str, ThreatDefinition] = {
    "SYN_FLOOD": ThreatDefinition(SeverityLevel.SEVERE, 85),
    "UDP_FLOOD": ThreatDefinition(SeverityLevel.SEVERE, 80),
    "SESSION_HIJACKING": ThreatDefinition(SeverityLevel.HIGH, 75),
    "SQL_INJECTION": ThreatDefinition(SeverityLevel.HIGH, 70),
    "DNS_AMPLIFICATION": ThreatDefinition(SeverityLevel.HIGH, 65),
    "XSS_INJECTION": ThreatDefinition(SeverityLevel.HIGH, 60),
    "COMMAND_INJECTION": ThreatDefinition(SeverityLevel.HIGH, 60),
    "PORT_SCANNING": ThreatDefinition(SeverityLevel.MEDIUM, 40),
    "BRUTE_FORCE": ThreatDefinition(SeverityLevel.MEDIUM, 35),
    "HIGH_REQUEST_RATE": ThreatDefinition(SeverityLevel.LOW, 10),
    "SUSPICIOUS_USER_AGENT": ThreatDefinition(SeverityLevel.LOW, 5),
}

# User data stores.
USER_SCORES: Dict[str, float] = {}
BLOCKED_USERS: Set[str] = set()
THREAT_LOG: List[ThreatEvent] = []
SESSION_IP_MAP: Dict[str, str] = {}

# Threshold constants.
NO_ACTION_MAX = 30
FLAG_TO_OVERSEER_MAX = 60
AUTO_BLOCK_MAX = 90


def _last_user_event(user_id: str) -> ThreatEvent | None:
    """Return the most recent threat event for a user, if one exists."""

    for event in reversed(THREAT_LOG):
        if event.user_id == user_id:
            return event
    return None


def record_threat(user_id: str, ip_address: str, threat_type: str) -> ThreatEvent:
    """Record a threat event, update score state, and auto-block when required."""

    definition = THREAT_DEFINITIONS.get(threat_type)
    if definition is None:
        raise ValueError(f"Unknown threat type: {threat_type}")

    apply_decay(user_id)

    current_score = USER_SCORES.get(user_id, 0.0)
    updated_score = current_score + definition.points
    USER_SCORES[user_id] = max(0.0, updated_score)

    should_auto_block = USER_SCORES[user_id] >= 61
    if should_auto_block:
        BLOCKED_USERS.add(user_id)

    event = ThreatEvent(
        event_id=uuid4(),
        user_id=user_id,
        ip_address=ip_address,
        threat_type=threat_type,
        severity=definition.severity,
        points_added=definition.points,
        total_points_after=USER_SCORES[user_id],
        timestamp=datetime.now(timezone.utc),
        is_auto_block=should_auto_block,
    )
    THREAT_LOG.append(event)

    return event


def apply_decay(user_id: str) -> None:
    """Apply 50% score decay per full 24-hour period since last user event."""

    last_event = _last_user_event(user_id)
    if last_event is None:
        return

    current_score = USER_SCORES.get(user_id, 0.0)
    if current_score <= 0:
        USER_SCORES[user_id] = 0.0
        return

    now = datetime.now(timezone.utc)
    elapsed = now - last_event.timestamp
    full_days = int(elapsed / timedelta(hours=24))

    if full_days <= 0:
        return

    decayed_score = current_score * (0.5**full_days)
    USER_SCORES[user_id] = max(0.0, decayed_score)


def get_user_summary(user_id: str) -> dict:
    """Return score, block state, and threat history for a user."""

    user_events = [event for event in THREAT_LOG if event.user_id == user_id]
    ordered_events = sorted(user_events, key=lambda event: event.timestamp, reverse=True)

    return {
        "user_id": user_id,
        "current_score": USER_SCORES.get(user_id, 0.0),
        "is_blocked": user_id in BLOCKED_USERS,
        "threat_events": [asdict(event) for event in ordered_events],
    }


def unblock_user(user_id: str) -> None:
    """Unblock a user without modifying their score or threat history."""

    BLOCKED_USERS.discard(user_id)


def clear_user_threats(user_id: str) -> None:
    """Clear all threat events and score state for a user, and unblock them."""

    global THREAT_LOG

    THREAT_LOG = [event for event in THREAT_LOG if event.user_id != user_id]
    USER_SCORES[user_id] = 0.0
    BLOCKED_USERS.discard(user_id)


def is_blocked(user_id: str) -> bool:
    """Return whether a user is currently blocked."""

    return user_id in BLOCKED_USERS
