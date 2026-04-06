# ids_project/scoring_engine.py
"""In-memory threat scoring engine for an IDS."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict
from uuid import uuid4

from config import SCORE_THRESHOLDS, THREAT_DEFINITIONS
from models import SeverityLevel, ThreatEvent
from state import BLOCKED_USERS, SESSION_IP_MAP, THREAT_LOG, USER_SCORES


@dataclass
class ThreatDefinition:
    """Static threat metadata used for point assignment."""

    severity: SeverityLevel
    points: float


NORMALIZED_THREAT_DEFINITIONS: Dict[str, ThreatDefinition] = {
    threat_type: ThreatDefinition(
        severity=SeverityLevel(str(definition["severity"])),
        points=float(definition["points"]),
    )
    for threat_type, definition in THREAT_DEFINITIONS.items()
}

NO_ACTION_MAX = SCORE_THRESHOLDS["NO_ACTION_MAX"]
FLAG_TO_OVERSEER_MAX = SCORE_THRESHOLDS["FLAG_TO_OVERSEER_MAX"]
AUTO_BLOCK_MAX = SCORE_THRESHOLDS["AUTO_BLOCK_MAX"]


def _last_user_event(user_id: str) -> ThreatEvent | None:
    """Return the most recent threat event for a user, if one exists."""

    for event in reversed(THREAT_LOG):
        if event.user_id == user_id:
            return event
    return None


def _try_broadcast(event: ThreatEvent) -> None:
    """Best-effort async broadcast of a threat event to WebSocket clients."""

    from ws_manager import manager

    data = {
        "type": "threat_event",
        "event": asdict(event),
        "stats": {
            "total_threats": len(THREAT_LOG),
            "blocked_users": len(BLOCKED_USERS),
            "tracked_users": len(USER_SCORES),
        },
    }
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(manager.broadcast(data))
    except RuntimeError:
        pass


def record_threat(user_id: str, ip_address: str, threat_type: str) -> ThreatEvent:
    """Record a threat event, update score state, and auto-block when required."""

    definition = NORMALIZED_THREAT_DEFINITIONS.get(threat_type)
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

    _try_broadcast(event)

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

    THREAT_LOG[:] = [event for event in THREAT_LOG if event.user_id != user_id]
    USER_SCORES[user_id] = 0.0
    BLOCKED_USERS.discard(user_id)
    SESSION_IP_MAP.pop(user_id, None)


def is_blocked(user_id: str) -> bool:
    """Return whether a user is currently blocked."""

    return user_id in BLOCKED_USERS
