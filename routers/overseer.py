# ids_project/routers/overseer.py
"""Overseer dashboard API routes for IDS administration."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from config import ALGORITHM, SECRET_KEY
from models import SeverityLevel, ThreatEvent
from scoring_engine import clear_user_threats, get_user_summary, unblock_user
from state import BLOCKED_USERS, THREAT_LOG, USER_SCORES

security = HTTPBearer(auto_error=False)
router = APIRouter(prefix="/overseer", tags=["Overseer Dashboard"])


class ThreatEventResponse(BaseModel):
    """Serialized threat event model for API responses."""

    event_id: UUID
    user_id: str
    ip_address: str
    threat_type: str
    severity: SeverityLevel
    points_added: float
    total_points_after: float
    timestamp: datetime
    is_auto_block: bool


class UserOverviewResponse(BaseModel):
    """Summary snapshot for a user in list views."""

    user_id: str
    current_score: float
    is_blocked: bool
    threat_count: int


class UserSummaryResponse(BaseModel):
    """Detailed summary for one user, including event history."""

    user_id: str
    current_score: float
    is_blocked: bool
    threat_events: list[ThreatEventResponse]


class UserActionResponse(BaseModel):
    """Common response shape for user state change actions."""

    message: str
    user_summary: UserSummaryResponse | None = None


class ClearThreatsResponse(BaseModel):
    """Response payload for user threat clear operations."""

    message: str


def _decode_and_validate_token(token: str) -> dict:
    """Decode a JWT and return its payload, raising 401 when invalid."""

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    return payload


def require_overseer(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Ensure requester is authenticated and has the overseer role."""

    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing credentials")

    payload = _decode_and_validate_token(credentials.credentials)
    if payload.get("role") != "overseer":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Overseer role required")
    return payload


def _serialize_event(event: ThreatEvent) -> ThreatEventResponse:
    """Convert ThreatEvent dataclass instances into API response models."""

    return ThreatEventResponse(
        event_id=event.event_id,
        user_id=event.user_id,
        ip_address=event.ip_address,
        threat_type=event.threat_type,
        severity=event.severity,
        points_added=event.points_added,
        total_points_after=event.total_points_after,
        timestamp=event.timestamp,
        is_auto_block=event.is_auto_block,
    )


@router.get("/users", response_model=list[UserOverviewResponse])
def list_users(_: dict = Depends(require_overseer)) -> list[UserOverviewResponse]:
    """Return all known users with score, block state, and threat counts."""

    user_ids = set(USER_SCORES) | set(BLOCKED_USERS)
    threat_counts: dict[str, int] = {}
    for event in THREAT_LOG:
        threat_counts[event.user_id] = threat_counts.get(event.user_id, 0) + 1

    return [
        UserOverviewResponse(
            user_id=user_id,
            current_score=USER_SCORES.get(user_id, 0.0),
            is_blocked=user_id in BLOCKED_USERS,
            threat_count=threat_counts.get(user_id, 0),
        )
        for user_id in sorted(user_ids)
    ]


@router.get("/users/{user_id}", response_model=UserSummaryResponse)
def get_user(user_id: str, _: dict = Depends(require_overseer)) -> UserSummaryResponse:
    """Return the full summary for one user."""

    if user_id not in USER_SCORES and user_id not in BLOCKED_USERS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    summary = get_user_summary(user_id)
    return UserSummaryResponse(
        user_id=summary["user_id"],
        current_score=summary["current_score"],
        is_blocked=summary["is_blocked"],
        threat_events=[
            _serialize_event(event)
            for event in sorted(
                [event for event in THREAT_LOG if event.user_id == user_id],
                key=lambda event: event.timestamp,
                reverse=True,
            )
        ],
    )


@router.get("/threats", response_model=list[ThreatEventResponse])
def list_threats(
    user_id: str | None = None,
    severity: SeverityLevel | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    _: dict = Depends(require_overseer),
) -> list[ThreatEventResponse]:
    """Return threat events filtered by optional user and severity constraints."""

    filtered_events = THREAT_LOG
    if user_id is not None:
        filtered_events = [event for event in filtered_events if event.user_id == user_id]
    if severity is not None:
        filtered_events = [event for event in filtered_events if event.severity == severity]

    ordered = sorted(filtered_events, key=lambda event: event.timestamp, reverse=True)
    return [_serialize_event(event) for event in ordered[:limit]]


@router.post("/users/{user_id}/unblock", response_model=UserActionResponse)
def unblock(user_id: str, _: dict = Depends(require_overseer)) -> UserActionResponse:
    """Unblock a user and return an updated summary payload."""

    unblock_user(user_id)
    summary = get_user_summary(user_id)
    return UserActionResponse(
        message=f"User '{user_id}' unblocked",
        user_summary=UserSummaryResponse(
            user_id=summary["user_id"],
            current_score=summary["current_score"],
            is_blocked=summary["is_blocked"],
            threat_events=[_serialize_event(event) for event in THREAT_LOG if event.user_id == user_id],
        ),
    )


@router.post("/users/{user_id}/clear", response_model=ClearThreatsResponse)
def clear(user_id: str, _: dict = Depends(require_overseer)) -> ClearThreatsResponse:
    """Clear threat history, score, and blocked state for a user."""

    clear_user_threats(user_id)
    return ClearThreatsResponse(message=f"Threat history cleared for user '{user_id}'")


@router.post("/users/{user_id}/block", response_model=UserActionResponse)
def block(user_id: str, _: dict = Depends(require_overseer)) -> UserActionResponse:
    """Manually block a user and create an audit event in the threat log."""

    current_score = USER_SCORES.get(user_id, 0.0)
    BLOCKED_USERS.add(user_id)
    event = ThreatEvent(
        event_id=uuid4(),
        user_id=user_id,
        ip_address="overseer-manual",
        threat_type="MANUAL_BLOCK",
        severity=SeverityLevel.HIGH,
        points_added=0.0,
        total_points_after=current_score,
        timestamp=datetime.now(timezone.utc),
        is_auto_block=False,
    )
    THREAT_LOG.append(event)

    summary = get_user_summary(user_id)
    return UserActionResponse(
        message=f"User '{user_id}' manually blocked",
        user_summary=UserSummaryResponse(
            user_id=summary["user_id"],
            current_score=summary["current_score"],
            is_blocked=summary["is_blocked"],
            threat_events=[_serialize_event(threat) for threat in THREAT_LOG if threat.user_id == user_id],
        ),
    )
