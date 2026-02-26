# ids_project/models.py
"""Shared dataclasses and Pydantic API models for the IDS project."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List
from uuid import UUID

from pydantic import BaseModel


class SeverityLevel(str, Enum):
    """Supported severity levels for threats."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    SEVERE = "SEVERE"


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


class UserSummary(BaseModel):
    """Detailed threat and score summary for a specific user."""

    user_id: str
    current_score: float
    is_blocked: bool
    threat_events: List[ThreatEvent]


class ThreatListResponse(BaseModel):
    """Response wrapper containing threat events list."""

    threats: List[ThreatEvent]


class LoginRequest(BaseModel):
    """Request payload for login endpoint."""

    username: str
    password: str


class TokenResponse(BaseModel):
    """Response payload for token issuance endpoints."""

    access_token: str
    token_type: str
