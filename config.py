# ids_project/config.py
"""Application configuration constants for the IDS project."""

from __future__ import annotations

SECRET_KEY: str = "change-this-in-real-projects"
ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

WINDOW_SECONDS: int = 10
REQUEST_LIMIT: int = 20

SCORE_THRESHOLDS: dict[str, float] = {
    "NO_ACTION_MAX": 30,
    "FLAG_TO_OVERSEER_MAX": 60,
    "AUTO_BLOCK_MAX": 90,
}

THREAT_DEFINITIONS: dict[str, dict[str, float | str]] = {
    "SYN_FLOOD": {"severity": "SEVERE", "points": 85},
    "UDP_FLOOD": {"severity": "SEVERE", "points": 80},
    "SESSION_HIJACKING": {"severity": "HIGH", "points": 75},
    "SQL_INJECTION": {"severity": "HIGH", "points": 70},
    "DNS_AMPLIFICATION": {"severity": "HIGH", "points": 65},
    "XSS_INJECTION": {"severity": "HIGH", "points": 60},
    "COMMAND_INJECTION": {"severity": "HIGH", "points": 60},
    "PORT_SCANNING": {"severity": "MEDIUM", "points": 40},
    "BRUTE_FORCE": {"severity": "MEDIUM", "points": 35},
    "HIGH_REQUEST_RATE": {"severity": "LOW", "points": 10},
    "SUSPICIOUS_USER_AGENT": {"severity": "LOW", "points": 5},
    "MANUAL_BLOCK": {"severity": "HIGH", "points": 0},
}
