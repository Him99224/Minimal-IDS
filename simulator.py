# ids_project/simulator.py
"""Attack simulator for IDS conference demos."""

from __future__ import annotations

import asyncio
import random
from typing import Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel

from scoring_engine import record_threat
from state import BLOCKED_USERS, FAILED_ATTEMPTS, SESSION_IP_MAP, THREAT_LOG, TOKEN_BLACKLIST, USER_SCORES, REQUEST_LOG

router = APIRouter(prefix="/demo", tags=["Demo Simulator"])

# Predefined attack scenarios for realistic demo
ATTACK_SCENARIOS = [
    {"user_id": "attacker-1", "ip": "192.168.1.100", "threat": "SQL_INJECTION"},
    {"user_id": "attacker-1", "ip": "192.168.1.100", "threat": "SQL_INJECTION"},
    {"user_id": "attacker-2", "ip": "10.0.0.55", "threat": "XSS_INJECTION"},
    {"user_id": "attacker-3", "ip": "172.16.0.12", "threat": "COMMAND_INJECTION"},
    {"user_id": "attacker-1", "ip": "192.168.1.101", "threat": "SESSION_HIJACKING"},
    {"user_id": "attacker-4", "ip": "203.0.113.42", "threat": "BRUTE_FORCE"},
    {"user_id": "attacker-2", "ip": "10.0.0.55", "threat": "HIGH_REQUEST_RATE"},
    {"user_id": "attacker-5", "ip": "198.51.100.7", "threat": "SYN_FLOOD"},
    {"user_id": "attacker-2", "ip": "10.0.0.55", "threat": "XSS_INJECTION"},
    {"user_id": "attacker-3", "ip": "172.16.0.12", "threat": "COMMAND_INJECTION"},
    {"user_id": "attacker-6", "ip": "192.0.2.99", "threat": "DNS_AMPLIFICATION"},
    {"user_id": "attacker-4", "ip": "203.0.113.42", "threat": "PORT_SCANNING"},
    {"user_id": "attacker-1", "ip": "192.168.1.100", "threat": "HIGH_REQUEST_RATE"},
    {"user_id": "attacker-7", "ip": "100.64.0.1", "threat": "UDP_FLOOD"},
    {"user_id": "attacker-5", "ip": "198.51.100.7", "threat": "SUSPICIOUS_USER_AGENT"},
    {"user_id": "attacker-3", "ip": "172.16.0.12", "threat": "SQL_INJECTION"},
    {"user_id": "attacker-6", "ip": "192.0.2.99", "threat": "SESSION_HIJACKING"},
    {"user_id": "attacker-2", "ip": "10.0.0.55", "threat": "BRUTE_FORCE"},
    {"user_id": "attacker-8", "ip": "45.33.32.156", "threat": "SYN_FLOOD"},
    {"user_id": "attacker-7", "ip": "100.64.0.1", "threat": "COMMAND_INJECTION"},
]


class SimulateResponse(BaseModel):
    message: str
    events_fired: int
    mode: str


class ResetResponse(BaseModel):
    message: str


@router.post("/simulate", response_model=SimulateResponse)
async def simulate_attacks(
    mode: Literal["instant", "staggered"] = Query(default="staggered", description="Firing mode"),
    count: int = Query(default=20, ge=1, le=50, description="Number of attack events to fire"),
) -> SimulateResponse:
    """Fire a sequence of simulated attacks for demo purposes.

    - **instant**: All events fire at once
    - **staggered**: Events fire with 0.5-1.5s random delays between them (dramatic reveal)
    """

    scenarios = []
    for i in range(count):
        scenarios.append(ATTACK_SCENARIOS[i % len(ATTACK_SCENARIOS)])

    fired = 0
    for scenario in scenarios:
        try:
            record_threat(scenario["user_id"], scenario["ip"], scenario["threat"])
            fired += 1
        except ValueError:
            pass

        if mode == "staggered":
            await asyncio.sleep(random.uniform(0.5, 1.5))

    return SimulateResponse(
        message=f"Simulation complete. {fired} threat events fired.",
        events_fired=fired,
        mode=mode,
    )


@router.post("/reset", response_model=ResetResponse)
def reset_demo() -> ResetResponse:
    """Clear all IDS state for a fresh demo run."""

    THREAT_LOG.clear()
    USER_SCORES.clear()
    BLOCKED_USERS.clear()
    SESSION_IP_MAP.clear()
    TOKEN_BLACKLIST.clear()
    FAILED_ATTEMPTS.clear()
    REQUEST_LOG.clear()

    return ResetResponse(message="All IDS state cleared. Ready for a fresh demo.")
