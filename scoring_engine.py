"""Threat-scoring engine primitives for the IDS."""

from typing import Dict, List

SESSION_IP_MAP: Dict[str, str] = {}
THREAT_LOG: List[dict] = []


def record_threat(user_id: str, ip: str, threat_type: str) -> None:
    """Record a threat event in an in-memory log."""
    THREAT_LOG.append({"user_id": user_id, "ip": ip, "threat_type": threat_type})
    print(f"[THREAT] user_id={user_id} ip={ip} threat_type={threat_type}")
