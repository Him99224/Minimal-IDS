"""Simple in-memory threat scoring primitives used by IDS detectors."""

from typing import Dict, List

SESSION_IP_MAP: Dict[str, str] = {}
THREAT_LOG: List[dict] = []


def record_threat(user_id: str, ip: str, threat_type: str) -> None:
    """Record a threat event in memory and print a log line."""
    entry = {"user_id": user_id, "ip": ip, "threat_type": threat_type}
    THREAT_LOG.append(entry)
    print(f"[THREAT] user_id={user_id} ip={ip} type={threat_type}")
