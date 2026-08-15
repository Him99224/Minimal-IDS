"""Unit tests for scoring_engine.py."""

from __future__ import annotations

from datetime import timedelta

import pytest

import scoring_engine
from state import BLOCKED_USERS, SESSION_IP_MAP, THREAT_LOG, USER_SCORES


@pytest.fixture(autouse=True)
def reset_state() -> None:
    """Reset in-memory IDS state before each test."""

    USER_SCORES.clear()
    BLOCKED_USERS.clear()
    THREAT_LOG.clear()
    SESSION_IP_MAP.clear()


def test_record_threat_updates_score_and_logs_event() -> None:
    event = scoring_engine.record_threat("u1", "127.0.0.1", "HIGH_REQUEST_RATE")

    assert USER_SCORES["u1"] == pytest.approx(10.0)
    assert event.user_id == "u1"
    assert event.ip_address == "127.0.0.1"
    assert event.threat_type == "HIGH_REQUEST_RATE"
    assert len(THREAT_LOG) == 1
    assert event.is_auto_block is False


def test_record_threat_rejects_unknown_threat_type() -> None:
    with pytest.raises(ValueError, match="Unknown threat type"):
        scoring_engine.record_threat("u1", "127.0.0.1", "NOT_A_THREAT")


def test_auto_block_when_score_crosses_threshold() -> None:
    event = scoring_engine.record_threat("u2", "127.0.0.2", "SQL_INJECTION")

    assert USER_SCORES["u2"] == pytest.approx(70.0)
    assert "u2" in BLOCKED_USERS
    assert event.is_auto_block is True


def test_apply_decay_reduces_score_by_half_per_day() -> None:
    scoring_engine.record_threat("u3", "127.0.0.3", "PORT_SCANNING")
    assert USER_SCORES["u3"] == pytest.approx(40.0)

    THREAT_LOG[-1].timestamp = THREAT_LOG[-1].timestamp - timedelta(days=2, minutes=1)
    scoring_engine.apply_decay("u3")

    assert USER_SCORES["u3"] == pytest.approx(10.0)


def test_get_user_summary_orders_events_descending() -> None:
    scoring_engine.record_threat("u4", "127.0.0.4", "HIGH_REQUEST_RATE")
    scoring_engine.record_threat("u4", "127.0.0.4", "SUSPICIOUS_USER_AGENT")

    summary = scoring_engine.get_user_summary("u4")

    assert summary["user_id"] == "u4"
    assert summary["current_score"] == pytest.approx(15.0)
    assert summary["is_blocked"] is False
    assert len(summary["threat_events"]) == 2
    assert summary["threat_events"][0]["timestamp"] >= summary["threat_events"][1]["timestamp"]


def test_unblock_user_removes_user_from_blocklist() -> None:
    scoring_engine.record_threat("u5", "127.0.0.5", "SYN_FLOOD")
    assert "u5" in BLOCKED_USERS

    scoring_engine.unblock_user("u5")

    assert "u5" not in BLOCKED_USERS


def test_clear_user_threats_resets_all_user_state() -> None:
    scoring_engine.record_threat("u6", "127.0.0.6", "HIGH_REQUEST_RATE")
    SESSION_IP_MAP["u6"] = "127.0.0.6"

    scoring_engine.clear_user_threats("u6")

    assert USER_SCORES["u6"] == pytest.approx(0.0)
    assert "u6" not in BLOCKED_USERS
    assert "u6" not in SESSION_IP_MAP
    assert all(event.user_id != "u6" for event in THREAT_LOG)


def test_is_blocked_reflects_current_state() -> None:
    scoring_engine.record_threat("u7", "127.0.0.7", "SYN_FLOOD")
    assert scoring_engine.is_blocked("u7") is True

    scoring_engine.unblock_user("u7")
    assert scoring_engine.is_blocked("u7") is False
