"""Unit tests for the audit logger."""

import io

import pytest

from neuroguard.audit import AuditAction, AuditEvent, AuditLogger


def test_log_creates_event_and_writes_line() -> None:
    """log() appends an event and writes JSON to the stream."""
    stream = io.StringIO()
    logger = AuditLogger(stream=stream)
    event = logger.log(
        AuditAction.ENCRYPT,
        actor="test_actor",
        resource="neural_data",
        outcome="success",
    )
    assert isinstance(event, AuditEvent)
    assert event.action == AuditAction.ENCRYPT
    assert event.actor == "test_actor"
    assert "encrypt" in stream.getvalue()
    assert "test_actor" in stream.getvalue()


def test_get_events_returns_all_logged_events() -> None:
    """get_events returns the in-memory list of events."""
    logger = AuditLogger(stream=io.StringIO())
    logger.log(AuditAction.CONSENT_GRANT, actor="user")
    logger.log(AuditAction.DECRYPT, resource="payload")
    events = logger.get_events()
    assert len(events) == 2
    assert events[0].action == AuditAction.CONSENT_GRANT
    assert events[1].action == AuditAction.DECRYPT


def test_clear_events_empties_buffer() -> None:
    """clear_events removes in-memory events."""
    logger = AuditLogger(stream=io.StringIO())
    logger.log(AuditAction.DATA_ACCESS)
    logger.clear_events()
    assert len(logger.get_events()) == 0


def test_audit_event_to_json_serializable() -> None:
    """AuditEvent.to_json() produces valid JSON."""
    event = AuditEvent(
        action=AuditAction.PROCESSING,
        actor="sdk",
        outcome="success",
        details={"key": "value"},
    )
    import json as json_mod
    parsed = json_mod.loads(event.to_json())
    assert parsed["action"] == "processing"
    assert parsed["actor"] == "sdk"
    assert parsed["outcome"] == "success"
    assert parsed["details"]["key"] == "value"
