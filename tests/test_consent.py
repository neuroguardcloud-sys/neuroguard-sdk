"""Unit tests for the consent manager."""

import pytest

from neuroguard.consent import ConsentManager, ConsentLevel, ConsentScope


def test_grant_and_has_consent() -> None:
    """After granting a scope, has_consent returns True."""
    mgr = ConsentManager()
    assert not mgr.has_consent(ConsentScope.PROCESSING)
    mgr.grant(ConsentScope.PROCESSING)
    assert mgr.has_consent(ConsentScope.PROCESSING)


def test_revoke_removes_consent() -> None:
    """After revoking, has_consent returns False."""
    mgr = ConsentManager()
    mgr.grant(ConsentScope.EXPORT)
    mgr.revoke(ConsentScope.EXPORT)
    assert not mgr.has_consent(ConsentScope.EXPORT)


def test_require_consent_raises_when_missing() -> None:
    """require_consent raises PermissionError when scope not granted."""
    mgr = ConsentManager()
    mgr.grant(ConsentScope.PROCESSING)
    with pytest.raises(PermissionError) as exc_info:
        mgr.require_consent(ConsentScope.PROCESSING, ConsentScope.EXPORT)
    assert "EXPORT" in str(exc_info.value)


def test_require_consent_passes_when_granted() -> None:
    """require_consent does not raise when all scopes are granted."""
    mgr = ConsentManager()
    mgr.grant(ConsentScope.PROCESSING)
    mgr.grant(ConsentScope.STORAGE)
    mgr.require_consent(ConsentScope.PROCESSING, ConsentScope.STORAGE)


def test_get_record_returns_granted_record() -> None:
    """get_record returns the consent record for a scope."""
    mgr = ConsentManager()
    mgr.grant(ConsentScope.ANALYTICS, metadata={"purpose": "usage_stats"})
    record = mgr.get_record(ConsentScope.ANALYTICS)
    assert record is not None
    assert record.level == ConsentLevel.EXPLICIT
    assert record.granted_at is not None
    assert record.metadata.get("purpose") == "usage_stats"
