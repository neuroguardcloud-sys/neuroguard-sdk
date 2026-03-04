"""Unit tests for the vault module."""

import io

import pytest

from neuroguard import ConsentManager, AuditLogger, NeuralDataVault
from neuroguard.audit import AuditAction


def test_store_and_retrieve_success_when_consent_granted() -> None:
    """Store encrypted payload and retrieve it when consent is granted for the category."""
    consent = ConsentManager()
    consent.grant_category("neural_signals")
    audit = AuditLogger(stream=io.StringIO())
    vault = NeuralDataVault(consent_manager=consent, audit_logger=audit)

    payload = b"encrypted_neural_data"
    vault.store("user_1", "neural_signals", payload)
    retrieved = vault.retrieve("user_1", "neural_signals")
    assert retrieved == payload

    events = audit.get_events()
    assert len(events) >= 2
    actions = [e.action for e in events]
    assert AuditAction.VAULT_STORE in actions
    assert AuditAction.VAULT_RETRIEVE in actions
    # No plaintext in details
    for e in events:
        assert "encrypted_neural_data" not in e.to_json()
        assert b"encrypted_neural_data" not in e.to_json().encode()


def test_retrieve_denied_when_consent_revoked() -> None:
    """Retrieve raises PermissionError and logs denied when consent is revoked for category."""
    consent = ConsentManager()
    consent.grant_category("biometric")
    audit = AuditLogger(stream=io.StringIO())
    vault = NeuralDataVault(consent_manager=consent, audit_logger=audit)
    vault.store("user_2", "biometric", b"encrypted_biometric")

    consent.revoke_category("biometric")

    with pytest.raises(PermissionError) as exc_info:
        vault.retrieve("user_2", "biometric")
    assert "biometric" in str(exc_info.value)

    events = audit.get_events()
    retrieve_events = [e for e in events if e.action == AuditAction.VAULT_RETRIEVE]
    assert any(e.outcome == "denied" for e in retrieve_events)


def test_retrieve_raises_key_error_when_not_stored() -> None:
    """Retrieve raises KeyError when user_id or category has no stored data."""
    consent = ConsentManager()
    consent.grant_category("signals")
    consent.grant_category("other_category")  # consent granted so failure is "not found"
    audit = AuditLogger(stream=io.StringIO())
    vault = NeuralDataVault(consent_manager=consent, audit_logger=audit)

    with pytest.raises(KeyError):
        vault.retrieve("nonexistent_user", "signals")

    vault.store("u", "signals", b"x")
    with pytest.raises(KeyError):
        vault.retrieve("u", "other_category")


def test_delete_removes_data() -> None:
    """Delete removes all stored data for the user_id."""
    consent = ConsentManager()
    consent.grant_category("cat_a")
    audit = AuditLogger(stream=io.StringIO())
    vault = NeuralDataVault(consent_manager=consent, audit_logger=audit)

    vault.store("user_3", "cat_a", b"data")
    vault.delete("user_3")

    with pytest.raises(KeyError):
        vault.retrieve("user_3", "cat_a")

    events = audit.get_events()
    assert any(e.action == AuditAction.VAULT_DELETE and e.outcome == "success" for e in events)


def test_delete_idempotent_when_no_data() -> None:
    """Delete does not raise when user_id has no data; still logs audit."""
    consent = ConsentManager()
    audit = AuditLogger(stream=io.StringIO())
    vault = NeuralDataVault(consent_manager=consent, audit_logger=audit)

    vault.delete("no_data_user")

    events = audit.get_events()
    assert any(e.action == AuditAction.VAULT_DELETE for e in events)


def test_audit_hash_chain_validates() -> None:
    """When audit logger uses hash chain, verify_chain validates after vault operations."""
    consent = ConsentManager()
    consent.grant_category("chain_test")
    audit = AuditLogger(stream=io.StringIO(), use_hash_chain=True)
    vault = NeuralDataVault(consent_manager=consent, audit_logger=audit)

    vault.store("u", "chain_test", b"encrypted")
    vault.retrieve("u", "chain_test")
    vault.delete("u")

    assert audit.verify_chain() is True
