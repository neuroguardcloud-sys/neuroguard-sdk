"""Unit tests for ConsentLedger (persistence, chain validity, export, integration)."""

import json
import os
import tempfile

import pytest

from neuroguard.consent import ConsentManager, ConsentLedger, ConsentScope


@pytest.fixture
def temp_ledger_path():
    """Return a path to a temp JSONL file; removed after test."""
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    try:
        yield path
    finally:
        if os.path.isfile(path):
            os.remove(path)


def test_writes_events_and_loads_history(temp_ledger_path: str) -> None:
    """Ledger writes events to file; new instance loads and history() returns them."""
    ledger = ConsentLedger(path=temp_ledger_path)
    ledger.record_grant("user_1", "processing", actor="user")
    ledger.record_revoke("user_1", "processing", actor="admin", reason="withdrawal")
    ledger.record_grant("user_2", "export")

    # Same instance
    h1 = ledger.history("user_1")
    assert len(h1) == 2
    assert h1[0]["type"] == "grant" and h1[0]["category"] == "processing"
    assert h1[1]["type"] == "revoke" and h1[1]["reason"] == "withdrawal" and h1[1]["actor"] == "admin"
    assert all("hash_prev" in e and "hash_current" in e for e in h1)

    # New instance loads from file
    ledger2 = ConsentLedger(path=temp_ledger_path)
    h2 = ledger2.history("user_1")
    assert len(h2) == 2
    assert h2[0]["type"] == "grant"
    assert ledger2.history("user_2") == ledger.history("user_2")
    assert ledger2.history() == ledger.history()


def test_history_without_user_id_returns_all(temp_ledger_path: str) -> None:
    """history(user_id=None) returns all events."""
    ledger = ConsentLedger(path=temp_ledger_path)
    ledger.record_grant("a", "x")
    ledger.record_grant("b", "y")
    all_events = ledger.history(user_id=None)
    assert len(all_events) == 2
    assert [e["user_id"] for e in all_events] == ["a", "b"]


def test_verify_chain_passes_for_untampered_file(temp_ledger_path: str) -> None:
    """verify_chain returns True for an intact file."""
    ledger = ConsentLedger(path=temp_ledger_path)
    ledger.record_grant("u", "storage")
    ledger.record_revoke("u", "storage")
    assert ledger.verify_chain() is True
    # After reload
    ledger2 = ConsentLedger(path=temp_ledger_path)
    assert ledger2.verify_chain() is True


def test_verify_chain_empty_ledger(temp_ledger_path: str) -> None:
    """verify_chain returns True for empty ledger."""
    ledger = ConsentLedger(path=temp_ledger_path)
    assert ledger.verify_chain() is True


def test_verify_chain_fails_if_line_modified(temp_ledger_path: str) -> None:
    """verify_chain returns False after a line in the file is tampered with."""
    ledger = ConsentLedger(path=temp_ledger_path)
    ledger.record_grant("u", "analytics")
    ledger.record_revoke("u", "analytics")
    assert ledger.verify_chain() is True

    # Tamper file: change first line's category
    with open(temp_ledger_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    first = json.loads(lines[0])
    first["category"] = "tampered"
    lines[0] = json.dumps(first, sort_keys=True) + "\n"
    with open(temp_ledger_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # New instance loads tampered file
    ledger2 = ConsentLedger(path=temp_ledger_path)
    assert ledger2.verify_chain() is False


def test_export_json_full_and_filtered(temp_ledger_path: str) -> None:
    """export_json() returns all events; export_json(user_id=X) filters by user."""
    ledger = ConsentLedger(path=temp_ledger_path)
    ledger.record_grant("alice", "storage", reason="opt_in")
    ledger.record_revoke("alice", "storage")
    ledger.record_grant("bob", "export")

    out = ledger.export_json()
    data = json.loads(out)
    assert len(data) == 3
    assert data[0]["type"] == "grant" and data[0]["user_id"] == "alice"
    assert data[0]["reason"] == "opt_in"
    assert "hash_prev" in data[0] and "hash_current" in data[0]

    out_alice = ledger.export_json(user_id="alice")
    data_alice = json.loads(out_alice)
    assert len(data_alice) == 2
    assert all(e["user_id"] == "alice" for e in data_alice)


def test_consent_manager_integration_writes_to_ledger(temp_ledger_path: str) -> None:
    """When ConsentManager is given a ledger, grant/revoke write to it."""
    ledger = ConsentLedger(path=temp_ledger_path)
    consent = ConsentManager(consent_ledger=ledger, ledger_user_id="app_user")
    consent.grant(ConsentScope.PROCESSING)
    consent.revoke(ConsentScope.PROCESSING)
    consent.grant_category("neural_signals")
    consent.revoke_category("neural_signals")

    history = ledger.history("app_user")
    assert len(history) == 4
    types = [e["type"] for e in history]
    assert types == ["grant", "revoke", "grant", "revoke"]
    assert ledger.verify_chain() is True


def test_consent_manager_without_ledger_unchanged() -> None:
    """ConsentManager without ledger still works; no ledger updates."""
    consent = ConsentManager()
    consent.grant(ConsentScope.EXPORT)
    consent.require_consent(ConsentScope.EXPORT)
    assert consent.has_consent(ConsentScope.EXPORT) is True
