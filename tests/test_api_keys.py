"""Tests for managed API key module (create, list, revoke, validate)."""

import pytest

from neuroguard.api_keys import (
    ApiKeyRecord,
    clear_store,
    create_key,
    has_any_keys,
    list_keys,
    revoke_key,
    validate_key,
)


@pytest.fixture(autouse=True)
def clear_before_after():
    """Isolate tests: clear managed key store before and after each test."""
    clear_store()
    yield
    clear_store()


def test_create_key_returns_record_with_expected_fields() -> None:
    """create_key(tenant_id) returns ApiKeyRecord with key, tenant_id, created_at, is_active."""
    record = create_key("tenant-a")
    assert isinstance(record, ApiKeyRecord)
    assert record.key.startswith("ng_")
    assert len(record.key) > 10
    assert record.tenant_id == "tenant-a"
    assert record.is_active is True
    assert record.created_at is not None


def test_list_keys_empty_then_after_create() -> None:
    """list_keys() returns empty list initially; after create_key returns that key."""
    assert list_keys() == []
    r1 = create_key("t1")
    keys = list_keys()
    assert len(keys) == 1
    assert keys[0].key == r1.key
    assert keys[0].tenant_id == "t1"
    r2 = create_key("t1")
    assert len(list_keys()) == 2
    assert len(list_keys(tenant_id="t1")) == 2
    assert len(list_keys(tenant_id="t2")) == 0
    create_key("t2")
    assert len(list_keys(tenant_id="t2")) == 1


def test_revoke_key_deactivates_key() -> None:
    """revoke_key(key) marks key inactive; returns True; second revoke returns False."""
    record = create_key("tenant-x")
    assert validate_key(record.key) == "tenant-x"
    assert revoke_key(record.key) is True
    assert validate_key(record.key) is None
    assert revoke_key(record.key) is False
    assert list_keys() == []


def test_revoke_key_unknown_returns_false() -> None:
    """revoke_key(unknown_key) returns False."""
    assert revoke_key("nonexistent") is False


def test_validate_key_active_returns_tenant_id() -> None:
    """validate_key(active_key) returns tenant_id."""
    record = create_key("my-tenant")
    assert validate_key(record.key) == "my-tenant"
    assert validate_key(None) is None
    assert validate_key("random") is None


def test_validate_key_revoked_returns_none() -> None:
    """validate_key(revoked_key) returns None."""
    record = create_key("t")
    revoke_key(record.key)
    assert validate_key(record.key) is None


def test_has_any_keys() -> None:
    """has_any_keys() is False when empty, True after create, still True after revoke."""
    assert has_any_keys() is False
    record = create_key("t")
    assert has_any_keys() is True
    revoke_key(record.key)
    assert has_any_keys() is True
