"""Tests for tenant registry (create, list, get, deactivate, persistence)."""

import os
import tempfile

import pytest

from neuroguard.tenants import (
    TenantRecord,
    clear_store,
    create_tenant,
    deactivate_tenant,
    get_tenant,
    list_tenants,
    reload_from_disk,
)


@pytest.fixture(autouse=True)
def isolate_tenants():
    """Disable persistence and clear store for each test."""
    os.environ["NEUROGUARD_TENANTS_PATH"] = ""
    clear_store()
    yield
    clear_store()
    os.environ.pop("NEUROGUARD_TENANTS_PATH", None)


def test_create_tenant_returns_record_with_expected_fields() -> None:
    """create_tenant(name) returns TenantRecord with tenant_id, name, created_at, is_active."""
    record = create_tenant("Acme Corp")
    assert isinstance(record, TenantRecord)
    assert record.tenant_id.startswith("acme-corp_")
    assert len(record.tenant_id) > 12
    assert record.name == "Acme Corp"
    assert record.is_active is True
    assert record.created_at is not None


def test_list_tenants_empty_then_after_create() -> None:
    """list_tenants() returns empty initially; after create returns that tenant."""
    assert list_tenants() == []
    t1 = create_tenant("First")
    tenants = list_tenants()
    assert len(tenants) == 1
    assert tenants[0].tenant_id == t1.tenant_id
    assert tenants[0].name == "First"
    t2 = create_tenant("Second")
    assert len(list_tenants()) == 2
    assert len(list_tenants(active_only=True)) == 2
    deactivate_tenant(t1.tenant_id)
    assert len(list_tenants(active_only=True)) == 1
    assert len(list_tenants(active_only=False)) == 2


def test_get_tenant() -> None:
    """get_tenant(tenant_id) returns record or None."""
    t = create_tenant("Lookup Me")
    found = get_tenant(t.tenant_id)
    assert found is not None
    assert found.name == "Lookup Me"
    assert get_tenant("nonexistent") is None


def test_deactivate_tenant() -> None:
    """deactivate_tenant(tenant_id) sets is_active False; returns True; second call returns False."""
    t = create_tenant("To Deactivate")
    assert t.is_active is True
    assert deactivate_tenant(t.tenant_id) is True
    found = get_tenant(t.tenant_id)
    assert found is not None and found.is_active is False
    assert deactivate_tenant(t.tenant_id) is False
    assert deactivate_tenant("nonexistent") is False


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


@pytest.fixture
def persisted_tenants_path():
    """Temp path for tenants JSON; persistence enabled."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        os.environ["NEUROGUARD_TENANTS_PATH"] = path
        yield path
    finally:
        os.environ.pop("NEUROGUARD_TENANTS_PATH", None)
        if os.path.isfile(path):
            os.remove(path)


def test_persistence_across_reload(persisted_tenants_path: str) -> None:
    """After create_tenant and deactivate_tenant, reload_from_disk(); list/get reflect persisted state."""
    clear_store()
    t1 = create_tenant("Alpha")
    t2 = create_tenant("Beta")
    deactivate_tenant(t1.tenant_id)
    reload_from_disk()
    tenants = list_tenants(active_only=False)
    assert len(tenants) == 2
    active = list_tenants(active_only=True)
    assert len(active) == 1
    assert active[0].tenant_id == t2.tenant_id
    assert get_tenant(t1.tenant_id) is not None
    assert get_tenant(t1.tenant_id).is_active is False
    assert get_tenant(t2.tenant_id).is_active is True


def test_deactivated_stays_deactivated_after_reload(persisted_tenants_path: str) -> None:
    """Deactivated tenant is still inactive after reload_from_disk()."""
    clear_store()
    t = create_tenant("Deact")
    deactivate_tenant(t.tenant_id)
    reload_from_disk()
    found = get_tenant(t.tenant_id)
    assert found is not None and found.is_active is False
    assert len(list_tenants(active_only=True)) == 0


def test_list_tenants_after_reload(persisted_tenants_path: str) -> None:
    """Create several tenants, reload, list_tenants returns same set."""
    clear_store()
    create_tenant("A")
    create_tenant("B")
    t3 = create_tenant("C")
    deactivate_tenant(t3.tenant_id)
    reload_from_disk()
    all_tenants = list_tenants(active_only=False)
    assert len(all_tenants) == 3
    active = list_tenants(active_only=True)
    assert len(active) == 2
