"""Tests for usage metering (increment, get, list, persistence, default tenant)."""

import os
import tempfile

import pytest

from neuroguard.usage_meter import (
    DEFAULT_TENANT,
    METRICS,
    clear_store,
    get_usage,
    increment_usage,
    list_usage,
    reload_from_disk,
)


@pytest.fixture(autouse=True)
def isolate_usage():
    """Disable persistence and clear store for each test."""
    os.environ["NEUROGUARD_USAGE_PATH"] = ""
    clear_store()
    yield
    clear_store()
    os.environ.pop("NEUROGUARD_USAGE_PATH", None)


def test_increment_usage_per_tenant_and_metric() -> None:
    """increment_usage(tenant_id, metric) increases the counter; get_usage returns it."""
    increment_usage("tenant-a", "vault_store")
    increment_usage("tenant-a", "vault_store")
    increment_usage("tenant-a", "dashboard_view")
    u = get_usage("tenant-a")
    assert u["vault_store"] == 2
    assert u["dashboard_view"] == 1
    assert u["vault_retrieve"] == 0
    for m in METRICS:
        assert m in u


def test_get_usage_unknown_tenant_returns_zeros() -> None:
    """get_usage(unknown_tenant) returns all metrics as 0."""
    u = get_usage("nonexistent")
    assert all(u[m] == 0 for m in METRICS)


def test_list_usage_returns_all_tenants() -> None:
    """list_usage() returns usage per tenant."""
    increment_usage("t1", "vault_store")
    increment_usage("t1", "security_check")
    increment_usage("t2", "dashboard_view")
    out = list_usage()
    assert "t1" in out
    assert "t2" in out
    assert out["t1"]["vault_store"] == 1
    assert out["t1"]["security_check"] == 1
    assert out["t2"]["dashboard_view"] == 1


def test_none_or_empty_tenant_normalizes_to_default() -> None:
    """increment_usage(None) and increment_usage('') use tenant_id default."""
    increment_usage(None, "lineage_export")
    increment_usage("", "security_check")
    u = get_usage(DEFAULT_TENANT)
    assert u["lineage_export"] == 1
    assert u["security_check"] == 1
    out = list_usage()
    assert DEFAULT_TENANT in out


def test_unknown_metric_ignored() -> None:
    """increment_usage with unknown metric does not crash; counter not stored."""
    increment_usage("t", "unknown_metric")
    u = get_usage("t")
    assert "unknown_metric" not in u or u.get("unknown_metric", 0) == 0


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


@pytest.fixture
def persisted_usage_path():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        os.environ["NEUROGUARD_USAGE_PATH"] = path
        yield path
    finally:
        os.environ.pop("NEUROGUARD_USAGE_PATH", None)
        if os.path.isfile(path):
            os.remove(path)


def test_persistence_across_reload(persisted_usage_path: str) -> None:
    """After increment_usage, reload_from_disk(); get_usage and list_usage reflect persisted state."""
    clear_store()
    increment_usage("persisted-tenant", "vault_store")
    increment_usage("persisted-tenant", "vault_store")
    increment_usage("persisted-tenant", "dashboard_export")
    reload_from_disk()
    u = get_usage("persisted-tenant")
    assert u["vault_store"] == 2
    assert u["dashboard_export"] == 1
    out = list_usage()
    assert "persisted-tenant" in out
    assert out["persisted-tenant"]["vault_store"] == 2


def test_list_usage_after_reload(persisted_usage_path: str) -> None:
    """Multiple tenants and metrics persist and survive reload."""
    clear_store()
    increment_usage("a", "vault_store")
    increment_usage("a", "vault_retrieve")
    increment_usage("b", "dashboard_view")
    reload_from_disk()
    out = list_usage()
    assert len(out) == 2
    assert out["a"]["vault_store"] == 1
    assert out["a"]["vault_retrieve"] == 1
    assert out["b"]["dashboard_view"] == 1
