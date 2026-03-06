"""Tests for subscription state (get, set, list, cancel, persistence)."""

import os
import tempfile
from datetime import datetime, timezone

import pytest

from neuroguard.subscriptions import (
    SubscriptionRecord,
    cancel_subscription,
    clear_store,
    get_subscription,
    list_subscriptions,
    reload_from_disk,
    set_subscription,
)


@pytest.fixture(autouse=True)
def isolate_subscriptions():
    os.environ["NEUROGUARD_SUBSCRIPTIONS_PATH"] = ""
    clear_store()
    yield
    clear_store()
    os.environ.pop("NEUROGUARD_SUBSCRIPTIONS_PATH", None)


def test_set_and_get_subscription() -> None:
    """set_subscription creates record; get_subscription returns it."""
    record = set_subscription("t1", "builder", "trial")
    assert isinstance(record, SubscriptionRecord)
    assert record.tenant_id == "t1"
    assert record.plan_name == "builder"
    assert record.status == "trial"
    assert record.started_at is not None
    found = get_subscription("t1")
    assert found is not None
    assert found.plan_name == "builder"
    assert get_subscription("unknown") is None


def test_set_subscription_with_dates() -> None:
    """set_subscription accepts optional started_at and renews_at."""
    started = datetime(2025, 1, 1, tzinfo=timezone.utc)
    renews = datetime(2025, 2, 1, tzinfo=timezone.utc)
    set_subscription("t1", "growth", "active", started_at=started, renews_at=renews)
    found = get_subscription("t1")
    assert found is not None
    assert found.started_at == started
    assert found.renews_at == renews


def test_set_subscription_invalid_status_raises() -> None:
    """set_subscription with invalid status raises ValueError."""
    with pytest.raises(ValueError):
        set_subscription("t1", "free", "invalid_status")


def test_list_subscriptions() -> None:
    """list_subscriptions returns all, sorted by started_at."""
    set_subscription("a", "free", "active")
    set_subscription("b", "builder", "trial")
    subs = list_subscriptions()
    assert len(subs) == 2
    assert subs[0].tenant_id in ("a", "b")
    assert subs[1].tenant_id in ("a", "b")


def test_cancel_subscription() -> None:
    """cancel_subscription sets status to canceled; returns True if subscription existed."""
    set_subscription("t1", "builder", "active")
    assert cancel_subscription("t1") is True
    found = get_subscription("t1")
    assert found is not None and found.status == "canceled"
    assert cancel_subscription("t1") is True  # idempotent
    assert cancel_subscription("unknown") is False


@pytest.fixture
def persisted_subs_path():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        os.environ["NEUROGUARD_SUBSCRIPTIONS_PATH"] = path
        yield path
    finally:
        os.environ.pop("NEUROGUARD_SUBSCRIPTIONS_PATH", None)
        if os.path.isfile(path):
            os.remove(path)


def test_persistence_across_reload(persisted_subs_path: str) -> None:
    """After set_subscription and cancel, reload_from_disk(); get and list reflect persisted state."""
    clear_store()
    set_subscription("p1", "growth", "active")
    set_subscription("p2", "builder", "trial")
    cancel_subscription("p2")
    reload_from_disk()
    found = get_subscription("p1")
    assert found is not None and found.status == "active"
    found2 = get_subscription("p2")
    assert found2 is not None and found2.status == "canceled"
    subs = list_subscriptions()
    assert len(subs) == 2
