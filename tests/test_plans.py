"""Tests for plan enforcement (get_plan, set_plan, check_limit, default, over-limit)."""

import os

import pytest

from neuroguard.plans import (
    DEFAULT_PLAN,
    PLAN_LIMITS,
    check_limit,
    clear_store,
    get_effective_plan,
    get_plan,
    list_plan_definitions,
    set_plan,
)
from neuroguard.usage_meter import clear_store as clear_usage_store, increment_usage
from neuroguard.subscriptions import cancel_subscription, clear_store as clear_subs_store, set_subscription


@pytest.fixture(autouse=True)
def isolate_plans():
    os.environ["NEUROGUARD_PLANS_PATH"] = ""
    os.environ["NEUROGUARD_SUBSCRIPTIONS_PATH"] = ""
    clear_store()
    clear_usage_store()
    clear_subs_store()
    yield
    clear_store()
    clear_subs_store()
    os.environ.pop("NEUROGUARD_PLANS_PATH", None)
    os.environ.pop("NEUROGUARD_SUBSCRIPTIONS_PATH", None)


def test_default_plan_is_free() -> None:
    """Unknown tenant has plan free."""
    assert get_plan("any-tenant") == "free"
    assert get_plan(None) == "free"
    assert get_plan("") == "free"


def test_set_plan_and_get_plan() -> None:
    """set_plan(tenant_id, plan_name) persists; get_plan returns it."""
    assert set_plan("t1", "builder") is True
    assert get_plan("t1") == "builder"
    assert set_plan("t2", "growth") is True
    assert get_plan("t2") == "growth"
    assert set_plan("t3", "unknown") is False
    assert get_plan("t3") == "free"


def test_check_limit_under_limit() -> None:
    """check_limit returns allowed=True when under limit."""
    increment_usage("t1", "dashboard_view")
    increment_usage("t1", "dashboard_view")
    allowed, remaining, reason = check_limit("t1", "dashboard_view")
    assert allowed is True
    assert remaining == 10 - 2  # free plan dashboard_view 10
    assert reason == "OK"


def test_check_limit_at_and_over_limit() -> None:
    """check_limit returns allowed=False when at or over limit."""
    for _ in range(10):
        increment_usage("t1", "dashboard_view")
    allowed, remaining, reason = check_limit("t1", "dashboard_view")
    assert allowed is False
    assert remaining == 0
    assert "limit" in reason.lower()


def test_check_limit_unlimited_plan() -> None:
    """With growth plan, check_limit always allows and remaining=-1."""
    set_plan("t1", "growth")
    for _ in range(100):
        increment_usage("t1", "dashboard_export")
    allowed, remaining, reason = check_limit("t1", "dashboard_export")
    assert allowed is True
    assert remaining == -1
    assert reason == "OK"


def test_plan_change_affects_access() -> None:
    """After exceeding free limit, set_plan to growth allows access again."""
    for _ in range(10):
        increment_usage("t1", "dashboard_view")
    allowed, _, _ = check_limit("t1", "dashboard_view")
    assert allowed is False
    set_plan("t1", "growth")
    allowed2, _, _ = check_limit("t1", "dashboard_view")
    assert allowed2 is True


def test_list_plan_definitions() -> None:
    """list_plan_definitions returns built-in plans with limits."""
    plans = list_plan_definitions()
    assert "free" in plans
    assert "builder" in plans
    assert "growth" in plans
    assert plans["free"]["dashboard_view"] == 10
    assert plans["growth"]["vault_store"] == -1


def test_get_effective_plan_no_subscription_uses_assigned_plan() -> None:
    """When no subscription exists, effective plan is the assigned plan."""
    set_plan("t1", "builder")
    effective, status, warning = get_effective_plan("t1")
    assert effective == "builder"
    assert status is None
    assert warning is None


def test_get_effective_plan_canceled_downgrades_to_free() -> None:
    """When subscription is canceled, effective plan is free."""
    set_plan("t1", "growth")
    set_subscription("t1", "growth", "active")
    cancel_subscription("t1")
    effective, status, warning = get_effective_plan("t1")
    assert effective == "free"
    assert status == "canceled"
    assert warning is None


def test_get_effective_plan_past_due_preserves_plan_sets_warning() -> None:
    """When subscription is past_due, effective plan unchanged and warning set."""
    set_plan("t1", "builder")
    set_subscription("t1", "builder", "past_due")
    effective, status, warning = get_effective_plan("t1")
    assert effective == "builder"
    assert status == "past_due"
    assert warning == "Subscription past due"


def test_check_limit_uses_effective_plan_after_cancel() -> None:
    """check_limit uses free limits when subscription is canceled."""
    set_plan("t1", "growth")
    set_subscription("t1", "growth", "active")
    for _ in range(11):
        increment_usage("t1", "dashboard_view")
    allowed, _, _ = check_limit("t1", "dashboard_view")
    assert allowed is True  # growth unlimited
    cancel_subscription("t1")
    allowed2, remaining, _ = check_limit("t1", "dashboard_view")
    assert allowed2 is False
    assert remaining == 0
