"""
Plan enforcement for NeuroGuard.

Built-in plans (free, builder, growth) define per-metric limits. Tenant-to-plan mapping
persisted to JSON. check_limit(tenant_id, metric) consults usage and plan to return
allowed, remaining, reason. Use tenant_id="default" when no tenant context; default plan is free.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from neuroguard.usage_meter import METRICS, get_usage

DEFAULT_TENANT = "default"
DEFAULT_PLAN = "free"

# Built-in plan names and limits (-1 = unlimited)
PLAN_LIMITS: Dict[str, Dict[str, int]] = {
    "free": {
        "vault_store": 100,
        "vault_retrieve": 100,
        "dashboard_view": 10,
        "dashboard_export": 5,
        "lineage_export": 20,
        "security_check": 100,
    },
    "builder": {
        "vault_store": 10_000,
        "vault_retrieve": 10_000,
        "dashboard_view": 1_000,
        "dashboard_export": 500,
        "lineage_export": 1_000,
        "security_check": 10_000,
    },
    "growth": {
        "vault_store": -1,
        "vault_retrieve": -1,
        "dashboard_view": -1,
        "dashboard_export": -1,
        "lineage_export": -1,
        "security_check": -1,
    },
}

_store: Dict[str, str] = {}  # tenant_id -> plan_name
_loaded = False

DEFAULT_PLANS_DIR = Path.home() / ".neuroguard"
PLANS_FILENAME = "tenant_plans.json"
ENV_PLANS_PATH = "NEUROGUARD_PLANS_PATH"


def _get_persist_path() -> Optional[Path]:
    raw = os.environ.get(ENV_PLANS_PATH)
    if raw is not None and (raw.strip() == "" or raw.strip().lower() == "0"):
        return None
    if raw and raw.strip():
        return Path(raw.strip())
    return DEFAULT_PLANS_DIR / PLANS_FILENAME


def _ensure_loaded() -> None:
    global _loaded
    if _loaded:
        return
    path = _get_persist_path()
    if path is None or not path.exists():
        _loaded = True
        return
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        _loaded = True
        return
    _store.clear()
    for tid, plan in data.get("tenant_plans", {}).items():
        if isinstance(tid, str) and isinstance(plan, str) and plan in PLAN_LIMITS:
            _store[tid] = plan
    _loaded = True


def _save() -> None:
    path = _get_persist_path()
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"tenant_plans": _store}, f, indent=2)


def _normalize_tenant(tenant_id: Optional[str]) -> str:
    return (tenant_id or "").strip() or DEFAULT_TENANT


def get_plan(tenant_id: Optional[str]) -> str:
    """Return the plan name for the tenant. Default is free."""
    _ensure_loaded()
    tid = _normalize_tenant(tenant_id)
    return _store.get(tid, DEFAULT_PLAN)


def set_plan(tenant_id: str, plan_name: str) -> bool:
    """Assign a plan to a tenant. Returns False if plan_name is unknown."""
    _ensure_loaded()
    if plan_name not in PLAN_LIMITS:
        return False
    _store[_normalize_tenant(tenant_id)] = plan_name
    _save()
    return True


def check_limit(tenant_id: Optional[str], metric: str) -> Tuple[bool, int, str]:
    """
    Check if the tenant is within plan limit for the metric.
    Returns (allowed, remaining, reason). remaining is -1 when unlimited.
    """
    _ensure_loaded()
    tid = _normalize_tenant(tenant_id)
    if metric not in METRICS:
        return True, -1, "OK"
    plan_name = get_plan(tid)
    limits = PLAN_LIMITS.get(plan_name, PLAN_LIMITS[DEFAULT_PLAN])
    limit = limits.get(metric, -1)
    if limit < 0:
        return True, -1, "OK"
    usage = get_usage(tid)
    current = usage.get(metric, 0)
    remaining = limit - current
    if remaining <= 0:
        return False, 0, f"Plan limit exceeded for {metric} (limit={limit})"
    return True, remaining, "OK"


def list_plan_definitions() -> Dict[str, Dict[str, int]]:
    """Return built-in plan names and their limits."""
    return dict(PLAN_LIMITS)


def clear_store() -> None:
    """Clear tenant->plan mapping (for tests)."""
    global _loaded
    _store.clear()
    _loaded = True
    _save()


def reload_from_disk() -> None:
    """Force reload from disk on next access (for tests)."""
    global _loaded
    _loaded = False
