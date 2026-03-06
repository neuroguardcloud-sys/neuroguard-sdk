"""
Subscription state per tenant for NeuroGuard.

Lightweight subscription layer: tenant_id, plan_name, status (trial, active, past_due, canceled),
started_at, renews_at. Persisted to JSON. If no subscription exists, existing plan logic is unchanged.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

STATUSES = ("trial", "active", "past_due", "canceled")

_store: dict[str, "SubscriptionRecord"] = {}
_loaded = False

DEFAULT_SUBS_DIR = Path.home() / ".neuroguard"
SUBS_FILENAME = "subscriptions.json"
ENV_SUBS_PATH = "NEUROGUARD_SUBSCRIPTIONS_PATH"


def _get_persist_path() -> Optional[Path]:
    raw = os.environ.get(ENV_SUBS_PATH)
    if raw is not None and (raw.strip() == "" or raw.strip().lower() == "0"):
        return None
    if raw and raw.strip():
        return Path(raw.strip())
    return DEFAULT_SUBS_DIR / SUBS_FILENAME


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
    for item in data.get("subscriptions", []):
        try:
            tenant_id = item.get("tenant_id")
            plan_name = item.get("plan_name")
            status = item.get("status")
            started_at = item.get("started_at")
            renews_at = item.get("renews_at")
            if not tenant_id or not plan_name or status not in STATUSES:
                continue
            if isinstance(started_at, str):
                dt_start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            else:
                continue
            dt_renews: Optional[datetime] = None
            if renews_at is not None and isinstance(renews_at, str):
                dt_renews = datetime.fromisoformat(renews_at.replace("Z", "+00:00"))
            _store[tenant_id] = SubscriptionRecord(
                tenant_id=tenant_id,
                plan_name=plan_name,
                status=status,
                started_at=dt_start,
                renews_at=dt_renews,
            )
        except (ValueError, TypeError):
            continue
    _loaded = True


def _save() -> None:
    path = _get_persist_path()
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "subscriptions": [
            {
                "tenant_id": r.tenant_id,
                "plan_name": r.plan_name,
                "status": r.status,
                "started_at": r.started_at.isoformat(),
                "renews_at": r.renews_at.isoformat() if r.renews_at else None,
            }
            for r in _store.values()
        ]
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


@dataclass
class SubscriptionRecord:
    """Subscription state for one tenant."""

    tenant_id: str
    plan_name: str
    status: str  # trial | active | past_due | canceled
    started_at: datetime
    renews_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "plan_name": self.plan_name,
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "renews_at": self.renews_at.isoformat() if self.renews_at else None,
        }


def get_subscription(tenant_id: str) -> Optional[SubscriptionRecord]:
    """Return subscription for tenant or None."""
    _ensure_loaded()
    return _store.get(tenant_id)


def set_subscription(
    tenant_id: str,
    plan_name: str,
    status: str,
    started_at: Optional[datetime] = None,
    renews_at: Optional[datetime] = None,
) -> SubscriptionRecord:
    """Create or update subscription. If started_at is None, set to now. status must be in STATUSES."""
    _ensure_loaded()
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    now = datetime.now(timezone.utc)
    started = started_at if started_at is not None else now
    record = SubscriptionRecord(
        tenant_id=tenant_id,
        plan_name=plan_name,
        status=status,
        started_at=started,
        renews_at=renews_at,
    )
    _store[tenant_id] = record
    _save()
    return record


def list_subscriptions() -> List[SubscriptionRecord]:
    """Return all subscriptions, sorted by started_at."""
    _ensure_loaded()
    return sorted(_store.values(), key=lambda r: r.started_at)


def cancel_subscription(tenant_id: str) -> bool:
    """Set subscription status to canceled. Returns True if subscription existed."""
    _ensure_loaded()
    if tenant_id not in _store:
        return False
    _store[tenant_id].status = "canceled"
    _save()
    return True


def clear_store() -> None:
    """Clear all subscriptions (for tests)."""
    global _loaded
    _store.clear()
    _loaded = True
    _save()


def reload_from_disk() -> None:
    """Force reload from disk on next access (for tests)."""
    global _loaded
    _loaded = False
