"""
Managed API key storage for NeuroGuard.

In-memory store of API key records (key, tenant_id, created_at, is_active).
Used alongside env-var keys for validation; supports create, list, revoke.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

# In-process store: key -> record (shared across requests)
_store: dict[str, "ApiKeyRecord"] = {}


@dataclass
class ApiKeyRecord:
    """Single API key record for managed keys."""

    key: str
    tenant_id: str
    created_at: datetime
    is_active: bool = True

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at.isoformat(),
            "is_active": self.is_active,
        }


def create_key(tenant_id: str) -> ApiKeyRecord:
    """Create a new API key for the given tenant. Returns the record (key shown once)."""
    raw = secrets.token_urlsafe(32)
    key = f"ng_{raw}"
    now = datetime.now(timezone.utc)
    record = ApiKeyRecord(key=key, tenant_id=tenant_id, created_at=now, is_active=True)
    _store[key] = record
    return record


def list_keys(tenant_id: Optional[str] = None) -> List[ApiKeyRecord]:
    """List all active keys, optionally filtered by tenant_id."""
    out = [r for r in _store.values() if r.is_active]
    if tenant_id is not None:
        out = [r for r in out if r.tenant_id == tenant_id]
    return sorted(out, key=lambda r: r.created_at)


def revoke_key(key: str) -> bool:
    """Mark key as inactive. Returns True if key existed and was active."""
    if key not in _store:
        return False
    record = _store[key]
    if not record.is_active:
        return False
    record.is_active = False
    return True


def validate_key(key: Optional[str]) -> Optional[str]:
    """
    If key exists in managed store and is active, return its tenant_id.
    Otherwise return None (caller may fall back to env keys).
    """
    if not key or key not in _store:
        return None
    record = _store[key]
    if not record.is_active:
        return None
    return record.tenant_id


def has_any_keys() -> bool:
    """True if the managed store has at least one key (any status)."""
    return len(_store) > 0


def clear_store() -> None:
    """Clear all managed keys (for tests)."""
    _store.clear()
