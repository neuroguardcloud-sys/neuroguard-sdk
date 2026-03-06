"""
Managed API key storage for NeuroGuard.

In-memory store of API key records (key, tenant_id, created_at, is_active),
with optional JSON file persistence. Path: NEUROGUARD_API_KEYS_PATH or
~/.neuroguard/api_keys.json. Set NEUROGUARD_API_KEYS_PATH to "" to disable persistence.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# In-process store: key -> record (shared across requests)
_store: dict[str, "ApiKeyRecord"] = {}
_loaded = False

DEFAULT_KEYS_DIR = Path.home() / ".neuroguard"
API_KEYS_FILENAME = "api_keys.json"
ENV_API_KEYS_PATH = "NEUROGUARD_API_KEYS_PATH"


def _get_persist_path() -> Optional[Path]:
    """Return path for JSON persistence, or None if persistence is disabled."""
    raw = os.environ.get(ENV_API_KEYS_PATH)
    if raw is not None and (raw.strip() == "" or raw.strip().lower() == "0"):
        return None
    if raw and raw.strip():
        return Path(raw.strip())
    return DEFAULT_KEYS_DIR / API_KEYS_FILENAME


def _ensure_loaded() -> None:
    """Load from disk on first use (lazy)."""
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
    for item in data.get("keys", []):
        try:
            key = item.get("key")
            tenant_id = item.get("tenant_id")
            created_at = item.get("created_at")
            is_active = item.get("is_active", True)
            if not key or not tenant_id or not created_at:
                continue
            if isinstance(created_at, str):
                dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            else:
                continue
            _store[key] = ApiKeyRecord(
                key=key,
                tenant_id=tenant_id,
                created_at=dt,
                is_active=bool(is_active),
            )
        except (ValueError, TypeError):
            continue
    _loaded = True


def _save() -> None:
    """Write current store to disk (if persistence enabled)."""
    path = _get_persist_path()
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "keys": [
            {
                "key": r.key,
                "tenant_id": r.tenant_id,
                "created_at": r.created_at.isoformat(),
                "is_active": r.is_active,
            }
            for r in _store.values()
        ]
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


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
    _ensure_loaded()
    raw = secrets.token_urlsafe(32)
    key = f"ng_{raw}"
    now = datetime.now(timezone.utc)
    record = ApiKeyRecord(key=key, tenant_id=tenant_id, created_at=now, is_active=True)
    _store[key] = record
    _save()
    return record


def list_keys(tenant_id: Optional[str] = None) -> List[ApiKeyRecord]:
    """List all active keys, optionally filtered by tenant_id."""
    _ensure_loaded()
    out = [r for r in _store.values() if r.is_active]
    if tenant_id is not None:
        out = [r for r in out if r.tenant_id == tenant_id]
    return sorted(out, key=lambda r: r.created_at)


def revoke_key(key: str) -> bool:
    """Mark key as inactive. Returns True if key existed and was active."""
    _ensure_loaded()
    if key not in _store:
        return False
    record = _store[key]
    if not record.is_active:
        return False
    record.is_active = False
    _save()
    return True


def validate_key(key: Optional[str]) -> Optional[str]:
    """
    If key exists in managed store and is active, return its tenant_id.
    Otherwise return None (caller may fall back to env keys).
    """
    _ensure_loaded()
    if not key or key not in _store:
        return None
    record = _store[key]
    if not record.is_active:
        return None
    return record.tenant_id


def has_any_keys() -> bool:
    """True if the managed store has at least one key (any status)."""
    _ensure_loaded()
    return len(_store) > 0


def clear_store() -> None:
    """Clear all managed keys (in-memory and on disk if persistence enabled). For tests."""
    global _loaded
    _store.clear()
    _loaded = True
    _save()


def reload_from_disk() -> None:
    """Force reload from disk on next access. Used for tests to simulate process restart."""
    global _loaded
    _loaded = False
