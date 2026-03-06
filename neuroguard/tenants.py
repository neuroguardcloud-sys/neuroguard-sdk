"""
Persistent tenant registry for NeuroGuard.

Stores tenant records (tenant_id, name, created_at, is_active) in a JSON file.
Path: NEUROGUARD_TENANTS_PATH or ~/.neuroguard/tenants.json.
Set NEUROGUARD_TENANTS_PATH to "" to disable persistence.
Backward compatible: auth and other code still use tenant_id strings; registry is additive.
"""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

_store: dict[str, "TenantRecord"] = {}
_loaded = False

DEFAULT_TENANTS_DIR = Path.home() / ".neuroguard"
TENANTS_FILENAME = "tenants.json"
ENV_TENANTS_PATH = "NEUROGUARD_TENANTS_PATH"


def _get_persist_path() -> Optional[Path]:
    """Return path for JSON persistence, or None if disabled."""
    raw = os.environ.get(ENV_TENANTS_PATH)
    if raw is not None and (raw.strip() == "" or raw.strip().lower() == "0"):
        return None
    if raw and raw.strip():
        return Path(raw.strip())
    return DEFAULT_TENANTS_DIR / TENANTS_FILENAME


def _slug(s: str) -> str:
    """Safe slug from name for use in tenant_id prefix."""
    s = re.sub(r"[^a-z0-9]+", "-", s.lower().strip())
    return s.strip("-") or "tenant"


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
    for item in data.get("tenants", []):
        try:
            tenant_id = item.get("tenant_id")
            name = item.get("name")
            created_at = item.get("created_at")
            is_active = item.get("is_active", True)
            if not tenant_id or not name or not created_at:
                continue
            if isinstance(created_at, str):
                dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            else:
                continue
            _store[tenant_id] = TenantRecord(
                tenant_id=tenant_id,
                name=name,
                created_at=dt,
                is_active=bool(is_active),
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
        "tenants": [
            {
                "tenant_id": r.tenant_id,
                "name": r.name,
                "created_at": r.created_at.isoformat(),
                "is_active": r.is_active,
            }
            for r in _store.values()
        ]
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


@dataclass
class TenantRecord:
    """Single tenant record in the registry."""

    tenant_id: str
    name: str
    created_at: datetime
    is_active: bool = True

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "is_active": self.is_active,
        }


def create_tenant(name: str) -> TenantRecord:
    """Create a new tenant. Generates a unique tenant_id. Persists if enabled."""
    _ensure_loaded()
    base = _slug(name) or "tenant"
    while True:
        tid = f"{base}_{secrets.token_urlsafe(8)}"
        if tid not in _store:
            break
    now = datetime.now(timezone.utc)
    record = TenantRecord(tenant_id=tid, name=name.strip(), created_at=now, is_active=True)
    _store[tid] = record
    _save()
    return record


def list_tenants(active_only: bool = False) -> List[TenantRecord]:
    """List all tenants, optionally only active. Sorted by created_at."""
    _ensure_loaded()
    out = list(_store.values())
    if active_only:
        out = [r for r in out if r.is_active]
    return sorted(out, key=lambda r: r.created_at)


def get_tenant(tenant_id: str) -> Optional[TenantRecord]:
    """Return tenant by tenant_id or None."""
    _ensure_loaded()
    return _store.get(tenant_id)


def deactivate_tenant(tenant_id: str) -> bool:
    """Set tenant is_active to False. Returns True if tenant existed and was active."""
    _ensure_loaded()
    if tenant_id not in _store:
        return False
    record = _store[tenant_id]
    if not record.is_active:
        return False
    record.is_active = False
    _save()
    return True


def clear_store() -> None:
    """Clear all tenants (in-memory and on disk if persistence enabled). For tests."""
    global _loaded
    _store.clear()
    _loaded = True
    _save()


def reload_from_disk() -> None:
    """Force reload from disk on next access. For tests."""
    global _loaded
    _loaded = False
