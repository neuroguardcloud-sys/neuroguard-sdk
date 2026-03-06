"""
Per-tenant usage metering for NeuroGuard.

Persistent counters per tenant_id for vault_store, vault_retrieve, dashboard_view,
dashboard_export, lineage_export, security_check. JSON file at NEUROGUARD_USAGE_PATH
or ~/.neuroguard/usage.json. Set to "" to disable persistence.
Use tenant_id="default" when no tenant context exists.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

DEFAULT_TENANT = "default"
METRICS = ("vault_store", "vault_retrieve", "dashboard_view", "dashboard_export", "lineage_export", "security_check")

_store: Dict[str, Dict[str, int]] = {}  # tenant_id -> { metric -> count }
_loaded = False

DEFAULT_USAGE_DIR = Path.home() / ".neuroguard"
USAGE_FILENAME = "usage.json"
ENV_USAGE_PATH = "NEUROGUARD_USAGE_PATH"


def _get_persist_path() -> Optional[Path]:
    raw = os.environ.get(ENV_USAGE_PATH)
    if raw is not None and (raw.strip() == "" or raw.strip().lower() == "0"):
        return None
    if raw and raw.strip():
        return Path(raw.strip())
    return DEFAULT_USAGE_DIR / USAGE_FILENAME


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
    for tid, metrics in data.get("usage", {}).items():
        if not isinstance(metrics, dict):
            continue
        _store[tid] = {m: int(v) for m, v in metrics.items() if m in METRICS and isinstance(v, (int, float))}
    _loaded = True


def _save() -> None:
    path = _get_persist_path()
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"usage": _store}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _normalize_tenant(tenant_id: Optional[str]) -> str:
    return (tenant_id or "").strip() or DEFAULT_TENANT


def increment_usage(tenant_id: Optional[str], metric: str) -> None:
    """Increment the counter for (tenant_id, metric). Persists if enabled."""
    _ensure_loaded()
    tid = _normalize_tenant(tenant_id)
    if metric not in METRICS:
        return
    if tid not in _store:
        _store[tid] = {m: 0 for m in METRICS}
    _store[tid][metric] = _store[tid].get(metric, 0) + 1
    _save()


def get_usage(tenant_id: Optional[str]) -> Dict[str, int]:
    """Return all metric counts for the tenant. Missing metrics are 0."""
    _ensure_loaded()
    tid = _normalize_tenant(tenant_id)
    base = {m: 0 for m in METRICS}
    if tid in _store:
        for m, v in _store[tid].items():
            if m in METRICS:
                base[m] = v
    return base


def list_usage() -> Dict[str, Dict[str, int]]:
    """Return usage for all tenants: { tenant_id -> { metric -> count } }."""
    _ensure_loaded()
    out = {}
    for tid, metrics in _store.items():
        out[tid] = {m: metrics.get(m, 0) for m in METRICS}
    return out


def clear_store() -> None:
    """Clear all usage (in-memory and on disk if enabled). For tests."""
    global _loaded
    _store.clear()
    _loaded = True
    _save()


def reload_from_disk() -> None:
    """Force reload from disk on next access. For tests."""
    global _loaded
    _loaded = False
