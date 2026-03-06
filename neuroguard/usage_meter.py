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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_TENANT = "default"
METRICS = ("vault_store", "vault_retrieve", "dashboard_view", "dashboard_export", "lineage_export", "security_check")

_store: Dict[str, Dict[str, int]] = {}  # tenant_id -> { metric -> count }
_events: List[Dict[str, Any]] = []  # [{ "tenant_id", "metric", "timestamp" }]
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
    _events.clear()
    for ev in data.get("events", []):
        if isinstance(ev, dict) and ev.get("tenant_id") is not None and ev.get("metric") in METRICS and ev.get("timestamp"):
            _events.append({"tenant_id": str(ev["tenant_id"]), "metric": ev["metric"], "timestamp": str(ev["timestamp"])})
    _loaded = True


def _save() -> None:
    path = _get_persist_path()
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"usage": _store, "events": _events}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _normalize_tenant(tenant_id: Optional[str]) -> str:
    return (tenant_id or "").strip() or DEFAULT_TENANT


def increment_usage(tenant_id: Optional[str], metric: str) -> None:
    """Increment the counter for (tenant_id, metric) and record a timestamped event. Persists if enabled."""
    _ensure_loaded()
    tid = _normalize_tenant(tenant_id)
    if metric not in METRICS:
        return
    if tid not in _store:
        _store[tid] = {m: 0 for m in METRICS}
    _store[tid][metric] = _store[tid].get(metric, 0) + 1
    _events.append({
        "tenant_id": tid,
        "metric": metric,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
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


def get_usage_by_day(tenant_id: Optional[str]) -> Dict[str, Dict[str, int]]:
    """Return usage for the tenant aggregated by day. Keys are YYYY-MM-DD, values are { metric -> count }."""
    _ensure_loaded()
    tid = _normalize_tenant(tenant_id)
    by_day: Dict[str, Dict[str, int]] = {}
    for ev in _events:
        if ev.get("tenant_id") != tid:
            continue
        ts = ev.get("timestamp", "")
        day = ts[:10] if len(ts) >= 10 else ""
        if not day:
            continue
        if day not in by_day:
            by_day[day] = {m: 0 for m in METRICS}
        m = ev.get("metric")
        if m in METRICS:
            by_day[day][m] = by_day[day].get(m, 0) + 1
    return by_day


def get_usage_by_month(tenant_id: Optional[str]) -> Dict[str, Dict[str, int]]:
    """Return usage for the tenant aggregated by month. Keys are YYYY-MM, values are { metric -> count }."""
    _ensure_loaded()
    tid = _normalize_tenant(tenant_id)
    by_month: Dict[str, Dict[str, int]] = {}
    for ev in _events:
        if ev.get("tenant_id") != tid:
            continue
        ts = ev.get("timestamp", "")
        month = ts[:7] if len(ts) >= 7 else ""
        if not month:
            continue
        if month not in by_month:
            by_month[month] = {m: 0 for m in METRICS}
        m = ev.get("metric")
        if m in METRICS:
            by_month[month][m] = by_month[month].get(m, 0) + 1
    return by_month


def clear_store() -> None:
    """Clear all usage and events (in-memory and on disk if enabled). For tests."""
    global _loaded
    _store.clear()
    _events.clear()
    _loaded = True
    _save()


def reload_from_disk() -> None:
    """Force reload from disk on next access. For tests."""
    global _loaded
    _loaded = False
