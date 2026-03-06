"""
Lightweight API key and tenant foundation for NeuroGuard.

When no API keys are configured (env empty), protected routes remain open for local dev.
When NEUROGUARD_API_KEYS is set, X-API-Key must be valid on protected routes.
"""

from __future__ import annotations

import os
from typing import Optional, Set

from fastapi import Header, HTTPException

DEFAULT_TENANT = "default"
ENV_API_KEYS = "NEUROGUARD_API_KEYS"


def get_configured_api_keys() -> Set[str]:
    """Return set of valid API keys from env (comma-separated). Empty = auth off."""
    raw = os.environ.get(ENV_API_KEYS, "").strip()
    if not raw:
        return set()
    return {k.strip() for k in raw.split(",") if k.strip()}


def validate_api_key(key: Optional[str]) -> Optional[str]:
    """
    If key is valid, return tenant_id (derived from key; here we use the key as tenant).
    If keys not configured, return DEFAULT_TENANT for any key or None.
    If keys configured and key invalid/missing, return None.
    """
    configured = get_configured_api_keys()
    if not configured:
        return DEFAULT_TENANT
    if not key or key not in configured:
        return None
    return key


def require_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> str:
    """
    FastAPI dependency: validate X-API-Key header.
    When no keys configured, returns DEFAULT_TENANT (no header required).
    When keys configured: missing or invalid key raises 401; valid key returns tenant_id.
    """
    tenant = validate_api_key(x_api_key)
    if tenant is None:
        raise HTTPException(status_code=401, detail="Missing or invalid API key")
    return tenant
