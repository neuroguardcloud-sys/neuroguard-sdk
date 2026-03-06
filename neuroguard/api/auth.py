"""
Lightweight API key and tenant foundation for NeuroGuard.

When no API keys are configured (env empty and no managed keys), protected routes
remain open for local dev. Valid keys can come from managed store or NEUROGUARD_API_KEYS.
"""

from __future__ import annotations

import os
from typing import Optional, Set

from fastapi import Header, HTTPException

from neuroguard.api_keys import has_any_keys, validate_key as validate_managed_key

DEFAULT_TENANT = "default"
ENV_API_KEYS = "NEUROGUARD_API_KEYS"


def get_configured_api_keys() -> Set[str]:
    """Return set of valid API keys from env (comma-separated). Empty = no env keys."""
    raw = os.environ.get(ENV_API_KEYS, "").strip()
    if not raw:
        return set()
    return {k.strip() for k in raw.split(",") if k.strip()}


def validate_api_key(key: Optional[str]) -> Optional[str]:
    """
    If key is valid, return tenant_id. Checks managed keys first, then env keys.
    If no keys configured (env empty and no managed keys), return DEFAULT_TENANT for local dev.
    If keys configured and key invalid/missing, return None.
    """
    # Managed key takes precedence
    tenant = validate_managed_key(key)
    if tenant is not None:
        return tenant
    configured = get_configured_api_keys()
    if key and key in configured:
        return key
    if not configured and not has_any_keys():
        return DEFAULT_TENANT
    return None


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
