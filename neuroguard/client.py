"""
NeuroGuard API client — simple Python SDK for interacting with the NeuroGuard REST API.

Example:
    >>> from neuroguard.client import NeuroGuardClient
    >>> client = NeuroGuardClient(base_url="http://127.0.0.1:8000", api_key="your-key")
    >>> client.consent_grant("user_1", "neural")
    >>> client.store("user_1", "neural", b"secret data")
    >>> data = client.retrieve("user_1", "neural")
    >>> print(client.dashboard())
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Optional, Union

import httpx


class NeuroGuardClient:
    """
    Client for the NeuroGuard REST API.

    Connects to a running NeuroGuard server (e.g. started with
    ``python -m neuroguard.api``). When ``api_key`` is set, the
    ``X-API-Key`` header is sent on every request (required for
    protected endpoints like dashboard when the server has API keys configured).

    Example:
        >>> client = NeuroGuardClient()
        >>> client.store("alice", "neural", b"encrypted-payload")
        >>> raw = client.retrieve("alice", "neural")
        >>> score = client.privacy_score()
    """

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        api_key: Optional[str] = None,
        *,
        client: Optional[Union[httpx.Client, Any]] = None,
    ) -> None:
        """
        Args:
            base_url: Base URL of the NeuroGuard API (no trailing slash).
            api_key: Optional API key; when set, X-API-Key header is sent.
            client: Optional HTTP client (e.g. httpx.Client or test double) with .request(method, path, **kwargs).
        """
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._owned = client is None
        self._client = client if client is not None else httpx.Client(base_url=self._base_url)

    def _headers(self) -> Dict[str, str]:
        if self._api_key:
            return {"X-API-Key": self._api_key}
        return {}

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = {**self._headers(), **kwargs.pop("headers", {})}
        return self._client.request(method, path, headers=headers, **kwargs)

    def consent_grant(self, user_id: str, category: str, actor: Optional[str] = None) -> Dict[str, Any]:
        """
        Grant consent for (user_id, category). Call before store/retrieve if using the ledger.

        Example:
            >>> client.consent_grant("alice", "neural")
        """
        r = self._request(
            "POST",
            "/consent/grant",
            json={"user_id": user_id, "category": category, "actor": actor or "user"},
        )
        r.raise_for_status()
        return r.json()

    def store(self, user_id: str, category: str, data: bytes) -> Dict[str, Any]:
        """
        Store encrypted data for (user_id, category). Requires prior consent.

        Example:
            >>> client.store("alice", "neural", b"secret bytes")
            {"ok": True, "user_id": "alice", "category": "neural"}
        """
        r = self._request(
            "POST",
            "/vault/store",
            json={
                "user_id": user_id,
                "category": category,
                "plaintext_base64": base64.b64encode(data).decode("ascii"),
            },
        )
        r.raise_for_status()
        return r.json()

    def retrieve(self, user_id: str, category: str) -> bytes:
        """
        Retrieve and decrypt data for (user_id, category). Requires consent.

        Example:
            >>> data = client.retrieve("alice", "neural")
        """
        r = self._request(
            "POST",
            "/vault/retrieve",
            json={"user_id": user_id, "category": category},
        )
        r.raise_for_status()
        body = r.json()
        return base64.b64decode(body["plaintext_base64"])

    def dashboard(self) -> Dict[str, Any]:
        """
        Return dashboard summary (tenant-scoped when API key is set).

        Example:
            >>> client.dashboard()
            {"tenant_id": "default", "encrypted_records": 1, "privacy_score": {...}}
        """
        r = self._request("GET", "/dashboard")
        r.raise_for_status()
        return r.json()

    def privacy_score(self) -> Dict[str, Any]:
        """
        Return privacy score (score, status, reasons).

        Example:
            >>> client.privacy_score()
            {"score": 100, "status": "low", "reasons": []}
        """
        r = self._request("GET", "/privacy-score")
        r.raise_for_status()
        return r.json()

    def security_check(
        self,
        consent_present: bool,
        encryption_enabled: bool,
        operation_type: str,
    ) -> Dict[str, Any]:
        """
        Run a security check for a sensitive operation.

        Example:
            >>> client.security_check(True, True, "read")
            {"allowed": True, "risk_level": "low", "reason": "Allowed."}
        """
        r = self._request(
            "POST",
            "/security/check",
            json={
                "consent_present": consent_present,
                "encryption_enabled": encryption_enabled,
                "operation_type": operation_type,
            },
        )
        r.raise_for_status()
        return r.json()

    def close(self) -> None:
        """Close the underlying HTTP client (if owned)."""
        if self._owned:
            self._client.close()

    def __enter__(self) -> "NeuroGuardClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
