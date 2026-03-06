"""Tests for NeuroGuardClient."""

import os
import tempfile
from typing import Any, Dict, Optional

import httpx
import pytest
from fastapi.testclient import TestClient

from neuroguard.api.app import create_app
from neuroguard.api_keys import clear_store as clear_api_keys_store
from neuroguard.client import NeuroGuardClient
from neuroguard.tenants import clear_store as clear_tenants_store
from neuroguard.usage_meter import clear_store as clear_usage_store
from neuroguard.plans import clear_store as clear_plans_store
from neuroguard.subscriptions import clear_store as clear_subscriptions_store


class _TestClientAdapter:
    """Makes FastAPI TestClient look like an httpx client for NeuroGuardClient."""

    def __init__(self, tc: TestClient, base_url: str) -> None:
        self._tc = tc
        self._base = base_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        url = self._base + (path if path.startswith("/") else "/" + path)
        if method == "GET":
            return self._tc.get(url, headers=headers or {}, **kwargs)
        if method == "POST":
            return self._tc.post(url, headers=headers or {}, json=json, **kwargs)
        raise ValueError(f"Unsupported method: {method}")


@pytest.fixture
def temp_ledger_path():
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    try:
        yield path
    finally:
        if os.path.isfile(path):
            os.remove(path)


@pytest.fixture
def client_with_test_app(temp_ledger_path):
    """NeuroGuardClient backed by the test app (no real HTTP)."""
    clear_api_keys_store()
    clear_tenants_store()
    clear_usage_store()
    clear_plans_store()
    clear_subscriptions_store()
    os.environ["NEUROGUARD_LEDGER_PATH"] = temp_ledger_path
    os.environ["NEUROGUARD_API_KEYS_PATH"] = ""
    os.environ["NEUROGUARD_TENANTS_PATH"] = ""
    os.environ["NEUROGUARD_USAGE_PATH"] = ""
    os.environ["NEUROGUARD_PLANS_PATH"] = ""
    os.environ["NEUROGUARD_SUBSCRIPTIONS_PATH"] = ""
    try:
        app = create_app()
        with TestClient(app) as tc:
            adapter = _TestClientAdapter(tc, "http://test")
            yield NeuroGuardClient(base_url="http://test", api_key=None, client=adapter)
    finally:
        os.environ.pop("NEUROGUARD_LEDGER_PATH", None)
        os.environ.pop("NEUROGUARD_API_KEYS_PATH", None)
        os.environ.pop("NEUROGUARD_TENANTS_PATH", None)
        os.environ.pop("NEUROGUARD_USAGE_PATH", None)
        os.environ.pop("NEUROGUARD_PLANS_PATH", None)
        os.environ.pop("NEUROGUARD_SUBSCRIPTIONS_PATH", None)


@pytest.fixture
def client_with_api_key(temp_ledger_path):
    """NeuroGuardClient with API key, backed by test app that requires keys."""
    clear_api_keys_store()
    clear_tenants_store()
    clear_usage_store()
    clear_plans_store()
    clear_subscriptions_store()
    os.environ["NEUROGUARD_LEDGER_PATH"] = temp_ledger_path
    os.environ["NEUROGUARD_API_KEYS_PATH"] = ""
    os.environ["NEUROGUARD_TENANTS_PATH"] = ""
    os.environ["NEUROGUARD_USAGE_PATH"] = ""
    os.environ["NEUROGUARD_PLANS_PATH"] = ""
    os.environ["NEUROGUARD_SUBSCRIPTIONS_PATH"] = ""
    os.environ["NEUROGUARD_API_KEYS"] = "test-key-123"
    try:
        app = create_app()
        with TestClient(app) as tc:
            adapter = _TestClientAdapter(tc, "http://test")
            yield NeuroGuardClient(base_url="http://test", api_key="test-key-123", client=adapter)
    finally:
        os.environ.pop("NEUROGUARD_LEDGER_PATH", None)
        os.environ.pop("NEUROGUARD_API_KEYS_PATH", None)
        os.environ.pop("NEUROGUARD_TENANTS_PATH", None)
        os.environ.pop("NEUROGUARD_USAGE_PATH", None)
        os.environ.pop("NEUROGUARD_PLANS_PATH", None)
        os.environ.pop("NEUROGUARD_SUBSCRIPTIONS_PATH", None)
        os.environ.pop("NEUROGUARD_API_KEYS", None)


def test_client_store_and_retrieve(client_with_test_app: NeuroGuardClient) -> None:
    """store() and retrieve() round-trip when consent is granted."""
    client = client_with_test_app
    client.consent_grant("u1", "neural")
    out = client.store("u1", "neural", b"secret payload")
    assert out["ok"] is True
    assert out["user_id"] == "u1"
    assert out["category"] == "neural"
    data = client.retrieve("u1", "neural")
    assert data == b"secret payload"


def test_client_dashboard(client_with_test_app: NeuroGuardClient) -> None:
    """dashboard() returns dict with tenant_id and expected keys."""
    data = client_with_test_app.dashboard()
    assert "tenant_id" in data
    assert "encrypted_records" in data
    assert "privacy_score" in data
    assert "score" in data["privacy_score"]
    assert 0 <= data["privacy_score"]["score"] <= 100


def test_client_privacy_score(client_with_test_app: NeuroGuardClient) -> None:
    """privacy_score() returns score, status, reasons."""
    data = client_with_test_app.privacy_score()
    assert "score" in data
    assert "status" in data
    assert "reasons" in data
    assert 0 <= data["score"] <= 100
    assert data["status"] in ("low", "moderate", "high")


def test_client_security_check(client_with_test_app: NeuroGuardClient) -> None:
    """security_check() returns allowed, risk_level, reason."""
    data = client_with_test_app.security_check(True, True, "read")
    assert data["allowed"] is True
    assert data["risk_level"] == "low"
    data2 = client_with_test_app.security_check(False, True, "export")
    assert data2["allowed"] is False
    assert "high" in data2["risk_level"].lower()


def test_client_dashboard_with_api_key(client_with_api_key: NeuroGuardClient) -> None:
    """With api_key set, dashboard() succeeds and returns tenant_id from key."""
    data = client_with_api_key.dashboard()
    assert data["tenant_id"] == "test-key-123"
    assert "encrypted_records" in data


def test_client_store_raises_on_no_consent(client_with_test_app: NeuroGuardClient) -> None:
    """store() without consent raises HTTPError 403."""
    client = client_with_test_app
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        client.store("u2", "other", b"data")
    assert exc_info.value.response.status_code == 403


def test_client_retrieve_raises_on_not_found(client_with_test_app: NeuroGuardClient) -> None:
    """retrieve() when no data raises HTTPError 404."""
    client = client_with_test_app
    client.consent_grant("u3", "cat")
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        client.retrieve("u3", "cat")
    assert exc_info.value.response.status_code == 404
