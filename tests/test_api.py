"""Tests for the NeuroGuard FastAPI API."""

import base64
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from neuroguard.api.app import create_app


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
def api_client(temp_ledger_path):
    """TestClient with temp ledger path so tests don't touch ~/.neuroguard."""
    os.environ["NEUROGUARD_LEDGER_PATH"] = temp_ledger_path
    try:
        app = create_app()
        with TestClient(app) as client:
            yield client
    finally:
        os.environ.pop("NEUROGUARD_LEDGER_PATH", None)


def test_health(api_client: TestClient) -> None:
    """GET /health returns status ok."""
    r = api_client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_consent_grant_then_vault_store_works(api_client: TestClient) -> None:
    """POST /consent/grant then POST /vault/store succeeds when consent is granted."""
    r = api_client.post(
        "/consent/grant",
        json={"user_id": "u1", "category": "neural", "actor": "user"},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is True

    plaintext = b"secret neural data"
    r2 = api_client.post(
        "/vault/store",
        json={
            "user_id": "u1",
            "category": "neural",
            "plaintext_base64": base64.b64encode(plaintext).decode("ascii"),
        },
    )
    assert r2.status_code == 200
    assert r2.json()["ok"] is True

    r3 = api_client.post(
        "/vault/retrieve",
        json={"user_id": "u1", "category": "neural"},
    )
    assert r3.status_code == 200
    data = r3.json()
    assert data["ok"] is True
    assert base64.b64decode(data["plaintext_base64"]) == plaintext


def test_vault_store_without_consent_fails(api_client: TestClient) -> None:
    """POST /vault/store without prior consent returns 403."""
    r = api_client.post(
        "/vault/store",
        json={
            "user_id": "u2",
            "category": "other",
            "plaintext_base64": base64.b64encode(b"x").decode("ascii"),
        },
    )
    assert r.status_code == 403


def test_compliance_report_returns_expected_fields(api_client: TestClient) -> None:
    """GET /compliance/report returns privacy_score, chain verification, timestamp."""
    r = api_client.get("/compliance/report")
    assert r.status_code == 200
    data = r.json()
    assert "timestamp" in data
    assert "privacy_score" in data
    ps = data["privacy_score"]
    assert "score" in ps
    assert "risk_level" in ps
    assert "breakdown" in ps
    assert "recommendations" in ps
    assert "consent_ledger_verify_chain" in data
    assert "audit_logger_verify_chain" in data


def test_compliance_report_with_user_id_includes_consent_history(api_client: TestClient) -> None:
    """GET /compliance/report?user_id=X includes consent_history when user_id provided."""
    api_client.post("/consent/grant", json={"user_id": "u3", "category": "cat"})
    r = api_client.get("/compliance/report", params={"user_id": "u3"})
    assert r.status_code == 200
    data = r.json()
    assert "consent_history" in data
    assert len(data["consent_history"]) >= 1
    assert data["consent_history"][0]["user_id"] == "u3"
    assert data["consent_history"][0]["category"] == "cat"


