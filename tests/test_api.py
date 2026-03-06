"""Tests for the NeuroGuard FastAPI API."""

import base64
import json
import os
import shutil
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


@pytest.fixture
def api_client_with_api_key_required(temp_ledger_path):
    """TestClient with API key auth required (NEUROGUARD_API_KEYS set)."""
    os.environ["NEUROGUARD_LEDGER_PATH"] = temp_ledger_path
    os.environ["NEUROGUARD_API_KEYS"] = "test-key-123,other-key"
    try:
        app = create_app()
        with TestClient(app) as client:
            yield client
    finally:
        os.environ.pop("NEUROGUARD_LEDGER_PATH", None)
        os.environ.pop("NEUROGUARD_API_KEYS", None)


@pytest.fixture
def api_client_file_backend(temp_ledger_path):
    """TestClient with file vault backend (temp settings + temp vault dir)."""
    vault_dir = tempfile.mkdtemp(prefix="neuroguard_vault_")
    fd, settings_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    settings = {
        "vault_backend": "file",
        "vault_store_path": vault_dir,
        "ledger_path": "",
        "strict_mode": False,
        "telemetry_enabled": False,
    }
    with open(settings_path, "w", encoding="utf-8") as f:
        json.dump(settings, f)
    os.environ["NEUROGUARD_LEDGER_PATH"] = temp_ledger_path
    os.environ["NEUROGUARD_SETTINGS_PATH"] = settings_path
    try:
        app = create_app()
        with TestClient(app) as client:
            yield client
    finally:
        os.environ.pop("NEUROGUARD_LEDGER_PATH", None)
        os.environ.pop("NEUROGUARD_SETTINGS_PATH", None)
        if os.path.isfile(settings_path):
            os.remove(settings_path)
        if os.path.isdir(vault_dir):
            shutil.rmtree(vault_dir, ignore_errors=True)


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


def test_lineage_unknown_data_id_returns_404(api_client: TestClient) -> None:
    """GET /lineage/{data_id} returns 404 for unknown data_id."""
    r = api_client.get("/lineage/unknown:id")
    assert r.status_code == 404


def test_lineage_after_vault_store_returns_record(api_client: TestClient) -> None:
    """After successful /vault/store, GET /lineage/{data_id} returns lineage with expected fields."""
    user_id, category = "u1", "neural"
    api_client.post("/consent/grant", json={"user_id": user_id, "category": category, "actor": "user"})
    api_client.post(
        "/vault/store",
        json={
            "user_id": user_id,
            "category": category,
            "plaintext_base64": base64.b64encode(b"payload").decode("ascii"),
        },
    )
    data_id = f"{user_id}:{category}"
    r = api_client.get(f"/lineage/{data_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["data_id"] == data_id
    assert data["encryption_status"] == "encrypted"
    assert data["consent_verified"] is True
    assert "events" in data
    assert len(data["events"]) >= 1
    assert data["events"][0]["event_type"] == "create"


def test_lineage_after_vault_retrieve_adds_read_event(api_client: TestClient) -> None:
    """After successful /vault/retrieve, GET /lineage/{data_id} shows an added 'read' event."""
    user_id, category = "u2", "sensor"
    api_client.post("/consent/grant", json={"user_id": user_id, "category": category, "actor": "user"})
    api_client.post(
        "/vault/store",
        json={
            "user_id": user_id,
            "category": category,
            "plaintext_base64": base64.b64encode(b"data").decode("ascii"),
        },
    )
    data_id = f"{user_id}:{category}"
    r_before = api_client.get(f"/lineage/{data_id}")
    assert r_before.status_code == 200
    events_before = len(r_before.json()["events"])

    api_client.post("/vault/retrieve", json={"user_id": user_id, "category": category})

    r_after = api_client.get(f"/lineage/{data_id}")
    assert r_after.status_code == 200
    events_after = r_after.json()["events"]
    assert len(events_after) == events_before + 1
    assert events_after[-1]["event_type"] == "read"


def test_privacy_score_returns_expected_shape(api_client: TestClient) -> None:
    """GET /privacy-score returns 200 with score, status, and reasons."""
    r = api_client.get("/privacy-score")
    assert r.status_code == 200
    data = r.json()
    assert "score" in data
    assert "status" in data
    assert "reasons" in data
    assert isinstance(data["score"], int)
    assert 0 <= data["score"] <= 100
    assert data["status"] in ("low", "moderate", "high")
    assert isinstance(data["reasons"], list)


def test_privacy_score_full_setup_returns_100(api_client: TestClient) -> None:
    """With full app state (encryption, consent, audit, lineage), GET /privacy-score returns 100 and status low."""
    r = api_client.get("/privacy-score")
    assert r.status_code == 200
    data = r.json()
    assert data["score"] == 100
    assert data["status"] == "low"
    assert data["reasons"] == []


def test_dashboard_returns_expected_shape(api_client: TestClient) -> None:
    """GET /dashboard returns 200 with tenant_id, encrypted_records, consent_events, audit_events, lineage_records, privacy_score."""
    r = api_client.get("/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert "tenant_id" in data
    assert "encrypted_records" in data
    assert "consent_events" in data
    assert "audit_events" in data
    assert "lineage_records" in data
    assert "privacy_score" in data
    assert isinstance(data["encrypted_records"], int)
    assert isinstance(data["consent_events"], int)
    assert isinstance(data["audit_events"], int)
    assert isinstance(data["lineage_records"], int)
    ps = data["privacy_score"]
    assert "score" in ps and "status" in ps and "reasons" in ps


def test_dashboard_counts_reflect_usage(api_client: TestClient) -> None:
    """After consent + vault store, dashboard shows non-zero encrypted_records, consent_events, lineage_records."""
    r_before = api_client.get("/dashboard")
    assert r_before.status_code == 200
    before = r_before.json()

    api_client.post("/consent/grant", json={"user_id": "dash", "category": "cat", "actor": "user"})
    api_client.post(
        "/vault/store",
        json={
            "user_id": "dash",
            "category": "cat",
            "plaintext_base64": base64.b64encode(b"x").decode("ascii"),
        },
    )

    r_after = api_client.get("/dashboard")
    assert r_after.status_code == 200
    after = r_after.json()
    assert after["encrypted_records"] == before["encrypted_records"] + 1
    assert after["consent_events"] >= before["consent_events"] + 1
    assert after["lineage_records"] == before["lineage_records"] + 1
    assert after["audit_events"] >= before["audit_events"]


def test_security_check_returns_expected_shape(api_client: TestClient) -> None:
    """POST /security/check returns 200 with allowed, risk_level, and reason."""
    r = api_client.post(
        "/security/check",
        json={
            "consent_present": True,
            "encryption_enabled": True,
            "operation_type": "read",
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "allowed" in data
    assert "risk_level" in data
    assert "reason" in data
    assert isinstance(data["allowed"], bool)
    assert data["risk_level"] in ("low", "moderate", "high")
    assert isinstance(data["reason"], str)


def test_security_check_blocked_without_consent(api_client: TestClient) -> None:
    """POST /security/check with consent_present=False returns allowed=False and high risk."""
    r = api_client.post(
        "/security/check",
        json={
            "consent_present": False,
            "encryption_enabled": True,
            "operation_type": "export",
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["allowed"] is False
    assert data["risk_level"] == "high"
    assert "consent" in data["reason"].lower()


def test_dashboard_export_returns_json_download(api_client: TestClient) -> None:
    """GET /dashboard/export returns 200 with same dashboard data as JSON and attachment header."""
    r = api_client.get("/dashboard/export")
    assert r.status_code == 200
    assert "application/json" in r.headers.get("content-type", "")
    assert "attachment" in r.headers.get("content-disposition", "").lower()
    data = r.json()
    assert "encrypted_records" in data
    assert "consent_events" in data
    assert "privacy_score" in data


def test_lineage_export_returns_json_download(api_client: TestClient) -> None:
    """GET /lineage/{data_id}/export returns 200 with lineage JSON download when record exists."""
    api_client.post("/consent/grant", json={"user_id": "ex", "category": "cat", "actor": "user"})
    api_client.post(
        "/vault/store",
        json={"user_id": "ex", "category": "cat", "plaintext_base64": base64.b64encode(b"x").decode("ascii")},
    )
    data_id = "ex:cat"
    r = api_client.get(f"/lineage/{data_id}/export")
    assert r.status_code == 200
    assert "application/json" in r.headers.get("content-type", "")
    assert "attachment" in r.headers.get("content-disposition", "").lower()
    data = r.json()
    assert data["data_id"] == data_id
    assert "events" in data


def test_lineage_export_missing_returns_404(api_client: TestClient) -> None:
    """GET /lineage/{data_id}/export returns 404 when lineage record does not exist."""
    r = api_client.get("/lineage/nonexistent:id/export")
    assert r.status_code == 404


def test_dashboard_missing_api_key_returns_401(api_client_with_api_key_required: TestClient) -> None:
    """When API keys are configured, GET /dashboard without X-API-Key returns 401."""
    r = api_client_with_api_key_required.get("/dashboard")
    assert r.status_code == 401
    assert "api key" in r.json().get("detail", "").lower()


def test_dashboard_invalid_api_key_returns_401(api_client_with_api_key_required: TestClient) -> None:
    """When API keys are configured, GET /dashboard with invalid X-API-Key returns 401."""
    r = api_client_with_api_key_required.get(
        "/dashboard",
        headers={"X-API-Key": "wrong-key"},
    )
    assert r.status_code == 401
    assert "api key" in r.json().get("detail", "").lower()


def test_dashboard_valid_api_key_success(api_client_with_api_key_required: TestClient) -> None:
    """When API keys are configured, GET /dashboard with valid X-API-Key returns 200 and tenant_id."""
    r = api_client_with_api_key_required.get(
        "/dashboard",
        headers={"X-API-Key": "test-key-123"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["tenant_id"] == "test-key-123"
    assert "encrypted_records" in data
    assert "privacy_score" in data


def test_tenant_isolated_dashboard(api_client_with_api_key_required: TestClient) -> None:
    """Data stored via vault (default tenant) is not visible in another tenant's dashboard."""
    client = api_client_with_api_key_required
    client.post("/consent/grant", json={"user_id": "u1", "category": "cat", "actor": "user"})
    client.post(
        "/vault/store",
        json={"user_id": "u1", "category": "cat", "plaintext_base64": base64.b64encode(b"x").decode("ascii")},
    )
    r = client.get("/dashboard", headers={"X-API-Key": "test-key-123"})
    assert r.status_code == 200
    data = r.json()
    assert data["tenant_id"] == "test-key-123"
    assert data["encrypted_records"] == 0
    assert data["lineage_records"] == 0


def test_dashboard_export_valid_api_key_success(api_client_with_api_key_required: TestClient) -> None:
    """When API keys are configured, GET /dashboard/export with valid X-API-Key returns 200."""
    r = api_client_with_api_key_required.get(
        "/dashboard/export",
        headers={"X-API-Key": "test-key-123"},
    )
    assert r.status_code == 200
    assert "application/json" in r.headers.get("content-type", "")
    data = r.json()
    assert "encrypted_records" in data


def test_api_with_file_backend_store_retrieve_dashboard(api_client_file_backend: TestClient) -> None:
    """With vault_backend=file, consent + vault store + retrieve and dashboard work."""
    client = api_client_file_backend
    client.post("/consent/grant", json={"user_id": "fb_user", "category": "neural", "actor": "user"})
    client.post(
        "/vault/store",
        json={
            "user_id": "fb_user",
            "category": "neural",
            "plaintext_base64": base64.b64encode(b"secret").decode("ascii"),
        },
    )
    assert client.get("/dashboard").json()["encrypted_records"] == 1
    r = client.post("/vault/retrieve", json={"user_id": "fb_user", "category": "neural"})
    assert r.status_code == 200
    assert base64.b64decode(r.json()["plaintext_base64"]) == b"secret"
    assert client.get("/lineage/fb_user:neural").status_code == 200

