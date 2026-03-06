"""Tests for the NeuroGuard FastAPI API."""

import base64
import json
import os
import shutil
import tempfile

import pytest
from fastapi.testclient import TestClient

from neuroguard.api.app import create_app
from neuroguard.api_keys import clear_store as clear_api_keys_store
from neuroguard.tenants import clear_store as clear_tenants_store
from neuroguard.usage_meter import clear_store as clear_usage_store
from neuroguard.plans import clear_store as clear_plans_store
from neuroguard.subscriptions import clear_store as clear_subscriptions_store


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
        with TestClient(app) as client:
            yield client
    finally:
        os.environ.pop("NEUROGUARD_LEDGER_PATH", None)
        os.environ.pop("NEUROGUARD_API_KEYS_PATH", None)
        os.environ.pop("NEUROGUARD_TENANTS_PATH", None)
        os.environ.pop("NEUROGUARD_USAGE_PATH", None)
        os.environ.pop("NEUROGUARD_PLANS_PATH", None)
        os.environ.pop("NEUROGUARD_SUBSCRIPTIONS_PATH", None)


@pytest.fixture
def api_client_with_api_key_required(temp_ledger_path):
    """TestClient with API key auth required (NEUROGUARD_API_KEYS set)."""
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
    os.environ["NEUROGUARD_API_KEYS"] = "test-key-123,other-key"
    try:
        app = create_app()
        with TestClient(app) as client:
            yield client
    finally:
        os.environ.pop("NEUROGUARD_LEDGER_PATH", None)
        os.environ.pop("NEUROGUARD_API_KEYS_PATH", None)
        os.environ.pop("NEUROGUARD_TENANTS_PATH", None)
        os.environ.pop("NEUROGUARD_USAGE_PATH", None)
        os.environ.pop("NEUROGUARD_PLANS_PATH", None)
        os.environ.pop("NEUROGUARD_SUBSCRIPTIONS_PATH", None)
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


# ---------------------------------------------------------------------------
# Admin API key management
# ---------------------------------------------------------------------------


def test_admin_create_api_key_returns_key(api_client: TestClient) -> None:
    """POST /admin/api-keys with tenant_id returns 200 and a key (no env keys: auth off)."""
    r = api_client.post("/admin/api-keys", json={"tenant_id": "tenant-a"})
    assert r.status_code == 200
    data = r.json()
    assert data.get("ok") is True
    assert "key" in data
    assert data["tenant_id"] == "tenant-a"
    assert data["key"].startswith("ng_")


def test_admin_list_api_keys_filtered_by_tenant(api_client: TestClient) -> None:
    """Create two keys for same tenant, list with key1 returns both; revoke key1, list with key2 returns one."""
    create_r1 = api_client.post("/admin/api-keys", json={"tenant_id": "tenant-b"})
    assert create_r1.status_code == 200
    key1 = create_r1.json()["key"]
    create_r2 = api_client.post(
        "/admin/api-keys",
        json={"tenant_id": "tenant-b"},
        headers={"X-API-Key": key1},
    )
    assert create_r2.status_code == 200
    key2 = create_r2.json()["key"]
    r = api_client.get("/admin/api-keys", headers={"X-API-Key": key1})
    assert r.status_code == 200
    keys = r.json().get("keys", [])
    assert len(keys) == 2
    rev_r = api_client.post("/admin/api-keys/revoke", json={"key": key1}, headers={"X-API-Key": key2})
    assert rev_r.status_code == 200
    r2 = api_client.get("/admin/api-keys", headers={"X-API-Key": key2})
    assert r2.status_code == 200
    assert len(r2.json().get("keys", [])) == 1


def test_admin_revoke_api_key_returns_404_for_unknown(api_client: TestClient) -> None:
    """POST /admin/api-keys/revoke with unknown key returns 404."""
    create_r = api_client.post("/admin/api-keys", json={"tenant_id": "tenant-c"})
    key = create_r.json()["key"]
    r = api_client.post(
        "/admin/api-keys/revoke",
        json={"key": "ng_nonexistent"},
        headers={"X-API-Key": key},
    )
    assert r.status_code == 404


def test_managed_key_valid_for_dashboard(api_client: TestClient) -> None:
    """A key created via POST /admin/api-keys can be used for GET /dashboard."""
    create_r = api_client.post("/admin/api-keys", json={"tenant_id": "dashboard-tenant"})
    assert create_r.status_code == 200
    key = create_r.json()["key"]
    r = api_client.get("/dashboard", headers={"X-API-Key": key})
    assert r.status_code == 200
    assert r.json()["tenant_id"] == "dashboard-tenant"


# ---------------------------------------------------------------------------
# Admin tenant registry
# ---------------------------------------------------------------------------


def test_admin_create_tenant_returns_tenant_id(api_client: TestClient) -> None:
    """POST /admin/tenants with name returns 200 and tenant_id, name, created_at."""
    r = api_client.post("/admin/tenants", json={"name": "Acme Inc"})
    assert r.status_code == 200
    data = r.json()
    assert data.get("ok") is True
    assert "tenant_id" in data
    assert data["name"] == "Acme Inc"
    assert "created_at" in data
    assert "acme-inc_" in data["tenant_id"] or "acme_" in data["tenant_id"]


def test_admin_list_tenants(api_client: TestClient) -> None:
    """GET /admin/tenants returns list of tenants; after create, list includes new tenant."""
    r = api_client.get("/admin/tenants")
    assert r.status_code == 200
    assert "tenants" in r.json()
    assert r.json()["tenants"] == []
    api_client.post("/admin/tenants", json={"name": "First"})
    api_client.post("/admin/tenants", json={"name": "Second"})
    r2 = api_client.get("/admin/tenants")
    assert r2.status_code == 200
    assert len(r2.json()["tenants"]) == 2


def test_admin_deactivate_tenant(api_client: TestClient) -> None:
    """POST /admin/tenants/deactivate marks tenant inactive; list still returns it with is_active false."""
    create_r = api_client.post("/admin/tenants", json={"name": "To Deactivate"})
    tenant_id = create_r.json()["tenant_id"]
    r = api_client.post("/admin/tenants/deactivate", json={"tenant_id": tenant_id})
    assert r.status_code == 200
    assert r.json().get("ok") is True
    list_r = api_client.get("/admin/tenants")
    tenants = list_r.json()["tenants"]
    found = next((t for t in tenants if t["tenant_id"] == tenant_id), None)
    assert found is not None and found["is_active"] is False


def test_admin_deactivate_tenant_unknown_returns_404(api_client: TestClient) -> None:
    """POST /admin/tenants/deactivate with unknown tenant_id returns 404."""
    r = api_client.post("/admin/tenants/deactivate", json={"tenant_id": "nonexistent_tenant_id"})
    assert r.status_code == 404


def test_admin_tenant_summary_existing_tenant(api_client: TestClient) -> None:
    """GET /admin/tenants/{tenant_id}/summary for an existing tenant returns tenant record, plan, usage, api_keys, dashboard_preview."""
    create_t = api_client.post("/admin/tenants", json={"name": "Summary Corp"})
    assert create_t.status_code == 200
    tenant_id = create_t.json()["tenant_id"]
    create_k = api_client.post("/admin/api-keys", json={"tenant_id": tenant_id})
    assert create_k.status_code == 200
    key = create_k.json()["key"]
    r = api_client.get(f"/admin/tenants/{tenant_id}/summary", headers={"X-API-Key": key})
    assert r.status_code == 200
    data = r.json()
    assert data["tenant_id"] == tenant_id
    assert data["tenant"] is not None
    assert data["tenant"]["name"] == "Summary Corp"
    assert data["plan"] == "free"
    assert "usage" in data
    assert isinstance(data["usage"], dict)
    assert data["api_keys"] is not None
    assert len(data["api_keys"]) == 1
    assert data["api_keys"][0]["tenant_id"] == tenant_id
    assert "dashboard_preview" in data
    assert data["dashboard_preview"]["tenant_id"] == tenant_id


def test_admin_tenant_summary_unknown_tenant(api_client: TestClient) -> None:
    """GET /admin/tenants/{tenant_id}/summary for unknown tenant returns tenant=null but plan, usage, api_keys, dashboard_preview."""
    r = api_client.get("/admin/tenants/unknown-tenant-id/summary")
    assert r.status_code == 200
    data = r.json()
    assert data["tenant_id"] == "unknown-tenant-id"
    assert data["tenant"] is None
    assert data["plan"] == "free"
    assert "usage" in data
    assert data["api_keys"] == []
    assert "dashboard_preview" in data
    assert data["dashboard_preview"]["tenant_id"] == "unknown-tenant-id"


def test_admin_tenant_summary_api_keys_filtered_by_tenant(api_client: TestClient) -> None:
    """Summary for tenant A returns only API keys belonging to tenant A, not other tenants."""
    create_t1 = api_client.post("/admin/tenants", json={"name": "Tenant A"})
    create_t2 = api_client.post("/admin/tenants", json={"name": "Tenant B"})
    tenant_a = create_t1.json()["tenant_id"]
    tenant_b = create_t2.json()["tenant_id"]
    k1 = api_client.post("/admin/api-keys", json={"tenant_id": tenant_a}).json()["key"]
    api_client.post("/admin/api-keys", json={"tenant_id": tenant_a}, headers={"X-API-Key": k1})
    create_k_b = api_client.post("/admin/api-keys", json={"tenant_id": tenant_b}, headers={"X-API-Key": k1})
    k_b = create_k_b.json()["key"]
    r = api_client.get(f"/admin/tenants/{tenant_a}/summary", headers={"X-API-Key": k1})
    assert r.status_code == 200
    data = r.json()
    assert len(data["api_keys"]) == 2
    assert all(k["tenant_id"] == tenant_a for k in data["api_keys"])
    r2 = api_client.get(f"/admin/tenants/{tenant_b}/summary", headers={"X-API-Key": k_b})
    assert r2.status_code == 200
    assert len(r2.json()["api_keys"]) == 1
    assert r2.json()["api_keys"][0]["tenant_id"] == tenant_b


# ---------------------------------------------------------------------------
# Admin usage metering
# ---------------------------------------------------------------------------


def test_admin_usage_list_empty_then_after_requests(api_client: TestClient) -> None:
    """GET /admin/usage returns usage dict; after dashboard call, default tenant has dashboard_view."""
    r = api_client.get("/admin/usage")
    assert r.status_code == 200
    data = r.json()
    assert "usage" in data
    assert data["usage"] == {}
    api_client.get("/dashboard")
    api_client.get("/dashboard")
    r2 = api_client.get("/admin/usage")
    assert r2.status_code == 200
    usage = r2.json()["usage"]
    assert "default" in usage
    assert usage["default"]["dashboard_view"] == 2


def test_admin_usage_tenant_id(api_client: TestClient) -> None:
    """GET /admin/usage/{tenant_id} returns usage for that tenant."""
    api_client.post("/security/check", json={"consent_present": True, "encryption_enabled": True, "operation_type": "read"})
    r = api_client.get("/admin/usage/default")
    assert r.status_code == 200
    data = r.json()
    assert data["tenant_id"] == "default"
    assert "usage" in data
    assert data["usage"]["security_check"] == 1


# ---------------------------------------------------------------------------
# Admin plan enforcement
# ---------------------------------------------------------------------------


def test_admin_plans_list(api_client: TestClient) -> None:
    """GET /admin/plans returns built-in plan definitions."""
    r = api_client.get("/admin/plans")
    assert r.status_code == 200
    data = r.json()
    assert "plans" in data
    assert "free" in data["plans"]
    assert "builder" in data["plans"]
    assert "growth" in data["plans"]
    assert data["plans"]["free"]["dashboard_view"] == 10


def test_admin_plans_get_and_set(api_client: TestClient) -> None:
    """GET /admin/plans/{tenant_id} returns plan; POST sets plan."""
    r = api_client.get("/admin/plans/default")
    assert r.status_code == 200
    assert r.json()["tenant_id"] == "default"
    assert r.json()["plan"] == "free"
    r2 = api_client.post("/admin/plans/default", json={"plan_name": "growth"})
    assert r2.status_code == 200
    assert r2.json()["plan"] == "growth"
    r3 = api_client.get("/admin/plans/default")
    assert r3.json()["plan"] == "growth"
    r4 = api_client.post("/admin/plans/default", json={"plan_name": "invalid"})
    assert r4.status_code == 400


def test_dashboard_over_limit_returns_429(api_client: TestClient) -> None:
    """When tenant (default) exceeds free plan dashboard_view limit, GET /dashboard returns 429."""
    for _ in range(10):
        api_client.get("/dashboard")
    r = api_client.get("/dashboard")
    assert r.status_code == 429
    assert "limit" in r.json().get("detail", "").lower()


def test_dashboard_export_over_limit_returns_429(api_client: TestClient) -> None:
    """When tenant exceeds free plan dashboard_export limit, GET /dashboard/export returns 429."""
    for _ in range(5):
        api_client.get("/dashboard/export")
    r = api_client.get("/dashboard/export")
    assert r.status_code == 429


def test_plan_change_restores_access(api_client: TestClient) -> None:
    """After hitting limit, upgrading to growth allows dashboard again."""
    for _ in range(10):
        api_client.get("/dashboard")
    assert api_client.get("/dashboard").status_code == 429
    api_client.post("/admin/plans/default", json={"plan_name": "growth"})
    r = api_client.get("/dashboard")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Admin subscriptions
# ---------------------------------------------------------------------------


def test_admin_subscriptions_list_and_set_and_get(api_client: TestClient) -> None:
    """GET /admin/subscriptions empty; POST creates; GET by tenant_id returns it."""
    r = api_client.get("/admin/subscriptions")
    assert r.status_code == 200
    assert r.json()["subscriptions"] == []
    create_r = api_client.post(
        "/admin/subscriptions/default",
        json={"plan_name": "builder", "status": "trial"},
    )
    assert create_r.status_code == 200
    data = create_r.json()
    assert data["ok"] is True
    assert "subscription" in data
    assert data["subscription"]["tenant_id"] == "default"
    assert data["subscription"]["plan_name"] == "builder"
    assert data["subscription"]["status"] == "trial"
    assert "started_at" in data["subscription"]
    r2 = api_client.get("/admin/subscriptions")
    assert len(r2.json()["subscriptions"]) == 1
    r3 = api_client.get("/admin/subscriptions/default")
    assert r3.status_code == 200
    assert r3.json()["subscription"]["status"] == "trial"


def test_admin_subscriptions_get_unknown_returns_404(api_client: TestClient) -> None:
    """GET /admin/subscriptions/{tenant_id} for unknown tenant returns 404."""
    r = api_client.get("/admin/subscriptions/nonexistent-tenant")
    assert r.status_code == 404


def test_admin_subscriptions_cancel(api_client: TestClient) -> None:
    """POST /admin/subscriptions/{tenant_id}/cancel sets status to canceled."""
    api_client.post("/admin/subscriptions/t1", json={"plan_name": "growth", "status": "active"})
    r = api_client.post("/admin/subscriptions/t1/cancel")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    get_r = api_client.get("/admin/subscriptions/t1")
    assert get_r.json()["subscription"]["status"] == "canceled"


def test_admin_subscriptions_cancel_unknown_returns_404(api_client: TestClient) -> None:
    """POST /admin/subscriptions/{tenant_id}/cancel for unknown returns 404."""
    r = api_client.post("/admin/subscriptions/nonexistent/cancel")
    assert r.status_code == 404

