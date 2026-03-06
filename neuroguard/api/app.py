"""
NeuroGuard local REST API — expose encryption, consent, vault, and compliance via FastAPI.

Local-first: vault in-memory, consent ledger persisted to ~/.neuroguard/consent_ledger.jsonl.
"""

from __future__ import annotations

import base64
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from neuroguard.db.schema import init_db
from neuroguard.api.vault_routes import router as vault_router
from neuroguard.api.settings_routes import router as settings_router
from fastapi.responses import Response
from pydantic import BaseModel

from neuroguard.api.evidence_bundle import generate_evidence_bundle
from neuroguard.api.pdf_report import generate_compliance_pdf

from neuroguard import NeuralDataCipher, ConsentManager, AuditLogger, NeuralDataVault
from neuroguard.audit import AuditAction
from neuroguard.consent import ConsentLedger
from neuroguard.lineage import DataLineage, LineageTracker
from neuroguard.privacy_score import compute_simple_score, evaluate, is_encryption_enabled
from neuroguard.security import check_operation
from neuroguard.settings import load_settings
from neuroguard.vault.backend import get_backend
from neuroguard.api.auth import require_api_key
from neuroguard.api_keys import create_key as create_api_key, list_keys as list_api_keys, revoke_key as revoke_api_key
from neuroguard.tenants import create_tenant, deactivate_tenant, get_tenant, list_tenants
from neuroguard.usage_meter import get_usage, increment_usage, list_usage
from neuroguard.plans import check_limit, get_plan, list_plan_definitions, set_plan

# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class ConsentBody(BaseModel):
    user_id: str
    category: str
    actor: Optional[str] = "user"
    reason: Optional[str] = None


class VaultStoreBody(BaseModel):
    user_id: str
    category: str
    plaintext_base64: str


class VaultRetrieveBody(BaseModel):
    user_id: str
    category: str


class SecurityCheckBody(BaseModel):
    consent_present: bool
    encryption_enabled: bool
    operation_type: str


class CreateApiKeyBody(BaseModel):
    tenant_id: str


class RevokeApiKeyBody(BaseModel):
    key: str


class CreateTenantBody(BaseModel):
    name: str


class DeactivateTenantBody(BaseModel):
    tenant_id: str


class SetPlanBody(BaseModel):
    plan_name: str


# ---------------------------------------------------------------------------
# State (in-memory vault, persisted ledger, shared cipher, audit, lineage)
# ---------------------------------------------------------------------------

_ledger: Optional[ConsentLedger] = None
_cipher: Optional[NeuralDataCipher] = None
_audit: Optional[AuditLogger] = None
_consent: Optional[ConsentManager] = None
_vault: Optional[NeuralDataVault] = None
_lineage_tracker: Optional[LineageTracker] = None


def _get_ledger() -> ConsentLedger:
    if _ledger is None:
        raise RuntimeError("API state not initialized")
    return _ledger


def _get_cipher() -> NeuralDataCipher:
    if _cipher is None:
        raise RuntimeError("API state not initialized")
    return _cipher


def _get_audit() -> AuditLogger:
    if _audit is None:
        raise RuntimeError("API state not initialized")
    return _audit


def _get_consent() -> ConsentManager:
    if _consent is None:
        raise RuntimeError("API state not initialized")
    return _consent


def _get_vault() -> NeuralDataVault:
    if _vault is None:
        raise RuntimeError("API state not initialized")
    return _vault


def _get_lineage_tracker() -> LineageTracker:
    if _lineage_tracker is None:
        raise RuntimeError("API state not initialized")
    return _lineage_tracker


def _vault_data_id(user_id: str, category: str) -> str:
    """Stable data_id for lineage (vault is keyed by user_id + category)."""
    return f"{user_id}:{category}"


def _has_consent_from_ledger(user_id: str, category: str) -> bool:
    """True if the last consent event for (user_id, category) is grant."""
    ledger = _get_ledger()
    events = [e for e in ledger.history(user_id) if e.get("category") == category]
    return bool(events and events[-1].get("type") == "grant")


def _init_state() -> None:
    global _ledger, _cipher, _audit, _consent, _vault, _lineage_tracker
    key = os.environ.get("NEUROGUARD_ENCRYPTION_KEY")
    if key:
        try:
            key_b = base64.urlsafe_b64decode(key)
        except Exception:
            key_b = NeuralDataCipher.generate_key()
    else:
        key_b = NeuralDataCipher.generate_key()
    _cipher = NeuralDataCipher(key=key_b)
    ledger_path = os.environ.get("NEUROGUARD_LEDGER_PATH")
    _ledger = ConsentLedger(path=ledger_path)
    _audit = AuditLogger(use_hash_chain=True)
    _consent = ConsentManager()
    settings = load_settings()
    backend = get_backend(settings)
    _vault = NeuralDataVault(consent_manager=_consent, audit_logger=_audit, backend=backend)
    _lineage_tracker = LineageTracker()


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Startup: init DB and app state; teardown optional."""
    init_db()
    _init_state()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="NeuroGuard API",
        description="Local REST API for encryption, consent, vault, and compliance",
        version="0.1.0",
        lifespan=_lifespan,
    )

    # Register all routers and routes before returning (no early return)
    app.include_router(vault_router, prefix="/vault2")
    app.include_router(settings_router)

    @app.get("/health")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @app.get("/lineage/{data_id}", response_model=DataLineage)
    def get_lineage(data_id: str) -> DataLineage:
        """Return the full DataLineage record for the given data_id."""
        tracker = _get_lineage_tracker()
        lineage = tracker.get_lineage(data_id)
        if lineage is None:
            raise HTTPException(status_code=404, detail="Lineage record not found")
        return lineage

    @app.get("/privacy-score")
    def get_privacy_score() -> Dict[str, Any]:
        """Return a simple privacy score (0-100), status, and reasons based on current setup."""
        encryption_enabled = False
        consent_enabled = False
        audit_enabled = False
        lineage_enabled = False
        try:
            encryption_enabled = is_encryption_enabled(_get_cipher())
        except RuntimeError:
            pass
        try:
            _get_consent()
            consent_enabled = True
        except RuntimeError:
            pass
        try:
            _get_audit()
            audit_enabled = True
        except RuntimeError:
            pass
        try:
            _get_lineage_tracker()
            lineage_enabled = True
        except RuntimeError:
            pass
        return compute_simple_score(
            encryption_enabled=encryption_enabled,
            consent_enabled=consent_enabled,
            audit_enabled=audit_enabled,
            lineage_enabled=lineage_enabled,
        )

    def _build_dashboard_data(tenant_id: str = "default") -> Dict[str, Any]:
        """Build dashboard summary dict. When tenant_id is set, counts are scoped to that tenant."""
        encryption_enabled = False
        consent_enabled = False
        audit_enabled = False
        lineage_enabled = False
        try:
            encryption_enabled = is_encryption_enabled(_get_cipher())
        except RuntimeError:
            pass
        try:
            _get_consent()
            consent_enabled = True
        except RuntimeError:
            pass
        try:
            _get_audit()
            audit_enabled = True
        except RuntimeError:
            pass
        try:
            _get_lineage_tracker()
            lineage_enabled = True
        except RuntimeError:
            pass
        privacy_score = compute_simple_score(
            encryption_enabled=encryption_enabled,
            consent_enabled=consent_enabled,
            audit_enabled=audit_enabled,
            lineage_enabled=lineage_enabled,
        )
        encrypted_records = 0
        consent_events = 0
        audit_events = 0
        lineage_records = 0
        try:
            encrypted_records = _get_vault().count_records(tenant_id=tenant_id)
        except RuntimeError:
            pass
        try:
            consent_events = len(_get_ledger().history())
        except RuntimeError:
            pass
        try:
            audit_events = len(_get_audit().get_events(tenant_id=tenant_id))
        except RuntimeError:
            pass
        try:
            lineage_records = _get_lineage_tracker().record_count(tenant_id=tenant_id)
        except RuntimeError:
            pass
        return {
            "tenant_id": tenant_id,
            "encrypted_records": encrypted_records,
            "consent_events": consent_events,
            "audit_events": audit_events,
            "lineage_records": lineage_records,
            "privacy_score": privacy_score,
        }

    @app.get("/dashboard")
    def get_dashboard(
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """Developer dashboard: summary of current system state (in-memory). Tenant-scoped when API key set."""
        allowed, remaining, reason = check_limit(tenant_id, "dashboard_view")
        if not allowed:
            raise HTTPException(status_code=429, detail=reason)
        increment_usage(tenant_id, "dashboard_view")
        return _build_dashboard_data(tenant_id=tenant_id)

    @app.get("/dashboard/export")
    def get_dashboard_export(
        tenant_id: str = Depends(require_api_key),
    ) -> Response:
        """Export dashboard data as JSON download. Tenant-scoped when API key set."""
        allowed, remaining, reason = check_limit(tenant_id, "dashboard_export")
        if not allowed:
            raise HTTPException(status_code=429, detail=reason)
        increment_usage(tenant_id, "dashboard_export")
        data = _build_dashboard_data(tenant_id=tenant_id)
        return Response(
            content=json.dumps(data, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=\"dashboard.json\""},
        )

    # ---------------------------------------------------------------------------
    # Admin: API key management (protected)
    # ---------------------------------------------------------------------------

    @app.get("/admin/api-keys")
    def admin_list_api_keys(
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """List managed API keys for the current tenant."""
        keys = list_api_keys(tenant_id=tenant_id)
        return {"keys": [r.to_dict() for r in keys]}

    @app.post("/admin/api-keys")
    def admin_create_api_key(
        body: CreateApiKeyBody,
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """Create a new managed API key for the given tenant_id. Key is returned once."""
        record = create_api_key(body.tenant_id)
        return {"ok": True, "key": record.key, "tenant_id": record.tenant_id, "created_at": record.created_at.isoformat()}

    @app.post("/admin/api-keys/revoke")
    def admin_revoke_api_key(
        body: RevokeApiKeyBody,
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """Revoke a managed API key by key value."""
        ok = revoke_api_key(body.key)
        if not ok:
            raise HTTPException(status_code=404, detail="Key not found or already revoked")
        return {"ok": True}

    # ---------------------------------------------------------------------------
    # Admin: Tenant registry (protected)
    # ---------------------------------------------------------------------------

    @app.get("/admin/tenants")
    def admin_list_tenants(
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """List all tenants (active and inactive)."""
        tenants = list_tenants(active_only=False)
        return {"tenants": [t.to_dict() for t in tenants]}

    @app.post("/admin/tenants")
    def admin_create_tenant(
        body: CreateTenantBody,
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """Create a new tenant. Returns tenant_id, name, created_at."""
        record = create_tenant(body.name)
        return {"ok": True, "tenant_id": record.tenant_id, "name": record.name, "created_at": record.created_at.isoformat()}

    @app.post("/admin/tenants/deactivate")
    def admin_deactivate_tenant(
        body: DeactivateTenantBody,
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """Deactivate a tenant by tenant_id."""
        ok = deactivate_tenant(body.tenant_id)
        if not ok:
            raise HTTPException(status_code=404, detail="Tenant not found or already deactivated")
        return {"ok": True}

    # ---------------------------------------------------------------------------
    # Admin: Usage metering (protected)
    # ---------------------------------------------------------------------------

    @app.get("/admin/usage")
    def admin_list_usage(
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """List usage counters for all tenants."""
        return {"usage": list_usage()}

    @app.get("/admin/usage/{tenant_id_param}")
    def admin_get_usage(
        tenant_id_param: str,
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """Get usage counters for a specific tenant."""
        return {"tenant_id": tenant_id_param, "usage": get_usage(tenant_id_param)}

    # ---------------------------------------------------------------------------
    # Admin: Plan enforcement (protected)
    # ---------------------------------------------------------------------------

    @app.get("/admin/plans")
    def admin_list_plans(
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """List built-in plan definitions (names and limits)."""
        return {"plans": list_plan_definitions()}

    @app.get("/admin/plans/{tenant_id_param}")
    def admin_get_plan(
        tenant_id_param: str,
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """Get the plan assigned to a tenant."""
        return {"tenant_id": tenant_id_param, "plan": get_plan(tenant_id_param)}

    @app.post("/admin/plans/{tenant_id_param}")
    def admin_set_plan(
        tenant_id_param: str,
        body: SetPlanBody,
        tenant_id: str = Depends(require_api_key),
    ) -> Dict[str, Any]:
        """Assign a plan to a tenant."""
        ok = set_plan(tenant_id_param, body.plan_name)
        if not ok:
            raise HTTPException(status_code=400, detail="Unknown plan name")
        return {"ok": True, "tenant_id": tenant_id_param, "plan": body.plan_name}

    @app.get("/lineage/{data_id}/export")
    def get_lineage_export(data_id: str) -> Response:
        """Export full lineage record for data_id as JSON download. 404 if missing."""
        increment_usage(None, "lineage_export")
        tracker = _get_lineage_tracker()
        lineage = tracker.get_lineage(data_id)
        if lineage is None:
            raise HTTPException(status_code=404, detail="Lineage record not found")
        return Response(
            content=lineage.model_dump_json(indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=\"lineage_{data_id.replace(':', '-')}.json\""},
        )

    @app.post("/security/check")
    def security_check(body: SecurityCheckBody) -> Dict[str, Any]:
        """Cognitive Firewall: evaluate whether a sensitive operation should be allowed."""
        increment_usage(None, "security_check")
        return check_operation(
            consent_present=body.consent_present,
            encryption_enabled=body.encryption_enabled,
            operation_type=body.operation_type,
        )

    # ---------------------------------------------------------------------------
    # Consent
    # ---------------------------------------------------------------------------

    @app.post("/consent/grant")
    def consent_grant(body: ConsentBody) -> Dict[str, Any]:
        ledger = _get_ledger()
        ledger.record_grant(
            body.user_id, body.category,
            actor=body.actor or "user",
            reason=body.reason,
        )
        return {"ok": True, "user_id": body.user_id, "category": body.category}

    @app.post("/consent/revoke")
    def consent_revoke(body: ConsentBody) -> Dict[str, Any]:
        ledger = _get_ledger()
        ledger.record_revoke(
            body.user_id, body.category,
            actor=body.actor or "user",
            reason=body.reason,
        )
        return {"ok": True, "user_id": body.user_id, "category": body.category}

    # ---------------------------------------------------------------------------
    # Vault (check consent from ledger; encrypt/decrypt; audit)
    # ---------------------------------------------------------------------------

    @app.post("/vault/store")
    def vault_store(body: VaultStoreBody) -> Dict[str, Any]:
        user_id, category, plaintext_base64 = body.user_id, body.category, body.plaintext_base64
        consent_ok = _has_consent_from_ledger(user_id, category)
        if not consent_ok:
            raise HTTPException(status_code=403, detail="Consent not granted for this user and category")
        try:
            plaintext = base64.b64decode(plaintext_base64)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid base64: {e}") from e
        cipher = _get_cipher()
        audit = _get_audit()
        vault = _get_vault()
        encrypted = cipher.encrypt(plaintext)
        vault.store(user_id, category, encrypted)
        increment_usage(None, "vault_store")
        audit.log(AuditAction.ENCRYPT, actor=user_id, resource=category, outcome="success", size_bytes=len(encrypted))
        data_id = _vault_data_id(user_id, category)
        _get_lineage_tracker().create(
            data_id,
            encryption_status="encrypted",
            consent_verified=consent_ok,
        )
        return {"ok": True, "user_id": user_id, "category": category}

    @app.post("/vault/retrieve")
    def vault_retrieve(body: VaultRetrieveBody) -> Dict[str, Any]:
        user_id, category = body.user_id, body.category
        if not _has_consent_from_ledger(user_id, category):
            raise HTTPException(status_code=403, detail="Consent not granted for this user and category")
        vault = _get_vault()
        encrypted = vault.get_encrypted(user_id, category)
        if encrypted is None:
            raise HTTPException(status_code=404, detail="No data for this user and category")
        cipher = _get_cipher()
        audit = _get_audit()
        try:
            plaintext = cipher.decrypt(encrypted)
        except Exception as e:
            raise HTTPException(status_code=500, detail="Decryption failed") from e
        audit.log(
            AuditAction.VAULT_RETRIEVE,
            actor=user_id,
            resource=category,
            outcome="success",
            size_bytes=len(plaintext),
        )
        data_id = _vault_data_id(user_id, category)
        _get_lineage_tracker().append_event(data_id, "read", actor=user_id)
        increment_usage(None, "vault_retrieve")
        return {"ok": True, "plaintext_base64": base64.b64encode(plaintext).decode("ascii")}

    # ---------------------------------------------------------------------------
    # Compliance
    # ---------------------------------------------------------------------------

    def _compliance_data(
        user_id: Optional[str],
    ) -> Dict[str, Any]:
        cipher = _get_cipher()
        consent = _get_consent()
        audit = _get_audit()
        vault = _get_vault()
        report = evaluate(
            encryption_engine=cipher,
            consent_manager=consent,
            audit_logger=audit,
            vault=vault,
        )
        ledger = _get_ledger()
        consent_chain_ok = ledger.verify_chain()
        audit_chain_ok = audit.verify_chain()
        out: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "privacy_score": {
                "score": report.score,
                "risk_level": report.risk_level.value,
                "breakdown": report.breakdown,
                "recommendations": report.recommendations,
            },
            "consent_ledger_verify_chain": consent_chain_ok,
            "audit_logger_verify_chain": audit_chain_ok,
        }
        if user_id is not None:
            out["consent_history"] = ledger.history(user_id)
        return out

    @app.get("/compliance/report")
    def compliance_report(
        user_id: Optional[str] = Query(None, description="Filter consent ledger history by user"),
    ) -> Dict[str, Any]:
        return _compliance_data(user_id)

    @app.get("/compliance/report.pdf")
    def compliance_report_pdf(
        user_id: Optional[str] = Query(None, description="Filter consent ledger history by user"),
    ) -> Response:
        report = _compliance_data(user_id)
        pdf_bytes = generate_compliance_pdf(report, user_id)
        filename = f"neuroguard_compliance_report_{user_id or 'all'}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/compliance/evidence.zip")
    def compliance_evidence_zip(
        user_id: Optional[str] = Query(None, description="Filter consent ledger by user"),
    ) -> Response:
        report = _compliance_data(user_id)
        ledger = _get_ledger()
        audit = _get_audit()
        consent_ledger_json = ledger.export_json(user_id)
        audit_log_json = json.dumps(
            [e.to_dict() for e in audit.get_events()],
            indent=2,
            default=str,
        )
        bundle_bytes = generate_evidence_bundle(
            report,
            user_id,
            consent_ledger_json=consent_ledger_json,
            audit_log_json=audit_log_json,
        )
        filename = f"neuroguard_evidence_bundle_{user_id or 'all'}.zip"
        return Response(
            content=bundle_bytes,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return app


# App instance for uvicorn
app = create_app()


def main() -> None:
    import uvicorn
    uvicorn.run("neuroguard.api.app:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
