"""
NeuroGuard vault API — secure vault endpoints using consent store, audit log, and vault storage.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from neuroguard.consent.store import grant_consent, revoke_consent, has_consent
from neuroguard.audit.log import append_event, verify_chain
from neuroguard.vault.vault import store_bytes, retrieve_bytes, delete_record

router = APIRouter(prefix="/vault", tags=["vault"])


class ConsentReq(BaseModel):
    subject_id: str
    grantee_id: str
    scope: str  # e.g. "vault:read" | "vault:write" | "vault:delete"


class StoreReq(BaseModel):
    actor_id: str
    subject_id: str
    payload: str


class RetrieveReq(BaseModel):
    actor_id: str
    subject_id: str


@router.post("/consent/grant")
def consent_grant(req: ConsentReq):
    grant_consent(req.subject_id, req.grantee_id, req.scope)
    append_event("consent:grant", req.grantee_id, req.subject_id, meta={"scope": req.scope})
    return {"ok": True}


@router.post("/consent/revoke")
def consent_revoke(req: ConsentReq):
    revoke_consent(req.subject_id, req.grantee_id, req.scope)
    append_event("consent:revoke", req.grantee_id, req.subject_id, meta={"scope": req.scope})
    return {"ok": True}


@router.post("/store")
def vault_store(req: StoreReq):
    if not has_consent(req.subject_id, req.actor_id, "vault:write"):
        raise HTTPException(status_code=403, detail="No consent for vault:write")
    record_id = store_bytes(req.payload.encode("utf-8"))
    append_event(
        "vault:store",
        req.actor_id,
        req.subject_id,
        record_id=record_id,
        meta={"bytes": len(req.payload)},
    )
    return {"ok": True, "record_id": record_id}


@router.post("/retrieve/{record_id}")
def vault_retrieve(record_id: str, req: RetrieveReq):
    if not has_consent(req.subject_id, req.actor_id, "vault:read"):
        raise HTTPException(status_code=403, detail="No consent for vault:read")
    try:
        data = retrieve_bytes(record_id).decode("utf-8")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Record not found")
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    append_event("vault:retrieve", req.actor_id, req.subject_id, record_id=record_id)
    return {"ok": True, "record_id": record_id, "payload": data}


@router.post("/delete/{record_id}")
def vault_delete(record_id: str, req: RetrieveReq):
    if not has_consent(req.subject_id, req.actor_id, "vault:delete"):
        raise HTTPException(status_code=403, detail="No consent for vault:delete")
    deleted = delete_record(record_id)
    append_event(
        "vault:delete",
        req.actor_id,
        req.subject_id,
        record_id=record_id,
        meta={"deleted": deleted},
    )
    return {"ok": True, "record_id": record_id, "deleted": deleted}


@router.get("/audit/verify")
def audit_verify():
    return {"ok": verify_chain()}
