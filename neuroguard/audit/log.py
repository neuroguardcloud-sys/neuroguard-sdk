import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from neuroguard.db.schema import get_conn

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def append_event(
    event_type: str,
    actor_id: str,
    subject_id: str,
    record_id: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> str:
    meta_json = json.dumps(meta or {}, separators=(",", ":"), sort_keys=True)
    conn = get_conn()

    # Get previous hash (last row)
    cur = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    prev_hash = row[0] if row else ""

    ts = _now()
    body = f"{ts}|{event_type}|{actor_id}|{subject_id}|{record_id or ''}|{meta_json}|{prev_hash}"
    h = _hash(body)

    conn.execute(
        """
        INSERT INTO audit_log(ts, event_type, actor_id, subject_id, record_id, meta_json, prev_hash, hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (ts, event_type, actor_id, subject_id, record_id, meta_json, prev_hash, h),
    )
    conn.commit()
    conn.close()
    return h

def verify_chain() -> bool:
    conn = get_conn()
    cur = conn.execute("SELECT ts, event_type, actor_id, subject_id, record_id, meta_json, prev_hash, hash FROM audit_log ORDER BY id ASC")
    rows = cur.fetchall()
    conn.close()

    prev = ""
    for (ts, event_type, actor_id, subject_id, record_id, meta_json, prev_hash, h) in rows:
        if prev_hash != prev:
            return False
        body = f"{ts}|{event_type}|{actor_id}|{subject_id}|{record_id or ''}|{meta_json}|{prev_hash}"
        if hashlib.sha256(body.encode("utf-8")).hexdigest() != h:
            return False
        prev = h
    return True