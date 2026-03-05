from datetime import datetime, timezone
from typing import Optional
from neuroguard.db.schema import get_conn

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def grant_consent(subject_id: str, grantee_id: str, scope: str) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO consent(subject_id, grantee_id, scope, is_active, created_at) VALUES (?, ?, ?, 1, ?)",
        (subject_id, grantee_id, scope, _now()),
    )
    conn.commit()
    conn.close()

def revoke_consent(subject_id: str, grantee_id: str, scope: str) -> None:
    conn = get_conn()
    conn.execute(
        """
        UPDATE consent
        SET is_active=0, revoked_at=?
        WHERE subject_id=? AND grantee_id=? AND scope=? AND is_active=1
        """,
        (_now(), subject_id, grantee_id, scope),
    )
    conn.commit()
    conn.close()

def has_consent(subject_id: str, grantee_id: str, scope: str) -> bool:
    conn = get_conn()
    cur = conn.execute(
        """
        SELECT 1 FROM consent
        WHERE subject_id=? AND grantee_id=? AND scope=? AND is_active=1
        LIMIT 1
        """,
        (subject_id, grantee_id, scope),
    )
    ok = cur.fetchone() is not None
    conn.close()
    return ok