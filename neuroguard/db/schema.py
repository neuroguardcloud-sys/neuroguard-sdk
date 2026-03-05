import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "neuroguard.db"

def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def init_db() -> None:
    conn = get_conn()
    cur = conn.cursor()

    # Consent table: who can do what to which data subject
    cur.execute("""
    CREATE TABLE IF NOT EXISTS consent (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_id TEXT NOT NULL,
        grantee_id TEXT NOT NULL,
        scope TEXT NOT NULL,               -- e.g. "vault:read", "vault:write", "vault:delete"
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        revoked_at TEXT
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_consent_subject ON consent(subject_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_consent_grantee ON consent(grantee_id);")

    # Audit log: append-only hash chain
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        event_type TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        record_id TEXT,
        meta_json TEXT,
        prev_hash TEXT,
        hash TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()