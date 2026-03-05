import os
import uuid
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken

VAULT_DIR = Path(__file__).resolve().parent / "_vault_store"
VAULT_DIR.mkdir(parents=True, exist_ok=True)

def _get_fernet() -> Fernet:
    key = os.environ.get("NEUROGUARD_MASTER_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "Missing NEUROGUARD_MASTER_KEY env var. Set it to a Fernet key."
        )
    return Fernet(key.encode("utf-8"))

def generate_master_key() -> str:
    return Fernet.generate_key().decode("utf-8")

def store_bytes(data: bytes) -> str:
    f = _get_fernet()
    record_id = str(uuid.uuid4())
    ciphertext = f.encrypt(data)
    (VAULT_DIR / f"{record_id}.bin").write_bytes(ciphertext)
    return record_id

def retrieve_bytes(record_id: str) -> bytes:
    f = _get_fernet()
    p = VAULT_DIR / f"{record_id}.bin"
    if not p.exists():
        raise FileNotFoundError("Record not found")
    ciphertext = p.read_bytes()
    try:
        return f.decrypt(ciphertext)
    except InvalidToken:
        raise RuntimeError("Decryption failed (wrong key or corrupted data)")

def delete_record(record_id: str) -> bool:
    p = VAULT_DIR / f"{record_id}.bin"
    if p.exists():
        p.unlink()
        return True
    return False