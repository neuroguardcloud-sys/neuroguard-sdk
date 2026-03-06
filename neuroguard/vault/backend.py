"""
Pluggable vault storage backends — protocol and implementations.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Optional, Protocol

from neuroguard.settings import Settings


DEFAULT_TENANT = "default"


class VaultBackend(Protocol):
    """Protocol for vault storage: store, retrieve, delete, count. Optional tenant scoping."""

    def store(
        self,
        user_id: str,
        category: str,
        payload: bytes,
        tenant_id: str = DEFAULT_TENANT,
    ) -> None:
        """Store encrypted payload for (tenant_id, user_id, category). Overwrites if exists."""
        ...

    def get(
        self,
        user_id: str,
        category: str,
        tenant_id: str = DEFAULT_TENANT,
    ) -> Optional[bytes]:
        """Return payload for (tenant_id, user_id, category) or None if not found."""
        ...

    def delete(
        self,
        user_id: str,
        category: Optional[str] = None,
        tenant_id: str = DEFAULT_TENANT,
    ) -> None:
        """Delete one (user_id, category) or all records for user_id in tenant. category=None = all for user."""
        ...

    def count_records(self, tenant_id: Optional[str] = None) -> int:
        """Return count: if tenant_id is None, total; else count for that tenant only."""
        ...


class InMemoryBackend:
    """In-memory vault backend: dict-based storage, tenant-scoped."""

    def __init__(self) -> None:
        # tenant_id -> user_id -> category -> payload
        self._store: Dict[str, Dict[str, Dict[str, bytes]]] = {}

    def store(
        self,
        user_id: str,
        category: str,
        payload: bytes,
        tenant_id: str = DEFAULT_TENANT,
    ) -> None:
        if tenant_id not in self._store:
            self._store[tenant_id] = {}
        if user_id not in self._store[tenant_id]:
            self._store[tenant_id][user_id] = {}
        self._store[tenant_id][user_id][category] = payload

    def get(
        self,
        user_id: str,
        category: str,
        tenant_id: str = DEFAULT_TENANT,
    ) -> Optional[bytes]:
        if tenant_id not in self._store or user_id not in self._store[tenant_id] or category not in self._store[tenant_id][user_id]:
            return None
        return self._store[tenant_id][user_id][category]

    def delete(
        self,
        user_id: str,
        category: Optional[str] = None,
        tenant_id: str = DEFAULT_TENANT,
    ) -> None:
        if tenant_id not in self._store or user_id not in self._store[tenant_id]:
            return
        if category is None:
            del self._store[tenant_id][user_id]
        elif category in self._store[tenant_id][user_id]:
            del self._store[tenant_id][user_id][category]

    def count_records(self, tenant_id: Optional[str] = None) -> int:
        if tenant_id is not None:
            if tenant_id not in self._store:
                return 0
            return sum(len(cats) for cats in self._store[tenant_id].values())
        return sum(
            sum(len(cats) for cats in users.values())
            for users in self._store.values()
        )


def _safe_segment(s: str) -> str:
    """Replace path-unsafe chars with underscore for use in file paths."""
    return re.sub(r"[^\w.\-]", "_", s, flags=re.ASCII)


class FileBackend:
    """File-based vault backend: one file per (tenant_id, user_id, category) under base directory."""

    def __init__(self, base_path: Path) -> None:
        self._base = Path(base_path)
        self._base.mkdir(parents=True, exist_ok=True)

    def _path(self, user_id: str, category: str, tenant_id: str = DEFAULT_TENANT) -> Path:
        return self._base / _safe_segment(tenant_id) / _safe_segment(user_id) / f"{_safe_segment(category)}.bin"

    def store(
        self,
        user_id: str,
        category: str,
        payload: bytes,
        tenant_id: str = DEFAULT_TENANT,
    ) -> None:
        p = self._path(user_id, category, tenant_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(payload)

    def get(
        self,
        user_id: str,
        category: str,
        tenant_id: str = DEFAULT_TENANT,
    ) -> Optional[bytes]:
        p = self._path(user_id, category, tenant_id)
        if not p.exists():
            return None
        return p.read_bytes()

    def delete(
        self,
        user_id: str,
        category: Optional[str] = None,
        tenant_id: str = DEFAULT_TENANT,
    ) -> None:
        if category is None:
            user_dir = self._base / _safe_segment(tenant_id) / _safe_segment(user_id)
            if user_dir.exists():
                for f in user_dir.iterdir():
                    f.unlink()
                user_dir.rmdir()
        else:
            p = self._path(user_id, category, tenant_id)
            if p.exists():
                p.unlink()

    def count_records(self, tenant_id: Optional[str] = None) -> int:
        if tenant_id is not None:
            tenant_dir = self._base / _safe_segment(tenant_id)
            if not tenant_dir.exists():
                return 0
            return sum(1 for _ in tenant_dir.rglob("*.bin"))
        return sum(1 for _ in self._base.rglob("*.bin"))


def get_backend(settings: Settings) -> VaultBackend:
    """Return a vault backend for the given settings."""
    if settings.vault_backend == "file":
        path = settings.vault_store_path.strip()
        base = Path(path) if path else (Path.home() / ".neuroguard" / "vault_store")
        return FileBackend(base)
    return InMemoryBackend()
