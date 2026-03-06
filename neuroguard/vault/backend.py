"""
Pluggable vault storage backends — protocol and implementations.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Optional, Protocol

from neuroguard.settings import Settings


class VaultBackend(Protocol):
    """Protocol for vault storage: store, retrieve, delete, count."""

    def store(self, user_id: str, category: str, payload: bytes) -> None:
        """Store encrypted payload for (user_id, category). Overwrites if exists."""
        ...

    def get(self, user_id: str, category: str) -> Optional[bytes]:
        """Return payload for (user_id, category) or None if not found."""
        ...

    def delete(self, user_id: str, category: Optional[str] = None) -> None:
        """Delete one (user_id, category) or all records for user_id if category is None."""
        ...

    def count_records(self) -> int:
        """Return the number of stored (user_id, category) records."""
        ...


class InMemoryBackend:
    """In-memory vault backend: dict-based storage."""

    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, bytes]] = {}

    def store(self, user_id: str, category: str, payload: bytes) -> None:
        if user_id not in self._store:
            self._store[user_id] = {}
        self._store[user_id][category] = payload

    def get(self, user_id: str, category: str) -> Optional[bytes]:
        if user_id not in self._store or category not in self._store[user_id]:
            return None
        return self._store[user_id][category]

    def delete(self, user_id: str, category: Optional[str] = None) -> None:
        if user_id not in self._store:
            return
        if category is None:
            del self._store[user_id]
        elif category in self._store[user_id]:
            del self._store[user_id][category]

    def count_records(self) -> int:
        return sum(len(cats) for cats in self._store.values())


def _safe_segment(s: str) -> str:
    """Replace path-unsafe chars with underscore for use in file paths."""
    return re.sub(r"[^\w.\-]", "_", s, flags=re.ASCII)


class FileBackend:
    """File-based vault backend: one file per (user_id, category) under a base directory."""

    def __init__(self, base_path: Path) -> None:
        self._base = Path(base_path)
        self._base.mkdir(parents=True, exist_ok=True)

    def _path(self, user_id: str, category: str) -> Path:
        return self._base / _safe_segment(user_id) / f"{_safe_segment(category)}.bin"

    def store(self, user_id: str, category: str, payload: bytes) -> None:
        p = self._path(user_id, category)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(payload)

    def get(self, user_id: str, category: str) -> Optional[bytes]:
        p = self._path(user_id, category)
        if not p.exists():
            return None
        return p.read_bytes()

    def delete(self, user_id: str, category: Optional[str] = None) -> None:
        if category is None:
            user_dir = self._base / _safe_segment(user_id)
            if user_dir.exists():
                for f in user_dir.iterdir():
                    f.unlink()
                user_dir.rmdir()
        else:
            p = self._path(user_id, category)
            if p.exists():
                p.unlink()

    def count_records(self) -> int:
        return sum(1 for _ in self._base.rglob("*.bin"))


def get_backend(settings: Settings) -> VaultBackend:
    """Return a vault backend for the given settings."""
    if settings.vault_backend == "file":
        path = settings.vault_store_path.strip()
        base = Path(path) if path else (Path.home() / ".neuroguard" / "vault_store")
        return FileBackend(base)
    return InMemoryBackend()
