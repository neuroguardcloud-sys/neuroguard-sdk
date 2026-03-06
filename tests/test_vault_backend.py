"""Tests for pluggable vault backends."""

import tempfile
from pathlib import Path

import pytest

from neuroguard.settings import Settings
from neuroguard.vault.backend import FileBackend, InMemoryBackend, get_backend


def test_get_backend_in_memory_by_default() -> None:
    """get_backend with default settings returns InMemoryBackend."""
    settings = Settings()
    assert settings.vault_backend == "in_memory"
    backend = get_backend(settings)
    assert isinstance(backend, InMemoryBackend)


def test_get_backend_file_returns_file_backend() -> None:
    """get_backend with vault_backend='file' returns FileBackend."""
    settings = Settings(vault_backend="file", vault_store_path="/tmp/ng_vault")
    backend = get_backend(settings)
    assert isinstance(backend, FileBackend)


def test_in_memory_backend_store_get_count() -> None:
    """InMemoryBackend store, get, and count_records work."""
    backend = InMemoryBackend()
    assert backend.count_records() == 0
    backend.store("u1", "cat1", b"payload1")
    backend.store("u1", "cat2", b"payload2")
    assert backend.count_records() == 2
    assert backend.get("u1", "cat1") == b"payload1"
    assert backend.get("u1", "cat2") == b"payload2"
    assert backend.get("u2", "cat1") is None


def test_in_memory_backend_delete() -> None:
    """InMemoryBackend delete by (user_id, category) and delete all for user."""
    backend = InMemoryBackend()
    backend.store("u1", "c1", b"a")
    backend.store("u1", "c2", b"b")
    backend.store("u2", "c1", b"c")
    backend.delete("u1", "c1")
    assert backend.count_records() == 2
    assert backend.get("u1", "c1") is None
    assert backend.get("u1", "c2") == b"b"
    backend.delete("u1", None)
    assert backend.count_records() == 1
    assert backend.get("u2", "c1") == b"c"


def test_file_backend_store_get_count(tmp_path: Path) -> None:
    """FileBackend store, get, and count_records in temp dir."""
    backend = FileBackend(tmp_path)
    assert backend.count_records() == 0
    backend.store("user_1", "neural", b"encrypted_data")
    backend.store("user_1", "bio", b"more_data")
    assert backend.count_records() == 2
    assert backend.get("user_1", "neural") == b"encrypted_data"
    assert backend.get("user_1", "bio") == b"more_data"
    assert backend.get("unknown", "neural") is None


def test_file_backend_delete(tmp_path: Path) -> None:
    """FileBackend delete one category and delete all for user."""
    backend = FileBackend(tmp_path)
    backend.store("u1", "c1", b"a")
    backend.store("u1", "c2", b"b")
    backend.store("u2", "c1", b"c")
    backend.delete("u1", "c1")
    assert backend.count_records() == 2
    assert backend.get("u1", "c1") is None
    assert backend.get("u1", "c2") == b"b"
    backend.delete("u1", None)
    assert backend.count_records() == 1
    assert backend.get("u2", "c1") == b"c"


def test_neural_data_vault_with_file_backend(tmp_path: Path) -> None:
    """NeuralDataVault with FileBackend: store and retrieve work (consent granted)."""
    from neuroguard import ConsentManager, AuditLogger, NeuralDataVault
    from neuroguard.vault.backend import FileBackend

    consent = ConsentManager()
    consent.grant_category("neural")
    audit = AuditLogger()
    backend = FileBackend(tmp_path)
    vault = NeuralDataVault(consent_manager=consent, audit_logger=audit, backend=backend)
    vault.store("user_1", "neural", b"encrypted_payload")
    assert vault.count_records() == 1
    out = vault.retrieve("user_1", "neural")
    assert out == b"encrypted_payload"
    assert vault.get_encrypted("user_1", "neural") == b"encrypted_payload"
