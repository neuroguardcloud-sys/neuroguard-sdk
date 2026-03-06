"""
In-memory secure vault for encrypted neural data.

Uses a pluggable backend (in-memory or file). Consent and audit are enforced here;
storage is delegated to the backend.
"""

from __future__ import annotations

from typing import Optional

from neuroguard.audit import AuditAction, AuditLogger
from neuroguard.consent import ConsentManager
from neuroguard.vault.backend import InMemoryBackend, VaultBackend


class NeuralDataVault:
    """
    Secure storage for encrypted neural/biometric payloads.

    Data is keyed by user_id and category. Retrieve is allowed only when
    consent is granted for that category. All operations are audited.
    Storage is delegated to a pluggable backend (in_memory or file).
    """

    def __init__(
        self,
        consent_manager: ConsentManager,
        audit_logger: AuditLogger,
        backend: Optional[VaultBackend] = None,
    ) -> None:
        if not isinstance(consent_manager, ConsentManager):
            raise TypeError("consent_manager must be a ConsentManager")
        if not isinstance(audit_logger, AuditLogger):
            raise TypeError("audit_logger must be an AuditLogger")
        self._consent = consent_manager
        self._audit = audit_logger
        self._backend = backend if backend is not None else InMemoryBackend()

    def store(self, user_id: str, category: str, encrypted_payload: bytes) -> None:
        self._backend.store(user_id, category, encrypted_payload)
        self._audit.log(
            AuditAction.VAULT_STORE,
            actor=user_id,
            resource=category,
            outcome="success",
            size_bytes=len(encrypted_payload),
        )

    def count_records(self) -> int:
        return self._backend.count_records()

    def retrieve(self, user_id: str, category: str) -> bytes:
        if not self._consent.has_consent_for_category(category):
            self._audit.log(
                AuditAction.VAULT_RETRIEVE,
                actor=user_id,
                resource=category,
                outcome="denied",
                reason="consent_not_granted",
            )
            raise PermissionError(f"Consent not granted for category: {category}")

        payload = self._backend.get(user_id, category)
        if payload is None:
            self._audit.log(
                AuditAction.VAULT_RETRIEVE,
                actor=user_id,
                resource=category,
                outcome="error",
                reason="not_found",
            )
            raise KeyError(f"No data for user_id={user_id!r}, category={category!r}")

        self._audit.log(
            AuditAction.VAULT_RETRIEVE,
            actor=user_id,
            resource=category,
            outcome="success",
            size_bytes=len(payload),
        )
        return payload

    def get_encrypted(self, user_id: str, category: str) -> Optional[bytes]:
        """Return encrypted payload for (user_id, category) without consent check. None if not found."""
        return self._backend.get(user_id, category)

    def delete(self, user_id: str) -> None:
        """Delete all stored data for the given user_id."""
        n = self._backend.count_records()
        self._backend.delete(user_id, None)
        n_after = self._backend.count_records()
        num_removed = n - n_after
        self._audit.log(
            AuditAction.VAULT_DELETE,
            actor=user_id,
            resource=user_id,
            outcome="success",
            categories_removed=num_removed,
        )