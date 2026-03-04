"""
Secure storage for encrypted neural data.

Simulates on-device vault: store/retrieve only encrypted payloads,
retrieve only when consent is granted for the requested category.
Every operation is audited; plaintext is never logged.
"""

from __future__ import annotations

from typing import Dict, Optional

from neuroguard.audit import AuditAction, AuditLogger
from neuroguard.consent import ConsentManager


class NeuralDataVault:
    """
    In-memory secure storage for encrypted neural/biometric payloads.

    Data is keyed by user_id and category. Retrieve is allowed only when
    consent is granted for that category. All operations are audited
    (no plaintext in audit logs).
    """

    def __init__(self, consent_manager: ConsentManager, audit_logger: AuditLogger) -> None:
        """
        Initialize the vault.

        Args:
            consent_manager: Used to check category consent before retrieve.
            audit_logger: Used to record every store/retrieve/delete (no plaintext).
        """
        if not isinstance(consent_manager, ConsentManager):
            raise TypeError("consent_manager must be a ConsentManager")
        if not isinstance(audit_logger, AuditLogger):
            raise TypeError("audit_logger must be an AuditLogger")

        self._consent = consent_manager
        self._audit = audit_logger
        self._store: Dict[str, Dict[str, bytes]] = {}  # user_id -> { category -> encrypted_payload }

    def store(self, user_id: str, category: str, encrypted_payload: bytes) -> None:
        """
        Store encrypted neural data for a user and category.

        Overwrites any existing payload for the same user_id and category.
        Logs an audit event (user_id, category, size only; no plaintext).
        """
        if user_id not in self._store:
            self._store[user_id] = {}
        self._store[user_id][category] = encrypted_payload
        self._audit.log(
            AuditAction.VAULT_STORE,
            actor=user_id,
            resource=category,
            outcome="success",
            size_bytes=len(encrypted_payload),
        )

    def retrieve(self, user_id: str, category: str) -> bytes:
        """
        Retrieve encrypted payload for a user and category.

        Raises PermissionError if consent is not granted for the category.
        Raises KeyError if no data exists for that user_id or category.
        Logs an audit event (no plaintext).
        """
        if not self._consent.has_consent_for_category(category):
            self._audit.log(
                AuditAction.VAULT_RETRIEVE,
                actor=user_id,
                resource=category,
                outcome="denied",
                reason="consent_not_granted",
            )
            raise PermissionError(f"Consent not granted for category: {category}")

        if user_id not in self._store or category not in self._store[user_id]:
            self._audit.log(
                AuditAction.VAULT_RETRIEVE,
                actor=user_id,
                resource=category,
                outcome="error",
                reason="not_found",
            )
            raise KeyError(f"No data for user_id={user_id!r}, category={category!r}")

        payload = self._store[user_id][category]
        self._audit.log(
            AuditAction.VAULT_RETRIEVE,
            actor=user_id,
            resource=category,
            outcome="success",
            size_bytes=len(payload),
        )
        return payload

    def get_encrypted(self, user_id: str, category: str) -> Optional[bytes]:
        """
        Return encrypted payload for (user_id, category) without consent check.
        Returns None if not found. For API use when consent is enforced externally.
        """
        if user_id not in self._store or category not in self._store[user_id]:
            return None
        return self._store[user_id][category]

    def delete(self, user_id: str) -> None:
        """
        Delete all stored data for the given user_id.

        No-op if user_id has no data. Logs an audit event.
        """
        had_data = user_id in self._store
        if had_data:
            num_categories = len(self._store[user_id])
            del self._store[user_id]
        else:
            num_categories = 0
        self._audit.log(
            AuditAction.VAULT_DELETE,
            actor=user_id,
            resource=user_id,
            outcome="success",
            categories_removed=num_categories,
        )
