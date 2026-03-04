"""
Consent and permission manager.

Tracks user consent for neural/biometric data use (e.g. processing, export, analytics)
so that data never leaves the device without explicit consent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Optional, Set

from neuroguard.consent.ledger import ConsentLedger


class ConsentScope(str, Enum):
    """Scope of data use that requires consent."""

    PROCESSING = "processing"  # On-device or local processing
    EXPORT = "export"  # Sending data off-device
    ANALYTICS = "analytics"  # Usage for analytics
    STORAGE = "storage"  # Persistent storage
    SHARING = "sharing"  # Sharing with third parties


class ConsentLevel(str, Enum):
    """Level of consent granted."""

    NONE = "none"
    EXPLICIT = "explicit"
    REVOKED = "revoked"


@dataclass
class ConsentRecord:
    """A single consent decision for a scope."""

    scope: ConsentScope
    level: ConsentLevel
    granted_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    metadata: Dict[str, str] = field(default_factory=dict)


class ConsentManager:
    """
    Manages consent and permissions for neural/biometric data.

    Use before performing any operation that touches sensitive data:
    check consent for the required scope, and record grants/revocations.
    """

    def __init__(
        self,
        consent_ledger: Optional["ConsentLedger"] = None,
        ledger_user_id: str = "default",
    ) -> None:
        self._consents: Dict[ConsentScope, ConsentRecord] = {}
        self._category_consents: Dict[str, bool] = {}  # category -> granted
        self._consent_ledger = consent_ledger
        self._ledger_user_id = ledger_user_id

    def grant(self, scope: ConsentScope, metadata: Optional[Dict[str, str]] = None) -> ConsentRecord:
        """Record explicit consent for a scope."""
        now = datetime.now(timezone.utc)
        record = ConsentRecord(
            scope=scope,
            level=ConsentLevel.EXPLICIT,
            granted_at=now,
            metadata=metadata or {},
        )
        self._consents[scope] = record
        if self._consent_ledger is not None:
            self._consent_ledger.record_grant(self._ledger_user_id, scope.value)
        return record

    def revoke(self, scope: ConsentScope) -> ConsentRecord:
        """Revoke consent for a scope."""
        now = datetime.now(timezone.utc)
        record = ConsentRecord(
            scope=scope,
            level=ConsentLevel.REVOKED,
            granted_at=self._consents.get(scope).granted_at if scope in self._consents else None,
            revoked_at=now,
        )
        self._consents[scope] = record
        if self._consent_ledger is not None:
            self._consent_ledger.record_revoke(self._ledger_user_id, scope.value)
        return record

    def has_consent(self, scope: ConsentScope) -> bool:
        """Return True if explicit consent is currently granted for the scope."""
        record = self._consents.get(scope)
        return record is not None and record.level == ConsentLevel.EXPLICIT

    def require_consent(self, *scopes: ConsentScope) -> None:
        """
        Raise PermissionError if any of the given scopes lack explicit consent.
        Use before performing an operation that needs consent.
        """
        missing: Set[ConsentScope] = set()
        for scope in scopes:
            if not self.has_consent(scope):
                missing.add(scope)
        if missing:
            raise PermissionError(f"Missing consent for scope(s): {sorted(s.name for s in missing)}")

    def get_record(self, scope: ConsentScope) -> Optional[ConsentRecord]:
        """Return the current consent record for a scope, or None."""
        return self._consents.get(scope)

    def list_consents(self) -> Dict[ConsentScope, ConsentRecord]:
        """Return a copy of all consent records."""
        return dict(self._consents)

    def grant_category(self, category: str) -> None:
        """Record explicit consent for a data category (e.g. for vault retrieve)."""
        self._category_consents[category] = True
        if self._consent_ledger is not None:
            self._consent_ledger.record_grant(self._ledger_user_id, category)

    def revoke_category(self, category: str) -> None:
        """Revoke consent for a data category."""
        self._category_consents[category] = False
        if self._consent_ledger is not None:
            self._consent_ledger.record_revoke(self._ledger_user_id, category)

    def has_consent_for_category(self, category: str) -> bool:
        """Return True if consent is granted for the given category."""
        return self._category_consents.get(category, False)
