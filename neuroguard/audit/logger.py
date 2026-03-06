"""
Audit logging system for neural and biometric data.

Records who did what and when, with optional outcome, for compliance
and tamper-evident trails. Logs are structured and can be written to
a file, stream, or custom handler.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, TextIO


class AuditAction(str, Enum):
    """Types of auditable actions."""

    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    CONSENT_GRANT = "consent_grant"
    CONSENT_REVOKE = "consent_revoke"
    DATA_ACCESS = "data_access"
    DATA_EXPORT = "data_export"
    PROCESSING = "processing"
    VAULT_STORE = "vault_store"
    VAULT_RETRIEVE = "vault_retrieve"
    VAULT_DELETE = "vault_delete"


@dataclass
class AuditEvent:
    """A single audit log entry."""

    action: AuditAction
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actor: Optional[str] = None
    resource: Optional[str] = None
    outcome: Optional[str] = None  # e.g. "success", "denied", "error"
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for JSON logging."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() + "Z"
        return d

    def to_json(self) -> str:
        """One-line JSON string for log output."""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """
    Writes structured audit events for neural/biometric operations.

    Use alongside encryption and consent: log every sensitive action
    so there is a tamper-evident trail.
    """

    def __init__(self, stream: Optional[TextIO] = None, use_hash_chain: bool = False) -> None:
        """
        Initialize the audit logger.

        Args:
            stream: Where to write log lines (default: stderr).
            use_hash_chain: If True, maintain a hash chain for verification (no plaintext in hashes).
        """
        self._stream = stream if stream is not None else sys.stderr
        self._events: list[AuditEvent] = []
        self._use_hash_chain = use_hash_chain
        self._event_hashes: list[str] = []  # hash of (prev_hash + event_json)

    def log(
        self,
        action: AuditAction,
        actor: Optional[str] = None,
        resource: Optional[str] = None,
        outcome: Optional[str] = None,
        **details: Any,
    ) -> AuditEvent:
        """Record an audit event and write it to the stream."""
        event = AuditEvent(
            action=action,
            actor=actor,
            resource=resource,
            outcome=outcome,
            details=details,
        )
        self._events.append(event)
        if self._use_hash_chain:
            prev_hash = self._event_hashes[-1] if self._event_hashes else ""
            chain_input = prev_hash + event.to_json()
            link_hash = hashlib.sha256(chain_input.encode()).hexdigest()
            self._event_hashes.append(link_hash)
        self._stream.write(event.to_json() + "\n")
        self._stream.flush()
        return event

    def get_events(self, tenant_id: Optional[str] = None) -> list[AuditEvent]:
        """Return events. If tenant_id is set, only events for that tenant (details.tenant_id or 'default')."""
        if tenant_id is None:
            return list(self._events)
        return [e for e in self._events if e.details.get("tenant_id", "default") == tenant_id]

    def clear_events(self) -> None:
        """Clear the in-memory event buffer (does not affect stream)."""
        self._events.clear()
        self._event_hashes.clear()

    def verify_chain(self) -> bool:
        """
        Verify the audit hash chain. Returns True if every link is valid.
        Only meaningful when the logger was created with use_hash_chain=True.
        """
        if not self._use_hash_chain or not self._event_hashes:
            return len(self._events) == 0 or not self._use_hash_chain
        prev_hash = ""
        for i, event in enumerate(self._events):
            chain_input = prev_hash + event.to_json()
            expected = hashlib.sha256(chain_input.encode()).hexdigest()
            if expected != self._event_hashes[i]:
                return False
            prev_hash = self._event_hashes[i]
        return True
