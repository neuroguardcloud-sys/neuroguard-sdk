"""
Lineage tracker — in-memory lifecycle tracking for neural/biometric data.
"""

from __future__ import annotations

from typing import Literal, Optional

from neuroguard.lineage.models import DataLineage, LineageEvent


class LineageTracker:
    """
    Tracks the lifecycle of neural or biometric data: creation, encryption status,
    consent verification, and access events (read, process, export).
    In-memory implementation; no persistence.
    """

    def __init__(self) -> None:
        self._records: dict[str, DataLineage] = {}

    def create(
        self,
        data_id: str,
        *,
        encryption_status: Literal["encrypted", "plaintext", "unknown"] = "unknown",
        consent_verified: bool = False,
    ) -> DataLineage:
        """Create a new lineage record for the given data_id."""
        if data_id in self._records:
            return self._records[data_id]
        lineage = DataLineage(
            data_id=data_id,
            encryption_status=encryption_status,
            consent_verified=consent_verified,
            events=[LineageEvent(event_type="create")],
        )
        self._records[data_id] = lineage
        return lineage

    def append_event(
        self,
        data_id: str,
        event_type: Literal["create", "read", "process", "export", "delete"],
        *,
        actor: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> Optional[LineageEvent]:
        """Append a new lineage event. Returns None if data_id does not exist."""
        if data_id not in self._records:
            return None
        event = LineageEvent(
            event_type=event_type,
            actor=actor,
            details=details or {},
        )
        self._records[data_id].events.append(event)
        return event

    def get_history(self, data_id: str) -> list[LineageEvent]:
        """Return the ordered list of lineage events for data_id."""
        if data_id not in self._records:
            return []
        return list(self._records[data_id].events)

    def get_lineage(self, data_id: str) -> Optional[DataLineage]:
        """Return the full lineage record for data_id, or None if not found."""
        return self._records.get(data_id)
