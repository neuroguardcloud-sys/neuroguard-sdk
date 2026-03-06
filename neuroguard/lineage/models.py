"""
Data lineage models — lifecycle and access events for neural/biometric data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field


class LineageEvent(BaseModel):
    """A single event in a data lineage (read, process, export, etc.)."""

    event_type: Literal["create", "read", "process", "export", "delete"] = Field(
        ...,
        description="Type of lifecycle or access event",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the event occurred",
    )
    actor: Optional[str] = None
    details: dict = Field(default_factory=dict, description="Optional event metadata")


class DataLineage(BaseModel):
    """Lineage record for a piece of neural or biometric data."""

    data_id: str = Field(..., description="Unique identifier for the data")
    tenant_id: str = Field(default="default", description="Tenant scope for hosted use")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the lineage record was created",
    )
    encryption_status: Literal["encrypted", "plaintext", "unknown"] = Field(
        default="unknown",
        description="Whether the data is stored encrypted",
    )
    consent_verified: bool = Field(
        default=False,
        description="Whether consent was verified for this data",
    )
    events: list[LineageEvent] = Field(
        default_factory=list,
        description="Ordered list of lifecycle and access events",
    )
