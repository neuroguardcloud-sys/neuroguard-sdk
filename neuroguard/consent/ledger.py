"""
Tamper-evident ConsentLedger — append-only event log with optional file persistence.

Records grant/revoke events with user_id, category, timestamp, actor, reason.
Each event includes hash_prev and hash_current for chain verification.
Default storage: ~/.neuroguard/consent_ledger.jsonl (JSONL, one JSON object per line).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DEFAULT_LEDGER_DIR = os.path.join(os.path.expanduser("~"), ".neuroguard")
DEFAULT_LEDGER_PATH = os.path.join(DEFAULT_LEDGER_DIR, "consent_ledger.jsonl")


def _payload_for_hash(event: Dict[str, Any]) -> str:
    """Canonical JSON for hashing (excludes hash_prev, hash_current)."""
    payload = {k: v for k, v in event.items() if k not in ("hash_prev", "hash_current")}
    return json.dumps(payload, sort_keys=True)


class ConsentLedger:
    """
    Append-only, hash-chained log of consent grant/revoke events.

    Optional persistence: if path is None, uses ~/.neuroguard/consent_ledger.jsonl.
    Each event is stored with hash_prev and hash_current. Use verify_chain() to
    detect tampering. history() and export_json() return list[dict].
    """

    def __init__(self, path: Optional[str] = None) -> None:
        """
        Initialize the ledger.

        Args:
            path: Path to JSONL file. If None, uses ~/.neuroguard/consent_ledger.jsonl.
        """
        self._path = path if path is not None else DEFAULT_LEDGER_PATH
        self._events: List[Dict[str, Any]] = []
        self._load()

    def _ensure_dir(self) -> None:
        """Create parent directory of ledger file if it does not exist."""
        dirpath = os.path.dirname(self._path)
        if dirpath:
            os.makedirs(dirpath, exist_ok=True)

    def _load(self) -> None:
        """Load existing events from file into memory."""
        self._events = []
        if not os.path.isfile(self._path):
            return
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    self._events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    def record_grant(
        self,
        user_id: str,
        category: str,
        actor: str = "user",
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append a grant event to the ledger and persist to file."""
        return self._append("grant", user_id, category, actor, reason)

    def record_revoke(
        self,
        user_id: str,
        category: str,
        actor: str = "user",
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append a revoke event to the ledger and persist to file."""
        return self._append("revoke", user_id, category, actor, reason)

    def _append(
        self,
        type_: str,
        user_id: str,
        category: str,
        actor: str,
        reason: Optional[str],
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        event: Dict[str, Any] = {
            "type": type_,
            "user_id": user_id,
            "category": category,
            "timestamp": now,
            "actor": actor,
        }
        if reason is not None:
            event["reason"] = reason

        hash_prev = self._events[-1].get("hash_current", "") if self._events else ""
        payload_str = _payload_for_hash(event)
        hash_current = hashlib.sha256((hash_prev + payload_str).encode()).hexdigest()
        event["hash_prev"] = hash_prev
        event["hash_current"] = hash_current

        self._events.append(event)
        self._ensure_dir()
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")
        return event

    def history(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return events as list of dicts. If user_id is set, filter to that user."""
        if user_id is None:
            return list(self._events)
        return [e for e in self._events if e.get("user_id") == user_id]

    def verify_chain(self) -> bool:
        """Verify file and in-memory ordering: each hash_current matches recomputed value."""
        prev_hash = ""
        for event in self._events:
            payload = _payload_for_hash(event)
            expected = hashlib.sha256((prev_hash + payload).encode()).hexdigest()
            if event.get("hash_current") != expected:
                return False
            prev_hash = event["hash_current"]
        return True

    def export_json(self, user_id: Optional[str] = None) -> str:
        """Export events as JSON string. If user_id is set, only that user's events."""
        events = self.history(user_id=user_id)
        return json.dumps(events, indent=2)
