"""
Cognitive Firewall — security check for sensitive operations.

Evaluates consent, encryption, and operation type to allow or block with a reason.
"""

from __future__ import annotations

from typing import Any, Dict


def check_operation(
    consent_present: bool,
    encryption_enabled: bool,
    operation_type: str,
) -> Dict[str, Any]:
    """
    Evaluate whether a sensitive operation should be allowed.

    Deterministic: allowed only when consent is present and encryption is enabled.
    Returns allowed (bool), risk_level ("low" | "moderate" | "high"), and reason (str).
    """
    if not consent_present:
        return {
            "allowed": False,
            "risk_level": "high",
            "reason": "Consent not present for this operation.",
        }
    if not encryption_enabled:
        return {
            "allowed": False,
            "risk_level": "moderate",
            "reason": "Encryption is not enabled.",
        }
    return {
        "allowed": True,
        "risk_level": "low",
        "reason": "Allowed.",
    }
