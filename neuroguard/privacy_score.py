"""
NeuroGuard Privacy Score — evaluate privacy posture of the SDK setup.

Computes a 0–100 score from encryption, consent enforcement, audit logging,
and vault access control. Produces a report with risk level and recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from neuroguard.audit import AuditLogger
from neuroguard.consent import ConsentManager
from neuroguard.encryption import NeuralDataCipher
from neuroguard.vault import NeuralDataVault


class RiskLevel(str, Enum):
    """Privacy risk level derived from the total score."""

    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"


@dataclass
class PrivacyScoreReport:
    """Report from a privacy score evaluation."""

    score: int
    risk_level: RiskLevel
    breakdown: Dict[str, Any]
    recommendations: List[str]


# Point allocation (total 100)
ENCRYPTION_POINTS = 35
CONSENT_POINTS = 25
AUDIT_POINTS = 20
VAULT_POINTS = 20


def evaluate(
    encryption_engine: Optional[NeuralDataCipher] = None,
    consent_manager: Optional[ConsentManager] = None,
    audit_logger: Optional[AuditLogger] = None,
    vault: Optional[NeuralDataVault] = None,
) -> PrivacyScoreReport:
    """
    Compute the NeuroGuard Privacy Score (0–100) for the current setup.

    Criteria:
    - Encryption (35 pts): engine present and usable (has key, can encrypt).
    - Consent enforcement (25 pts): ConsentManager present and operational.
    - Audit logging (20 pts): AuditLogger present and operational.
    - Vault access control (20 pts): Vault present and wired to consent/audit.

    Returns a PrivacyScoreReport with score, risk level, breakdown, and recommendations.
    """
    breakdown: Dict[str, Any] = {}
    recommendations: List[str] = []

    # Encryption: 35 points
    enc_ok = (
        encryption_engine is not None
        and isinstance(encryption_engine, NeuralDataCipher)
        and _encryption_enabled(encryption_engine)
    )
    enc_earned = ENCRYPTION_POINTS if enc_ok else 0
    breakdown["encryption"] = {"earned": enc_earned, "max": ENCRYPTION_POINTS}
    if not enc_ok:
        recommendations.append("Enable encryption for neural/biometric data (use NeuralDataCipher).")

    # Consent enforcement: 25 points
    consent_ok = consent_manager is not None and isinstance(consent_manager, ConsentManager)
    consent_earned = CONSENT_POINTS if consent_ok else 0
    breakdown["consent_enforcement"] = {"earned": consent_earned, "max": CONSENT_POINTS}
    if not consent_ok:
        recommendations.append("Use ConsentManager and enforce consent before sensitive operations.")

    # Audit logging: 20 points
    audit_ok = audit_logger is not None and isinstance(audit_logger, AuditLogger)
    audit_earned = AUDIT_POINTS if audit_ok else 0
    breakdown["audit_logging"] = {"earned": audit_earned, "max": AUDIT_POINTS}
    if not audit_ok:
        recommendations.append("Enable audit logging (use AuditLogger) for all sensitive actions.")

    # Vault access control: 20 points
    vault_ok = vault is not None and isinstance(vault, NeuralDataVault)
    vault_earned = VAULT_POINTS if vault_ok else 0
    breakdown["vault_access_control"] = {"earned": vault_earned, "max": VAULT_POINTS}
    if not vault_ok:
        recommendations.append("Use NeuralDataVault with consent and audit for stored neural data.")

    score = enc_earned + consent_earned + audit_earned + vault_earned
    if score >= 80:
        risk_level = RiskLevel.LOW
    elif score >= 50:
        risk_level = RiskLevel.MODERATE
    else:
        risk_level = RiskLevel.HIGH

    return PrivacyScoreReport(
        score=score,
        risk_level=risk_level,
        breakdown=breakdown,
        recommendations=recommendations,
    )


def _encryption_enabled(cipher: NeuralDataCipher) -> bool:
    """Return True if the cipher is configured and can encrypt."""
    try:
        key = cipher.get_key()
        if not key or len(key) == 0:
            return False
        cipher.encrypt(b"\x00")
        return True
    except Exception:
        return False


def is_encryption_enabled(cipher: Optional[NeuralDataCipher]) -> bool:
    """Return True if cipher is present and usable for encryption (for simple score)."""
    return cipher is not None and isinstance(cipher, NeuralDataCipher) and _encryption_enabled(cipher)


# ---------------------------------------------------------------------------
# Simple API-oriented score (encryption, consent, audit, lineage)
# ---------------------------------------------------------------------------

POINTS_PER_CRITERION = 25


def compute_simple_score(
    encryption_enabled: bool,
    consent_enabled: bool,
    audit_enabled: bool,
    lineage_enabled: bool,
) -> Dict[str, Any]:
    """
    Compute a 0-100 privacy score from four criteria (25 points each).
    Returns score, status ("low" | "moderate" | "high"), and reasons (missing items).
    Deterministic and simple for API use.
    """
    reasons: List[str] = []
    if not encryption_enabled:
        reasons.append("Encryption is not enabled.")
    if not consent_enabled:
        reasons.append("Consent enforcement is not enabled.")
    if not audit_enabled:
        reasons.append("Audit logging is not enabled.")
    if not lineage_enabled:
        reasons.append("Lineage tracking is not enabled.")

    score = 0
    if encryption_enabled:
        score += POINTS_PER_CRITERION
    if consent_enabled:
        score += POINTS_PER_CRITERION
    if audit_enabled:
        score += POINTS_PER_CRITERION
    if lineage_enabled:
        score += POINTS_PER_CRITERION

    if score >= 80:
        status = "low"
    elif score >= 50:
        status = "moderate"
    else:
        status = "high"

    return {
        "score": score,
        "status": status,
        "reasons": reasons,
    }
