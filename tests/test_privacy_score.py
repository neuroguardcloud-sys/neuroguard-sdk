"""Unit tests for the privacy score module."""

import io

import pytest

from neuroguard import NeuralDataCipher, ConsentManager, AuditLogger, NeuralDataVault
from neuroguard.privacy_score import (
    PrivacyScoreReport,
    RiskLevel,
    evaluate,
    ENCRYPTION_POINTS,
    CONSENT_POINTS,
    AUDIT_POINTS,
    VAULT_POINTS,
)


def test_evaluate_full_stack_scores_100() -> None:
    """When all four components are present and valid, score is 100 and risk is Low."""
    cipher = NeuralDataCipher()
    consent = ConsentManager()
    audit = AuditLogger(stream=io.StringIO())
    vault = NeuralDataVault(consent_manager=consent, audit_logger=audit)

    report = evaluate(
        encryption_engine=cipher,
        consent_manager=consent,
        audit_logger=audit,
        vault=vault,
    )

    assert report.score == 100
    assert report.risk_level == RiskLevel.LOW
    assert report.breakdown["encryption"]["earned"] == ENCRYPTION_POINTS
    assert report.breakdown["consent_enforcement"]["earned"] == CONSENT_POINTS
    assert report.breakdown["audit_logging"]["earned"] == AUDIT_POINTS
    assert report.breakdown["vault_access_control"]["earned"] == VAULT_POINTS
    assert len(report.recommendations) == 0


def test_evaluate_no_components_scores_zero() -> None:
    """When all components are None, score is 0 and risk is High."""
    report = evaluate(
        encryption_engine=None,
        consent_manager=None,
        audit_logger=None,
        vault=None,
    )

    assert report.score == 0
    assert report.risk_level == RiskLevel.HIGH
    assert report.breakdown["encryption"]["earned"] == 0
    assert report.breakdown["consent_enforcement"]["earned"] == 0
    assert report.breakdown["audit_logging"]["earned"] == 0
    assert report.breakdown["vault_access_control"]["earned"] == 0
    assert len(report.recommendations) == 4


def test_evaluate_partial_stack() -> None:
    """Encryption + consent + audit only (no vault) gives 80 and Low risk."""
    cipher = NeuralDataCipher()
    consent = ConsentManager()
    audit = AuditLogger(stream=io.StringIO())

    report = evaluate(
        encryption_engine=cipher,
        consent_manager=consent,
        audit_logger=audit,
        vault=None,
    )

    assert report.score == ENCRYPTION_POINTS + CONSENT_POINTS + AUDIT_POINTS
    assert report.score == 80
    assert report.risk_level == RiskLevel.LOW
    assert "vault" in report.recommendations[0].lower() or "NeuralDataVault" in report.recommendations[0]


def test_risk_level_moderate() -> None:
    """Score 50–79 yields Moderate risk."""
    consent = ConsentManager()
    audit = AuditLogger(stream=io.StringIO())
    vault = NeuralDataVault(consent_manager=consent, audit_logger=audit)

    report = evaluate(
        encryption_engine=None,
        consent_manager=consent,
        audit_logger=audit,
        vault=vault,
    )

    assert report.score == CONSENT_POINTS + AUDIT_POINTS + VAULT_POINTS  # 65
    assert report.risk_level == RiskLevel.MODERATE


def test_report_has_required_fields() -> None:
    """PrivacyScoreReport has score, risk_level, breakdown, recommendations."""
    report = evaluate(None, None, None, None)
    assert hasattr(report, "score")
    assert hasattr(report, "risk_level")
    assert hasattr(report, "breakdown")
    assert hasattr(report, "recommendations")
    assert isinstance(report.breakdown, dict)
    assert isinstance(report.recommendations, list)
    assert "encryption" in report.breakdown
    assert "consent_enforcement" in report.breakdown
    assert "audit_logging" in report.breakdown
    assert "vault_access_control" in report.breakdown
