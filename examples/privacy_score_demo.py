"""
Demo: NeuroGuard Privacy Score evaluation.

Shows how to evaluate the current privacy posture (encryption, consent,
audit, vault) and interpret the report (score, risk level, recommendations).
"""

import io
import sys

sys.path.insert(0, ".")

from neuroguard import (
    NeuralDataCipher,
    ConsentManager,
    AuditLogger,
    NeuralDataVault,
)
from neuroguard.privacy_score import evaluate, RiskLevel


def main() -> None:
    # Build a full stack: encryption, consent, audit, vault
    cipher = NeuralDataCipher(secret="demo-secret")
    consent = ConsentManager()
    consent.grant_category("neural_signals")
    audit = AuditLogger(stream=io.StringIO())
    vault = NeuralDataVault(consent_manager=consent, audit_logger=audit)

    report = evaluate(
        encryption_engine=cipher,
        consent_manager=consent,
        audit_logger=audit,
        vault=vault,
    )

    print("NeuroGuard Privacy Score:", report.score, "/ 100")
    print("Risk level:", report.risk_level.value)
    print("\nBreakdown:")
    for name, data in report.breakdown.items():
        print(f"  {name}: {data['earned']} / {data['max']}")
    if report.recommendations:
        print("\nRecommendations:")
        for r in report.recommendations:
            print("  -", r)
    else:
        print("\nNo recommendations — all controls in place.")

    # Partial stack: no vault
    report_partial = evaluate(
        encryption_engine=cipher,
        consent_manager=consent,
        audit_logger=audit,
        vault=None,
    )
    print("\n--- Without vault ---")
    print("Score:", report_partial.score, "Risk:", report_partial.risk_level.value)
    print("Recommendations:", report_partial.recommendations)


if __name__ == "__main__":
    main()
