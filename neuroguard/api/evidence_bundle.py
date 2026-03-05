"""
Evidence bundle generator — ZIP of compliance artifacts for export.

Includes PDF report, JSON report, consent ledger, audit log, and hash chain proof.
"""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from typing import Any, Dict


def generate_evidence_bundle(
    report: Dict[str, Any],
    user_id: str | None,
    *,
    consent_ledger_json: str = "[]",
    audit_log_json: str = "[]",
) -> bytes:
    """
    Build a ZIP file containing all compliance artifacts.

    Args:
        report: Full compliance report dict (timestamp, privacy_score,
                consent_ledger_verify_chain, audit_logger_verify_chain, etc.).
        user_id: Optional user id (used for PDF title/scope).
        consent_ledger_json: JSON string of consent ledger entries (from ledger.export_json()).
        audit_log_json: JSON string of audit logger entries.

    Returns:
        ZIP file as bytes.
    """
    from neuroguard.api.pdf_report import generate_compliance_pdf

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # compliance_report.pdf
        pdf_bytes = generate_compliance_pdf(report, user_id)
        zf.writestr("compliance_report.pdf", pdf_bytes)

        # compliance_report.json
        zf.writestr("compliance_report.json", json.dumps(report, indent=2, default=str))

        # consent_ledger.json
        zf.writestr("consent_ledger.json", consent_ledger_json)

        # audit_log.json
        zf.writestr("audit_log.json", audit_log_json)

        # hash_chain_proof.txt
        consent_ok = report.get("consent_ledger_verify_chain", False)
        audit_ok = report.get("audit_logger_verify_chain", False)
        proof_lines = [
            "NeuroGuard Hash Chain Verification",
            "",
            f"Consent ledger chain valid: {'Yes' if consent_ok else 'No'}",
            f"Audit logger chain valid: {'Yes' if audit_ok else 'No'}",
        ]
        zf.writestr("hash_chain_proof.txt", "\n".join(proof_lines))

    buf.seek(0)
    return buf.read()
