"""
PDF generator for NeuroGuard compliance reports.

Uses reportlab to produce a clean PDF with privacy score, breakdown,
recommendations, chain verification, and consent history summary.
"""

from __future__ import annotations

from io import BytesIO
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_compliance_pdf(report: Dict[str, Any], user_id: str | None) -> bytes:
    """
    Generate a PDF from the full compliance report dict.

    Args:
        report: Full compliance report (timestamp, privacy_score, consent_ledger_verify_chain,
                audit_logger_verify_chain, optional consent_history).
        user_id: Optional user id for the report scope (shown in PDF; may differ from report scope).
    """
    return _build_pdf(
        timestamp=report.get("timestamp", ""),
        privacy_score=report.get("privacy_score", {}),
        consent_ledger_verify_chain=report.get("consent_ledger_verify_chain", False),
        audit_logger_verify_chain=report.get("audit_logger_verify_chain", False),
        user_id=user_id,
        consent_history=report.get("consent_history"),
    )


def _build_pdf(
    timestamp: str,
    privacy_score: Dict[str, Any],
    consent_ledger_verify_chain: bool,
    audit_logger_verify_chain: bool,
    user_id: Optional[str] = None,
    consent_history: Optional[List[Dict[str, Any]]] = None,
) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=inch,
        leftMargin=inch,
        topMargin=inch,
        bottomMargin=inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=18,
        spaceAfter=12,
    )
    heading_style = styles["Heading2"]
    body_style = styles["Normal"]

    story: List[Any] = []

    # Title
    story.append(Paragraph("NeuroGuard Compliance Report", title_style))
    story.append(Spacer(1, 0.2 * inch))

    # Timestamp and optional user_id
    story.append(Paragraph(f"<b>Generated:</b> {timestamp}", body_style))
    if user_id:
        story.append(Paragraph(f"<b>User ID:</b> {user_id}", body_style))
    story.append(Spacer(1, 0.3 * inch))

    # Privacy score
    story.append(Paragraph("Privacy Score", heading_style))
    score = privacy_score.get("score", 0)
    risk = privacy_score.get("risk_level", "N/A")
    story.append(Paragraph(f"Score: <b>{score}</b> / 100  |  Risk level: <b>{risk}</b>", body_style))
    story.append(Spacer(1, 0.15 * inch))

    # Breakdown table
    breakdown = privacy_score.get("breakdown", {})
    if breakdown:
        story.append(Paragraph("Breakdown", heading_style))
        data = [["Component", "Earned", "Max"]]
        for name, vals in breakdown.items():
            if isinstance(vals, dict):
                earned = vals.get("earned", 0)
                max_pts = vals.get("max", 0)
                data.append([name.replace("_", " ").title(), str(earned), str(max_pts)])
        t = Table(data, colWidths=[3 * inch, 1 * inch, 1 * inch])
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("ALIGN", (1, 0), (2, -1), "RIGHT"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
                ]
            )
        )
        story.append(t)
        story.append(Spacer(1, 0.2 * inch))

    # Recommendations
    recs = privacy_score.get("recommendations", [])
    if recs:
        story.append(Paragraph("Recommendations", heading_style))
        for r in recs:
            story.append(Paragraph(f"• {r}", body_style))
        story.append(Spacer(1, 0.2 * inch))
    else:
        story.append(Paragraph("Recommendations", heading_style))
        story.append(Paragraph("None — all controls in place.", body_style))
        story.append(Spacer(1, 0.2 * inch))

    # Chain verification
    story.append(Paragraph("Chain Verification", heading_style))
    story.append(
        Paragraph(
            f"Consent ledger chain valid: <b>{'Yes' if consent_ledger_verify_chain else 'No'}</b>",
            body_style,
        )
    )
    story.append(
        Paragraph(
            f"Audit logger chain valid: <b>{'Yes' if audit_logger_verify_chain else 'No'}</b>",
            body_style,
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    # Consent history summary (latest 10)
    if consent_history is not None:
        story.append(Paragraph("Consent History (latest 10)", heading_style))
        latest = consent_history[-10:] if len(consent_history) > 10 else consent_history
        if not latest:
            story.append(Paragraph("No consent events for this user.", body_style))
        else:
            data = [["Type", "Category", "Timestamp", "Actor"]]
            for e in reversed(latest):
                data.append(
                    [
                        e.get("type", ""),
                        e.get("category", ""),
                        e.get("timestamp", "")[:19] if e.get("timestamp") else "",
                        e.get("actor", ""),
                    ]
                )
            t = Table(data, colWidths=[1 * inch, 1.5 * inch, 2 * inch, 1 * inch])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
                    ]
                )
            )
            story.append(t)

    doc.build(story)
    buf.seek(0)
    return buf.read()
