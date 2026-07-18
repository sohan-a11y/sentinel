"""Agent 5 — Report Agent.

Builds headline metrics and full reports (Markdown + PDF) from the persisted
ScanSession / CweApplicability / Finding rows for one scan session. Reads
only; never sends a byte to a target, so no guardrails.enforce_* call is
required here. The Streamlit dashboard (sentinel/dashboard/app.py) reads the
same DB rows live and calls these same functions for report downloads.
"""
from __future__ import annotations

from xml.sax.saxutils import escape as _xml_escape

from sqlalchemy import update
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from sentinel.agents.state import SentinelState
from sentinel.db.models import (
    CweApplicability,
    Finding,
    FindingStatus,
    ScanSession,
    ScanStatus,
    TargetRegistration,
)
from sentinel.db.session import get_session
from sentinel.security import audit_log


def _get_scan_session(db: Session, scan_session_id: int) -> ScanSession:
    scan_session = db.query(ScanSession).filter(ScanSession.id == scan_session_id).one_or_none()
    if scan_session is None:
        raise ValueError(f"ScanSession {scan_session_id} not found")
    return scan_session


def build_summary(db: Session, scan_session_id: int) -> dict:
    _get_scan_session(db, scan_session_id)

    applicability_rows = (
        db.query(CweApplicability).filter(CweApplicability.scan_session_id == scan_session_id).all()
    )
    applicable_cwe_count = sum(1 for row in applicability_rows if row.applicable)
    not_applicable_cwe_count = sum(1 for row in applicability_rows if not row.applicable)
    tested_cwe_count = sum(1 for row in applicability_rows if row.applicable and row.tested)

    findings = db.query(Finding).filter(Finding.scan_session_id == scan_session_id).all()
    confirmed_count = sum(1 for f in findings if f.status == FindingStatus.CONFIRMED)
    unconfirmed_count = sum(1 for f in findings if f.status == FindingStatus.UNCONFIRMED)
    pending_count = sum(1 for f in findings if f.status == FindingStatus.PENDING_VERIFICATION)

    headline = (
        f"{tested_cwe_count}/{applicable_cwe_count} applicable CWEs tested, "
        f"{confirmed_count} confirmed exploitable, {unconfirmed_count} unconfirmed"
    )

    return {
        "scan_session_id": scan_session_id,
        "applicable_cwe_count": applicable_cwe_count,
        "not_applicable_cwe_count": not_applicable_cwe_count,
        "tested_cwe_count": tested_cwe_count,
        "confirmed_count": confirmed_count,
        "unconfirmed_count": unconfirmed_count,
        "pending_count": pending_count,
        "headline": headline,
    }


def _sorted_findings(db: Session, scan_session_id: int) -> list[Finding]:
    findings = db.query(Finding).filter(Finding.scan_session_id == scan_session_id).all()
    return sorted(findings, key=lambda f: (0 if f.status == FindingStatus.CONFIRMED else 1, -f.confidence))


def _applicability_rows(db: Session, scan_session_id: int) -> tuple[list[CweApplicability], list[CweApplicability]]:
    rows = (
        db.query(CweApplicability)
        .filter(CweApplicability.scan_session_id == scan_session_id)
        .order_by(CweApplicability.cwe_id)
        .all()
    )
    applicable = [row for row in rows if row.applicable]
    not_applicable = [row for row in rows if not row.applicable]
    return applicable, not_applicable


def _target_domain(db: Session, scan_session: ScanSession) -> str:
    registration = (
        db.query(TargetRegistration).filter(TargetRegistration.id == scan_session.target_id).one_or_none()
    )
    return registration.domain if registration is not None else "unknown"


def _md_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def export_markdown(db: Session, scan_session_id: int) -> str:
    scan_session = _get_scan_session(db, scan_session_id)
    domain = _target_domain(db, scan_session)
    summary = build_summary(db, scan_session_id)
    findings = _sorted_findings(db, scan_session_id)
    applicable_rows, not_applicable_rows = _applicability_rows(db, scan_session_id)

    lines: list[str] = []
    lines.append(f"# Sentinel Pentest Report — {domain}")
    lines.append("")
    lines.append(f"**{summary['headline']}**")
    lines.append("")
    lines.append("## Scan Details")
    lines.append("")
    lines.append(f"- **Target domain:** {domain}")
    lines.append(f"- **Scan session ID:** {scan_session_id}")
    lines.append(f"- **Status:** {scan_session.status.value}")
    lines.append(f"- **Environment tier:** {scan_session.environment_tier.value}")
    lines.append(f"- **Started at:** {scan_session.started_at.isoformat() if scan_session.started_at else 'n/a'}")
    lines.append(f"- **Ended at:** {scan_session.ended_at.isoformat() if scan_session.ended_at else 'n/a'}")
    if scan_session.status == ScanStatus.HALTED:
        lines.append(f"- **Halted reason:** {scan_session.halted_reason or 'n/a'}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if findings:
        lines.append("| CWE ID | Endpoint | Tier | Detection Method | Confidence | Status |")
        lines.append("|---|---|---|---|---|---|")
        for f in findings:
            lines.append(
                f"| {_md_cell(f.cwe_id)} | {_md_cell(f.endpoint)} | {_md_cell(f.tier.value)} | "
                f"{_md_cell(f.detection_method)} | {f.confidence:.2f} | {_md_cell(f.status.value)} |"
            )
    else:
        lines.append("No findings recorded.")
    lines.append("")

    lines.append("## CWE Coverage Appendix")
    lines.append("")
    lines.append("### Applicable CWEs")
    lines.append("")
    if applicable_rows:
        lines.append("| CWE ID | Name | Tested | Detection Method | Reason |")
        lines.append("|---|---|---|---|---|")
        for row in applicable_rows:
            lines.append(
                f"| {_md_cell(row.cwe_id)} | {_md_cell(row.cwe_name)} | {'yes' if row.tested else 'no'} | "
                f"{_md_cell(row.detection_method or 'n/a')} | {_md_cell(row.reason)} |"
            )
    else:
        lines.append("No applicable CWEs recorded.")
    lines.append("")

    lines.append("### Not Applicable CWEs")
    lines.append("")
    if not_applicable_rows:
        lines.append("| CWE ID | Name | Reason |")
        lines.append("|---|---|---|")
        for row in not_applicable_rows:
            lines.append(f"| {_md_cell(row.cwe_id)} | {_md_cell(row.cwe_name)} | {_md_cell(row.reason)} |")
    else:
        lines.append("No not-applicable CWEs recorded.")
    lines.append("")

    return "\n".join(lines)


def _pdf_cell(value: object, style) -> Paragraph:
    return Paragraph(_xml_escape(str(value)), style)


def _pdf_table(header: list[str], rows: list[list[object]], col_widths: list[float], body_style, header_style) -> Table:
    data = [[_pdf_cell(h, header_style) for h in header]]
    for row in rows:
        data.append([_pdf_cell(cell, body_style) for cell in row])
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
            ]
        )
    )
    return table


def export_pdf(db: Session, scan_session_id: int, output_path: str) -> None:
    scan_session = _get_scan_session(db, scan_session_id)
    domain = _target_domain(db, scan_session)
    summary = build_summary(db, scan_session_id)
    findings = _sorted_findings(db, scan_session_id)
    applicable_rows, not_applicable_rows = _applicability_rows(db, scan_session_id)

    styles = getSampleStyleSheet()
    cell_style = styles["BodyText"]
    header_style = styles["BodyText"].clone("HeaderCell")
    header_style.textColor = colors.white
    header_style.fontName = "Helvetica-Bold"

    doc = SimpleDocTemplate(output_path, pagesize=letter, title=f"Sentinel Pentest Report - {domain}")
    story: list = []

    story.append(Paragraph(f"Sentinel Pentest Report — {_xml_escape(domain)}", styles["Title"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(_xml_escape(summary["headline"]), styles["Heading3"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Scan Details", styles["Heading2"]))
    details_rows = [
        ["Target domain", domain],
        ["Scan session ID", str(scan_session_id)],
        ["Status", scan_session.status.value],
        ["Environment tier", scan_session.environment_tier.value],
        ["Started at", scan_session.started_at.isoformat() if scan_session.started_at else "n/a"],
        ["Ended at", scan_session.ended_at.isoformat() if scan_session.ended_at else "n/a"],
    ]
    if scan_session.status == ScanStatus.HALTED:
        details_rows.append(["Halted reason", scan_session.halted_reason or "n/a"])
    story.append(_pdf_table(["Field", "Value"], details_rows, [140, 300], cell_style, header_style))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Findings", styles["Heading2"]))
    if findings:
        findings_rows = [
            [f.cwe_id, f.endpoint, f.tier.value, f.detection_method, f"{f.confidence:.2f}", f.status.value]
            for f in findings
        ]
        story.append(
            _pdf_table(
                ["CWE ID", "Endpoint", "Tier", "Detection Method", "Confidence", "Status"],
                findings_rows,
                [50, 150, 45, 75, 55, 65],
                cell_style,
                header_style,
            )
        )
    else:
        story.append(Paragraph("No findings recorded.", cell_style))
    story.append(Spacer(1, 14))

    story.append(Paragraph("CWE Coverage Appendix", styles["Heading2"]))
    story.append(Paragraph("Applicable CWEs", styles["Heading3"]))
    if applicable_rows:
        applicable_data = [
            [row.cwe_id, row.cwe_name, "yes" if row.tested else "no", row.detection_method or "n/a", row.reason]
            for row in applicable_rows
        ]
        story.append(
            _pdf_table(
                ["CWE ID", "Name", "Tested", "Detection Method", "Reason"],
                applicable_data,
                [45, 110, 40, 80, 165],
                cell_style,
                header_style,
            )
        )
    else:
        story.append(Paragraph("No applicable CWEs recorded.", cell_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Not Applicable CWEs", styles["Heading3"]))
    if not_applicable_rows:
        na_data = [[row.cwe_id, row.cwe_name, row.reason] for row in not_applicable_rows]
        story.append(
            _pdf_table(["CWE ID", "Name", "Reason"], na_data, [55, 140, 245], cell_style, header_style)
        )
    else:
        story.append(Paragraph("No not-applicable CWEs recorded.", cell_style))

    doc.build(story)


def report_node(state: SentinelState) -> dict:
    scan_session_id = state["scan_session_id"]
    from datetime import datetime, timezone
    from sentinel.db.models import ScanStatus
    with get_session() as db:
        summary = build_summary(db, scan_session_id)
        audit_log.record(
            db,
            agent="report_agent",
            action="report_summary_built",
            payload={"scan_session_id": scan_session_id, "headline": summary["headline"]},
        )
        # Compare-and-set prevents a report thread holding an old RUNNING
        # object from overwriting a concurrent manual halt, revocation, or
        # execution failure with COMPLETED.
        transitioned = db.execute(
            update(ScanSession)
            .where(
                ScanSession.id == scan_session_id,
                ScanSession.status == ScanStatus.RUNNING,
            )
            .values(status=ScanStatus.COMPLETED, ended_at=datetime.now(timezone.utc))
        ).rowcount
        if transitioned:
            db.flush()
            scan_session = db.get(ScanSession, scan_session_id)
            if scan_session is not None:
                db.refresh(scan_session)
                from sentinel.control_plane import service

                service.complete_lease_for_scan(db, scan_session=scan_session)
    return {"current_phase": "report_complete"}
