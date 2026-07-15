"""Integration glue between the in-memory LangGraph state and the DB.

Each agent module (cwe_mapping, dispatcher, verification) owns its own
reasoning and its own audit-log entries, but three of them hand back plain
dicts in `state` rather than writing straight to the DB themselves — that's
deliberate (it's what let them be built independently against
sentinel/agents/state.py without fighting over write access to the same
tables). These two nodes are the sync points: after dispatch, the
CweApplicability rows cwe_mapping_agent already created get their
tested/detection_method flags synced from the mutated checklist; after
verification, the Finding table gets its rows created for the first time.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from sentinel.agents.state import SentinelState
from sentinel.db.models import (
    ActionTier,
    CweApplicability,
    Finding,
    FindingStatus,
    ScanSession,
)
from sentinel.db.session import get_session


def sync_cwe_checklist(db: Session, scan_session_id: int, cwe_checklist: list) -> int:
    rows_by_id = {
        row.cwe_id: row
        for row in db.query(CweApplicability).filter(CweApplicability.scan_session_id == scan_session_id).all()
    }
    tested_count = 0
    for item in cwe_checklist:
        row = rows_by_id.get(item.get("cwe_id"))
        if row is None:
            continue
        if item.get("tested"):
            row.tested = True
            row.detection_method = item.get("detection_method")
        if row.tested:
            tested_count += 1
    db.flush()

    scan_session = db.get(ScanSession, scan_session_id)
    if scan_session is not None:
        scan_session.tested_cwe_count = tested_count
        db.flush()
    return tested_count


def sync_cwe_checklist_node(state: SentinelState) -> dict:
    scan_session_id = state["scan_session_id"]
    cwe_checklist = state.get("cwe_checklist", [])
    with get_session() as db:
        sync_cwe_checklist(db, scan_session_id, cwe_checklist)
    return {"current_phase": "cwe_checklist_synced"}


_STATUS_MAP = {
    "confirmed": FindingStatus.CONFIRMED,
    "unconfirmed": FindingStatus.UNCONFIRMED,
}


def persist_findings(db: Session, scan_session_id: int, verified_findings: list) -> list[Finding]:
    rows: list[Finding] = []
    for finding in verified_findings:
        row = Finding(
            scan_session_id=scan_session_id,
            cwe_id=finding.get("cwe_id", "UNKNOWN"),
            endpoint=finding.get("endpoint", ""),
            tier=ActionTier(finding.get("tier", "tier_a")),
            detection_method=finding.get("detection_method", "unknown"),
            poc_evidence=finding.get("poc_evidence", ""),
            confidence=float(finding.get("confidence", 0.0)),
            status=_STATUS_MAP.get(finding.get("status"), FindingStatus.PENDING_VERIFICATION),
            verification_method=finding.get("verification_method"),
            verification_note=finding.get("verification_note"),
        )
        db.add(row)
        rows.append(row)
    db.flush()
    return rows


def persist_findings_node(state: SentinelState) -> dict:
    scan_session_id = state["scan_session_id"]
    verified_findings = state.get("verified_findings", [])
    with get_session() as db:
        persist_findings(db, scan_session_id, verified_findings)
    return {"current_phase": "findings_persisted"}


def mark_unverified_due_to_halt(raw_findings: list) -> list:
    """Used when the kill switch trips during dispatch. Verification itself
    makes live requests to the target — running it after a halt would violate
    the halt, so raw findings are demoted straight to unconfirmed instead of
    being independently re-checked."""
    return [
        {
            **finding,
            "status": "unconfirmed",
            "verification_method": "skipped_scan_halted",
            "verification_note": (
                "scan was halted before independent verification could run — treated as "
                "unconfirmed pending manual review, not dropped"
            ),
        }
        for finding in raw_findings
    ]


def finalize_halted_findings_node(state: SentinelState) -> dict:
    raw_findings = state.get("raw_findings", [])
    verified = mark_unverified_due_to_halt(raw_findings)
    return {"verified_findings": verified, "current_phase": "verification_skipped_scan_halted"}
