"""Scan lifecycle: start (Phase 0 gate + pipeline kickoff), status, findings."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sentinel.agents.graph import run_scan_pipeline
from sentinel.agents.report_agent import build_summary
from sentinel.api.deps import get_db, require_api_key
from sentinel.db.models import Finding, ScanSession
from sentinel.phase0 import registry
from sentinel.security.guardrails import UnauthorizedTargetError

router = APIRouter(prefix="/api/scans", tags=["scans"], dependencies=[Depends(require_api_key)])


class StartScanRequest(BaseModel):
    domain: str


def _run_pipeline_in_background(scan_session_id: int, domain: str, environment_tier: str) -> None:
    """Runs in a FastAPI BackgroundTask thread with its OWN db session — the
    request's session is closed by the time this executes."""
    run_scan_pipeline(scan_session_id, domain, environment_tier)


@router.post("/start", status_code=202)
def start_scan(payload: StartScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)) -> dict:
    # Phase 0 is executing here: registry.start_scan_session re-runs BOTH
    # Phase 0 checks (authorization + a fresh canary probe) before a single
    # agent gets to run — this call is the gate for the entire pipeline below.
    try:
        scan_session = registry.start_scan_session(db, payload.domain)
    except UnauthorizedTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    db.flush()
    scan_session_id = scan_session.id
    environment_tier = scan_session.environment_tier.value

    background_tasks.add_task(_run_pipeline_in_background, scan_session_id, payload.domain, environment_tier)

    return {
        "scan_session_id": scan_session_id,
        "status": scan_session.status.value,
        "environment_tier": environment_tier,
    }


@router.get("/{scan_session_id}")
def get_scan(scan_session_id: int, db: Session = Depends(get_db)) -> dict:
    scan_session = db.get(ScanSession, scan_session_id)
    if scan_session is None:
        raise HTTPException(status_code=404, detail=f"ScanSession {scan_session_id} not found")
    summary = build_summary(db, scan_session_id)
    return {
        "scan_session_id": scan_session_id,
        "status": scan_session.status.value,
        "environment_tier": scan_session.environment_tier.value,
        "halted_reason": scan_session.halted_reason,
        "started_at": scan_session.started_at.isoformat() if scan_session.started_at else None,
        "ended_at": scan_session.ended_at.isoformat() if scan_session.ended_at else None,
        **summary,
    }


@router.get("/{scan_session_id}/findings")
def get_findings(scan_session_id: int, db: Session = Depends(get_db)) -> list[dict]:
    scan_session = db.get(ScanSession, scan_session_id)
    if scan_session is None:
        raise HTTPException(status_code=404, detail=f"ScanSession {scan_session_id} not found")
    findings = db.query(Finding).filter(Finding.scan_session_id == scan_session_id).all()
    return [f.to_dict() for f in findings]
