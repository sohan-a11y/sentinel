"""Scan status and findings.

New execution must start from /api/contracts/{id}/runs. This module keeps the
old start URL only as an authenticated migration response so there is no
public free-form-domain path around signed contracts and leases.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sentinel.agents.report_agent import build_summary
from sentinel.api.deps import get_db, require_api_key
from sentinel.db.models import Finding, ScanSession

router = APIRouter(prefix="/api/scans", tags=["scans"], dependencies=[Depends(require_api_key)])


class StartScanRequest(BaseModel):
    domain: str


@router.post("/start", status_code=410)
def start_scan(payload: StartScanRequest) -> dict:
    """Retired: accepting a run-time domain would bypass the control plane."""
    return {
        "detail": (
            "Free-form scan starts are retired. Create a signed contract with "
            "POST /api/contracts, then start POST /api/contracts/{contract_id}/runs."
        )
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
