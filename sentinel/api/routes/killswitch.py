"""The one human touchpoint after Phase 0: halt a running scan immediately."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sentinel.agents.kill_switch import manual_halt
from sentinel.api.deps import get_db, require_api_key
from sentinel.db.models import ScanSession

router = APIRouter(prefix="/api/scans", tags=["kill-switch"], dependencies=[Depends(require_api_key)])


class HaltRequest(BaseModel):
    reason: str = "manual operator halt"


@router.post("/{scan_session_id}/halt")
def halt_scan(scan_session_id: int, payload: HaltRequest = HaltRequest(), db: Session = Depends(get_db)) -> dict:
    scan_session = db.get(ScanSession, scan_session_id)
    if scan_session is None:
        raise HTTPException(status_code=404, detail=f"ScanSession {scan_session_id} not found")

    manual_halt(db, scan_session_id, reason=payload.reason)
    db.refresh(scan_session)
    return {
        "scan_session_id": scan_session_id,
        "status": scan_session.status.value,
        "halted_reason": scan_session.halted_reason,
    }
