"""FastAPI entry point. Run with: uvicorn sentinel.api.main:app --reload"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

from sentinel.api.deps import get_db
from sentinel.api.routes import killswitch, registration, scans
from sentinel.db.session import init_db
from sentinel.security import audit_log


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Sentinel",
    description="Autonomous, multi-agent CWE-coverage pentesting platform for pre-registered, "
    "ownership-verified domains only.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(registration.router)
app.include_router(scans.router)
app.include_router(killswitch.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/audit-log/verify")
def verify_audit_log(db: Session = Depends(get_db)) -> dict:
    """Recomputes the audit-log hash chain from genesis — proves (or
    disproves) that nothing has been retroactively edited or deleted."""
    ok, reason = audit_log.verify_chain(db)
    return {"chain_intact": ok, "reason": reason}
