"""FastAPI dependency wiring — one DB session per request, plus control-plane auth."""
from __future__ import annotations

import hmac
from typing import Iterator

from fastapi import Header, HTTPException
from sqlalchemy.orm import Session

from sentinel.config import settings
from sentinel.db.session import SessionLocal


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def require_api_key(authorization: str | None = Header(default=None)) -> None:
    """No-op when SENTINEL_API_KEY isn't configured — permissive by default
    for local/dev use, since Phase 0 was designed around registered domains
    and never assumed a caller-identity layer on top. Every mutating route in
    this API depends on this; setting the key is what actually binds a
    caller to the domain they registered for any deployment reachable by
    anyone else (closes an OWASP A01 gap: Phase 0 verifies domain ownership,
    never requester identity)."""
    if not settings.api_key:
        return
    expected = f"Bearer {settings.api_key}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Missing or invalid API key")
