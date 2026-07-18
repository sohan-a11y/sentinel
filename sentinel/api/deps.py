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
    """Fail closed when the API has no configured operator credential.

    Phase 0 proves control of a domain, not the identity of an API caller.
    Leaving this optional would make a network-reachable deployment an
    anonymous origin-verification and scan-control service.  A single API
    key is intentionally only an MVP operator boundary; tenant- and
    asset-scoped identity remains a production prerequisite.
    """
    if not settings.api_key:
        raise HTTPException(
            status_code=503,
            detail="SENTINEL_API_KEY must be configured before the API can be used",
        )
    expected = f"Bearer {settings.api_key}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Missing or invalid API key")


def require_configured_api_key(authorization: str | None = Header(default=None)) -> None:
    """Compatibility dependency for contract routes.

    Every routed API now uses the same fail-closed key check; retaining this
    name makes the stricter contract boundary explicit at its call sites.
    """
    require_api_key(authorization)
