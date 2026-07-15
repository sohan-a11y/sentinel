from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinel.config import settings
from sentinel.db.models import Base


@pytest.fixture(autouse=True)
def _hermetic_security_settings(monkeypatch):
    """The test suite must not depend on whatever a developer's local .env
    happens to contain — a real SENTINEL_API_KEY or SENTINEL_AUDIT_LOG_HMAC_KEY
    on disk should never change test behavior. Individual tests (e.g.
    test_api_auth.py) still override these explicitly via their own
    monkeypatch calls, which take effect after this fixture runs."""
    monkeypatch.setattr(settings, "api_key", None)
    monkeypatch.setattr(settings, "audit_log_hmac_key", None)


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
