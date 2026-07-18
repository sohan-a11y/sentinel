from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from sentinel.api import deps
from sentinel.api.main import app
from sentinel.config import settings
from sentinel.db.models import Base


def _isolated_client(monkeypatch) -> TestClient:
    """The real app's lifespan calls init_db() against whatever
    sentinel.db.session.engine is bound to (sqlite:///./sentinel.db by
    default) — override get_db with an isolated in-memory DB so these smoke
    tests never touch that file."""
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    TestSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override_get_db():
        db = TestSessionLocal()
        try:
            yield db
            db.commit()
        finally:
            db.close()

    monkeypatch.setattr(settings, "api_key", "test-main-api-key")
    app.dependency_overrides[deps.get_db] = override_get_db
    return TestClient(app, headers={"Authorization": "Bearer test-main-api-key"})


def test_health_check(monkeypatch):
    client = _isolated_client(monkeypatch)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_app_mounts_all_routers():
    paths = {route.path for route in app.routes}
    assert "/api/targets/register" in paths
    assert "/api/scans/start" in paths
    assert "/api/scans/{scan_session_id}/halt" in paths
    assert "/api/audit-log/verify" in paths


def test_audit_log_verify_endpoint_reports_intact_chain_on_fresh_db(monkeypatch):
    client = _isolated_client(monkeypatch)
    response = client.get("/api/audit-log/verify")
    assert response.status_code == 200
    assert response.json()["chain_intact"] is True
