from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from sentinel.api import deps
from sentinel.api.routes import killswitch, registration, scans
from sentinel.config import settings
from sentinel.db.models import Base

app = FastAPI()
app.include_router(registration.router)
app.include_router(scans.router)
app.include_router(killswitch.router)


def _client():
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

    app.dependency_overrides[deps.get_db] = override_get_db
    return TestClient(app)


def test_no_api_key_configured_allows_requests_through(monkeypatch):
    monkeypatch.setattr(settings, "api_key", None)
    client = _client()
    response = client.get("/api/targets/never-registered.com")
    # 404 (not "not registered"), not 401 — proves the auth layer let it through
    assert response.status_code == 404


def test_api_key_configured_rejects_missing_header(monkeypatch):
    monkeypatch.setattr(settings, "api_key", "sekret")
    client = _client()
    response = client.get("/api/targets/never-registered.com")
    assert response.status_code == 401


def test_api_key_configured_rejects_wrong_key(monkeypatch):
    monkeypatch.setattr(settings, "api_key", "sekret")
    client = _client()
    response = client.get(
        "/api/targets/never-registered.com", headers={"Authorization": "Bearer wrong-key"}
    )
    assert response.status_code == 401


def test_api_key_configured_accepts_correct_key(monkeypatch):
    monkeypatch.setattr(settings, "api_key", "sekret")
    client = _client()
    response = client.get(
        "/api/targets/never-registered.com", headers={"Authorization": "Bearer sekret"}
    )
    assert response.status_code == 404  # past auth, into the real 404


def test_api_key_enforced_on_scan_start_and_halt(monkeypatch):
    monkeypatch.setattr(settings, "api_key", "sekret")
    client = _client()
    start_response = client.post("/api/scans/start", json={"domain": "x.com"})
    assert start_response.status_code == 401
    halt_response = client.post("/api/scans/1/halt", json={"reason": "x"})
    assert halt_response.status_code == 401
