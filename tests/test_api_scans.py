from __future__ import annotations

import httpx
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from unittest.mock import patch

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


def _register_and_verify(client, domain="scan-api-test.com"):
    reg_response = client.post(
        "/api/targets/register",
        json={
            "domain": domain,
            "account_owner": "alice@corp.com",
            "canary_check_url_template": f"https://{domain}/api/users/{{marker}}",
        },
    )
    token = reg_response.json()["verification_token"]
    with respx.mock:
        respx.get(f"https://{domain}{settings.well_known_path}").mock(return_value=httpx.Response(200, text=token))
        client.post(f"/api/targets/{domain}/verify")
    return domain


def test_start_scan_rejects_unregistered_domain():
    client = _client()
    response = client.post("/api/scans/start", json={"domain": "never-registered.com"})
    assert response.status_code == 403


@respx.mock
def test_start_scan_returns_session_and_schedules_pipeline():
    client = _client()
    domain = _register_and_verify(client)

    respx.get(url__regex=rf"https://{domain}/api/users/.*").mock(return_value=httpx.Response(200, text="marker-body"))

    with patch("sentinel.api.routes.scans.run_scan_pipeline") as mock_pipeline:
        response = client.post("/api/scans/start", json={"domain": domain})

    assert response.status_code == 202
    body = response.json()
    assert body["scan_session_id"] is not None
    mock_pipeline.assert_called_once()
    called_args = mock_pipeline.call_args[0]
    assert called_args[0] == body["scan_session_id"]
    assert called_args[1] == domain


@respx.mock
def test_get_scan_returns_summary_after_start():
    client = _client()
    domain = _register_and_verify(client)
    respx.get(url__regex=rf"https://{domain}/api/users/.*").mock(return_value=httpx.Response(200, text="marker-body"))

    with patch("sentinel.api.routes.scans.run_scan_pipeline"):
        start_response = client.post("/api/scans/start", json={"domain": domain})
    scan_session_id = start_response.json()["scan_session_id"]

    get_response = client.get(f"/api/scans/{scan_session_id}")
    assert get_response.status_code == 200
    body = get_response.json()
    assert "headline" in body
    assert body["status"] == "running"


def test_get_scan_404_for_unknown_id():
    client = _client()
    response = client.get("/api/scans/999999")
    assert response.status_code == 404


def test_get_findings_empty_list_for_fresh_scan():
    client = _client()
    domain = _register_and_verify(client)
    with respx.mock:
        respx.get(url__regex=rf"https://{domain}/api/users/.*").mock(return_value=httpx.Response(200, text="marker-body"))
        with patch("sentinel.api.routes.scans.run_scan_pipeline"):
            start_response = client.post("/api/scans/start", json={"domain": domain})
    scan_session_id = start_response.json()["scan_session_id"]

    response = client.get(f"/api/scans/{scan_session_id}/findings")
    assert response.status_code == 200
    assert response.json() == []


def test_halt_scan_updates_status():
    client = _client()
    domain = _register_and_verify(client)
    with respx.mock:
        respx.get(url__regex=rf"https://{domain}/api/users/.*").mock(return_value=httpx.Response(200, text="marker-body"))
        with patch("sentinel.api.routes.scans.run_scan_pipeline"):
            start_response = client.post("/api/scans/start", json={"domain": domain})
    scan_session_id = start_response.json()["scan_session_id"]

    halt_response = client.post(f"/api/scans/{scan_session_id}/halt", json={"reason": "operator stop"})
    assert halt_response.status_code == 200
    body = halt_response.json()
    assert body["status"] == "halted"
    assert body["halted_reason"] == "operator stop"

    get_response = client.get(f"/api/scans/{scan_session_id}")
    assert get_response.json()["status"] == "halted"


def test_halt_scan_404_for_unknown_id():
    client = _client()
    response = client.post("/api/scans/999999/halt", json={"reason": "x"})
    assert response.status_code == 404
