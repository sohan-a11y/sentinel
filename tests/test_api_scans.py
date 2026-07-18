from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from sentinel.api import deps
from sentinel.api.routes import contracts, killswitch, registration, scans
from sentinel.config import settings
from sentinel.db.models import Base

app = FastAPI()
app.include_router(registration.router)
app.include_router(contracts.router)
app.include_router(scans.router)
app.include_router(killswitch.router)


def _client(monkeypatch) -> TestClient:
    monkeypatch.setattr(settings, "control_plane_signing_key", "test-contract-signing-key")
    monkeypatch.setattr(settings, "api_key", "test-contract-api-key")
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
    return TestClient(app, headers={"Authorization": "Bearer test-contract-api-key"})


def _register_and_verify(client: TestClient, domain: str = "scan-api-test.com") -> tuple[str, str]:
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
        respx.get(f"https://{domain}{settings.well_known_path}").mock(
            return_value=httpx.Response(200, text=token)
        )
        verified = client.post(f"/api/targets/{domain}/verify")
    assert verified.status_code == 200
    return domain, token


def _create_contract(client: TestClient, domain: str) -> int:
    response = client.post(
        "/api/contracts",
        json={
            "domain": domain,
            "approved_by": "security.approver@example.com",
            "allowed_tier": "tier_a",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "max_scan_sessions": 1,
            "max_requests": 100,
        },
    )
    assert response.status_code == 201
    return response.json()["contract_id"]


def _start_contract_scan(client: TestClient, domain: str, verification_token: str, contract_id: int):
    with respx.mock:
        respx.get(f"https://{domain}{settings.well_known_path}").mock(
            return_value=httpx.Response(200, text=verification_token)
        )
        respx.get(url__regex=rf"https://{domain}/api/users/.*").mock(
            return_value=httpx.Response(200, text="marker-body")
        )
        with patch("sentinel.api.routes.contracts.run_scan_pipeline") as pipeline:
            response = client.post(f"/api/contracts/{contract_id}/runs", json={})
    return response, pipeline


def test_free_form_scan_start_is_retired(monkeypatch):
    client = _client(monkeypatch)

    response = client.post("/api/scans/start", json={"domain": "never-registered.com"})

    assert response.status_code == 410
    assert "signed contract" in response.json()["detail"].lower()


def test_contract_start_returns_session_and_schedules_pipeline(monkeypatch):
    client = _client(monkeypatch)
    domain, verification_token = _register_and_verify(client)
    contract_id = _create_contract(client, domain)

    response, pipeline = _start_contract_scan(client, domain, verification_token, contract_id)

    assert response.status_code == 202
    body = response.json()
    assert body["scan_session_id"] is not None
    assert body["contract_id"] == contract_id
    assert body["recipe"] == "recon.v1"
    pipeline.assert_called_once()
    assert pipeline.call_args.args[0] == body["scan_session_id"]
    assert len(pipeline.call_args.args) == 1


def test_get_scan_returns_summary_after_contract_start(monkeypatch):
    client = _client(monkeypatch)
    domain, verification_token = _register_and_verify(client)
    contract_id = _create_contract(client, domain)
    start_response, _ = _start_contract_scan(client, domain, verification_token, contract_id)
    scan_session_id = start_response.json()["scan_session_id"]

    get_response = client.get(f"/api/scans/{scan_session_id}")

    assert get_response.status_code == 200
    body = get_response.json()
    assert "headline" in body
    assert body["status"] == "running"


def test_get_scan_404_for_unknown_id(monkeypatch):
    client = _client(monkeypatch)

    response = client.get("/api/scans/999999")

    assert response.status_code == 404


def test_get_findings_empty_list_for_fresh_contract_scan(monkeypatch):
    client = _client(monkeypatch)
    domain, verification_token = _register_and_verify(client)
    contract_id = _create_contract(client, domain)
    start_response, _ = _start_contract_scan(client, domain, verification_token, contract_id)
    scan_session_id = start_response.json()["scan_session_id"]

    response = client.get(f"/api/scans/{scan_session_id}/findings")

    assert response.status_code == 200
    assert response.json() == []


def test_halt_scan_updates_status_and_revokes_contract_run(monkeypatch):
    client = _client(monkeypatch)
    domain, verification_token = _register_and_verify(client)
    contract_id = _create_contract(client, domain)
    start_response, _ = _start_contract_scan(client, domain, verification_token, contract_id)
    scan_session_id = start_response.json()["scan_session_id"]

    halt_response = client.post(f"/api/scans/{scan_session_id}/halt", json={"reason": "operator stop"})

    assert halt_response.status_code == 200
    body = halt_response.json()
    assert body["status"] == "halted"
    assert body["halted_reason"] == "operator stop"
    assert client.get(f"/api/scans/{scan_session_id}").json()["status"] == "halted"


def test_halt_scan_404_for_unknown_id(monkeypatch):
    client = _client(monkeypatch)

    response = client.post("/api/scans/999999/halt", json={"reason": "x"})

    assert response.status_code == 404
