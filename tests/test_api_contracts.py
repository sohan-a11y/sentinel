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
from sentinel.api.routes import contracts, registration, scans
from sentinel.config import settings
from sentinel.db.models import Base

app = FastAPI()
app.include_router(registration.router)
app.include_router(contracts.router)
app.include_router(scans.router)


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


def _register_and_verify(client: TestClient, domain: str) -> str:
    response = client.post(
        "/api/targets/register",
        json={
            "domain": domain,
            "account_owner": "owner@example.com",
            "canary_check_url_template": f"https://{domain}/canary/{{marker}}",
        },
    )
    token = response.json()["verification_token"]
    with respx.mock:
        respx.get(f"https://{domain}{settings.well_known_path}").mock(
            return_value=httpx.Response(200, text=token)
        )
        verification = client.post(f"/api/targets/{domain}/verify")
    assert verification.json()["verified"] is True
    return token


def _create_contract(client: TestClient, domain: str) -> int:
    contract = client.post(
        "/api/contracts",
        json={
            "domain": domain,
            "approved_by": "security.approver@example.com",
            "allowed_tier": "tier_a",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "max_scan_sessions": 1,
        },
    )
    assert contract.status_code == 201
    return contract.json()["contract_id"]


def test_contract_backed_run_never_accepts_a_free_form_domain(monkeypatch):
    client = _client(monkeypatch)
    domain = "contract-api-test.example"
    token = _register_and_verify(client, domain)

    contract_id = _create_contract(client, domain)
    with respx.mock:
        respx.get(f"https://{domain}{settings.well_known_path}").mock(
            return_value=httpx.Response(200, text=token)
        )
        respx.get(url__regex=rf"https://{domain}/canary/.*").mock(
            return_value=httpx.Response(200, text="canary")
        )
        with patch("sentinel.api.routes.contracts.run_scan_pipeline") as pipeline:
            started = client.post(f"/api/contracts/{contract_id}/runs", json={})

    assert started.status_code == 202
    assert started.json()["contract_id"] is not None
    pipeline.assert_called_once()
    assert len(pipeline.call_args.args) == 1


def test_contract_rejects_tier_b_without_fixture_controls(monkeypatch):
    client = _client(monkeypatch)
    domain = "tier-b-contract-api.example"
    _register_and_verify(client, domain)

    response = client.post(
        "/api/contracts",
        json={
            "domain": domain,
            "approved_by": "security.approver@example.com",
            "allowed_tier": "tier_b",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )

    assert response.status_code == 422


def test_contract_revocation_prevents_a_new_run(monkeypatch):
    client = _client(monkeypatch)
    domain = "revoked-contract-api.example"
    _register_and_verify(client, domain)
    contract_id = _create_contract(client, domain)

    revoked = client.post(
        f"/api/contracts/{contract_id}/revoke",
        json={"reason": "approval withdrawn"},
    )
    start = client.post(f"/api/contracts/{contract_id}/runs", json={})

    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert start.status_code == 409


def test_contract_operations_fail_closed_when_api_auth_is_not_configured(monkeypatch):
    client = _client(monkeypatch)
    monkeypatch.setattr(settings, "api_key", None)

    response = client.post(
        "/api/contracts",
        json={
            "domain": "anything.example",
            "approved_by": "operator@example.com",
            "allowed_tier": "tier_a",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        },
    )

    assert response.status_code == 503
