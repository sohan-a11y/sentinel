from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256

import httpx
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from sentinel.api import deps
from sentinel.api.routes import contracts, registration
from sentinel.config import settings
from sentinel.db.models import Base
from sentinel.phase0 import registry as registry_module
from sentinel.zero_trust.policy import generate_ed25519_keypair


app = FastAPI()
app.include_router(registration.router)
app.include_router(contracts.router)


def _client(monkeypatch, *, raise_server_exceptions: bool = True) -> tuple[TestClient, str]:
    private_key, public_key = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "control_plane_signing_key", "test-contract-signing-key")
    monkeypatch.setattr(settings, "runner_permit_private_key", private_key)
    monkeypatch.setattr(settings, "deployment_mode", "development")
    monkeypatch.setattr(settings, "enable_development_runner_permit_issuance", True)
    monkeypatch.setattr(settings, "api_key", "test-contract-api-key")
    # Permit issuance deliberately rechecks ownership. Keep API-route tests
    # deterministic after the initial real verification; the control-plane
    # suite separately proves this fresh gate blocks a stale target before it
    # consumes a budget.
    real_run_ownership_verification = registry_module.run_ownership_verification

    def verified_target_or_real_verification(db, domain):
        current = registry_module.get_active_registration(db, domain)
        if current is not None and current.is_ownership_verified:
            return current
        return real_run_ownership_verification(db, domain)

    monkeypatch.setattr(
        registry_module,
        "run_ownership_verification",
        verified_target_or_real_verification,
    )
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

    app.dependency_overrides.clear()
    app.dependency_overrides[deps.get_db] = override_get_db
    return (
        TestClient(
            app,
            headers={"Authorization": "Bearer test-contract-api-key"},
            raise_server_exceptions=raise_server_exceptions,
        ),
        public_key,
    )


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


def _create_contract(
    client: TestClient,
    domain: str,
    *,
    max_scan_sessions: int = 1,
    customer_authorization_reference: str | None = "customer-email-ticket-2026-0718",
) -> int:
    request = {
        "domain": domain,
        "approved_by": "security.approver@example.com",
        "allowed_tier": "tier_a",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "max_scan_sessions": max_scan_sessions,
        "max_requests": 7,
    }
    if customer_authorization_reference is not None:
        request["customer_authorization_reference"] = customer_authorization_reference
    response = client.post(
        "/api/contracts",
        json=request,
    )
    assert response.status_code == 201
    if customer_authorization_reference is not None:
        assert customer_authorization_reference not in str(response.json())
    return response.json()["contract_id"]


def test_issues_a_customer_local_permit_without_exporting_the_private_signing_key(monkeypatch):
    client, public_key = _client(monkeypatch)
    domain = "runner-permit.example"
    _register_and_verify(client, domain)
    contract_id = _create_contract(client, domain)

    response = client.post(
        f"/api/contracts/{contract_id}/runner-permits",
        json={"allowed_path_prefixes": ["/api/", "/health"]},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["contract_id"] == contract_id
    assert payload["permit"]["allowed_hosts"] == [domain]
    assert payload["permit"]["allowed_methods"] == ["GET", "HEAD"]
    assert payload["permit"]["allowed_path_prefixes"] == ["/api/", "/health"]
    assert payload["permit"]["request_budget"] == 7
    assert payload["issuer_key_id"] == sha256(public_key.encode("ascii")).hexdigest()[:16]
    assert "runner_public_verification_key" not in payload
    assert "private" not in str(payload).lower()
    assert "test-contract-signing-key" not in str(payload)


def test_runner_permit_consumes_the_contract_run_budget(monkeypatch):
    client, _ = _client(monkeypatch)
    domain = "runner-budget.example"
    _register_and_verify(client, domain)
    contract_id = _create_contract(client, domain, max_scan_sessions=1)

    first = client.post(f"/api/contracts/{contract_id}/runner-permits", json={})
    second = client.post(f"/api/contracts/{contract_id}/runner-permits", json={})

    assert first.status_code == 201
    assert second.status_code == 409


def test_runner_permit_fails_closed_when_asymmetric_signing_is_not_configured(monkeypatch):
    client, _ = _client(monkeypatch)
    monkeypatch.setattr(settings, "runner_permit_private_key", None)
    domain = "runner-signing-missing.example"
    _register_and_verify(client, domain)
    contract_id = _create_contract(client, domain)

    response = client.post(f"/api/contracts/{contract_id}/runner-permits", json={})

    assert response.status_code == 503


def test_runner_permit_fails_closed_when_asymmetric_signing_key_is_malformed(monkeypatch):
    client, _ = _client(monkeypatch, raise_server_exceptions=False)
    monkeypatch.setattr(settings, "runner_permit_private_key", "not-a-valid-ed25519-private-key")
    domain = "runner-signing-malformed.example"
    _register_and_verify(client, domain)
    contract_id = _create_contract(client, domain)

    response = client.post(f"/api/contracts/{contract_id}/runner-permits", json={})

    assert response.status_code == 503
    assert "configured" in response.json()["detail"].lower()
    assert "ed25519" not in response.text.lower()


def test_runner_permit_requires_a_nonsecret_customer_authorization_reference(monkeypatch):
    client, _ = _client(monkeypatch)
    domain = "runner-reference.example"
    _register_and_verify(client, domain)
    contract_id = _create_contract(client, domain, customer_authorization_reference=None)

    response = client.post(f"/api/contracts/{contract_id}/runner-permits", json={})

    assert response.status_code == 422
    assert "reference" in response.json()["detail"].lower()


def test_runner_permit_issuance_is_disabled_unless_an_operator_explicitly_enables_the_development_gate(
    monkeypatch,
):
    client, _ = _client(monkeypatch)
    monkeypatch.setattr(settings, "enable_development_runner_permit_issuance", False)
    domain = "runner-permit-disabled.example"
    _register_and_verify(client, domain)
    contract_id = _create_contract(client, domain)

    response = client.post(f"/api/contracts/{contract_id}/runner-permits", json={})

    assert response.status_code == 503
    assert "disabled" in response.json()["detail"].lower()


def test_runner_permit_issuance_is_disabled_outside_an_explicit_development_deployment(monkeypatch):
    client, _ = _client(monkeypatch)
    monkeypatch.setattr(settings, "deployment_mode", "production")
    domain = "runner-permit-production.example"
    _register_and_verify(client, domain)
    contract_id = _create_contract(client, domain)

    response = client.post(f"/api/contracts/{contract_id}/runner-permits", json={})

    assert response.status_code == 503
    assert "disabled" in response.json()["detail"].lower()
