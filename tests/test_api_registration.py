from __future__ import annotations

import httpx
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from sentinel.api import deps
from sentinel.api.routes import registration
from sentinel.config import settings
from sentinel.db.models import Base

app = FastAPI()
app.include_router(registration.router)


def _client(monkeypatch):
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


def test_register_returns_token_and_marker(monkeypatch):
    client = _client(monkeypatch)
    response = client.post(
        "/api/targets/register",
        json={
            "domain": "example-test.com",
            "account_owner": "alice@corp.com",
            "canary_check_url_template": "https://example-test.com/api/users/{marker}",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["domain"] == "example-test.com"
    assert body["verification_token"]
    assert body["canary_marker"]


def test_register_duplicate_returns_409(monkeypatch):
    client = _client(monkeypatch)
    payload = {
        "domain": "dup-test.com",
        "account_owner": "alice@corp.com",
        "canary_check_url_template": "https://dup-test.com/api/users/{marker}",
    }
    client.post("/api/targets/register", json=payload)
    response = client.post("/api/targets/register", json=payload)
    assert response.status_code == 409


def test_register_rejects_missing_marker_placeholder(monkeypatch):
    client = _client(monkeypatch)
    response = client.post(
        "/api/targets/register",
        json={
            "domain": "no-marker-test.com",
            "account_owner": "alice@corp.com",
            "canary_check_url_template": "https://no-marker-test.com/api/users/42",
        },
    )
    assert response.status_code == 422


def test_get_unregistered_target_returns_404(monkeypatch):
    client = _client(monkeypatch)
    response = client.get("/api/targets/never-registered.com")
    assert response.status_code == 404


@respx.mock
def test_verify_endpoint_reflects_well_known_result(monkeypatch):
    client = _client(monkeypatch)
    domain = "verify-test.com"
    reg_response = client.post(
        "/api/targets/register",
        json={
            "domain": domain,
            "account_owner": "alice@corp.com",
            "canary_check_url_template": f"https://{domain}/api/users/{{marker}}",
        },
    )
    token = reg_response.json()["verification_token"]
    respx.get(f"https://{domain}{settings.well_known_path}").mock(return_value=httpx.Response(200, text=token))

    verify_response = client.post(f"/api/targets/{domain}/verify")
    assert verify_response.status_code == 200
    assert verify_response.json()["verified"] is True

    get_response = client.get(f"/api/targets/{domain}")
    assert get_response.json()["verification_method"] == "well_known_http"


def test_deactivate_target(monkeypatch):
    client = _client(monkeypatch)
    domain = "deactivate-test.com"
    client.post(
        "/api/targets/register",
        json={
            "domain": domain,
            "account_owner": "alice@corp.com",
            "canary_check_url_template": f"https://{domain}/api/users/{{marker}}",
        },
    )
    delete_response = client.delete(f"/api/targets/{domain}")
    assert delete_response.status_code == 204
    get_response = client.get(f"/api/targets/{domain}")
    assert get_response.status_code == 404
