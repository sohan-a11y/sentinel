from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest
import respx

from sentinel.agents.dispatch import idor_agent
from sentinel.db.models import (
    ActionTier,
    EnvironmentTier,
    ScanSession,
    ScanStatus,
    TargetRegistration,
)
from sentinel.security import audit_log, guardrails
from sentinel.security.guardrails import DemonstrationBudgetExceededError

DOMAIN = "example-idor-test.com"


@pytest.fixture(autouse=True)
def _audit_log_file(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_log.settings, "audit_log_file", str(tmp_path / "audit.ndjson"))


class _FakeLlmClient:
    def __init__(self, result: dict):
        self._result = result
        self.calls: list[dict] = []

    def complete_json(self, *, system, user, json_schema, schema_name, max_tokens=4096):
        self.calls.append({"system": system, "user": user, "schema_name": schema_name})
        return self._result


def _make_registration(db_session, domain: str = DOMAIN) -> TargetRegistration:
    reg = TargetRegistration(
        domain=domain,
        account_owner="tester@example.com",
        verification_token="tok",
        canary_marker="marker",
        canary_check_url_template="https://x/{marker}",
        verification_passed_at=datetime.now(timezone.utc),
    )
    db_session.add(reg)
    db_session.flush()
    return reg


def _make_scan_session(
    db_session,
    registration: TargetRegistration,
    environment_tier: EnvironmentTier = EnvironmentTier.VERIFIED_SAFE,
    status: ScanStatus = ScanStatus.RUNNING,
) -> ScanSession:
    session_row = ScanSession(target_id=registration.id, status=status, environment_tier=environment_tier)
    db_session.add(session_row)
    db_session.flush()
    return session_row


def _cwe_items(applicable: bool = True) -> list[dict]:
    return [
        {
            "cwe_id": "CWE-639",
            "name": "Insecure Direct Object Reference",
            "category": "access-control",
            "applicable": applicable,
            "reason": "endpoints with id-like params requiring auth were found",
            "tested": False,
            "detection_method": None,
        }
    ]


def _base_site_map() -> dict:
    return {
        "domain": DOMAIN,
        "endpoints": [
            {
                "url": f"https://{DOMAIN}/api/orders/1001",
                "methods": ["GET"],
                "params": ["order_id"],
                "forms": [],
                "requires_auth": True,
                "source": "crawl",
            }
        ],
        "cookies": [{"name": "session", "value": "abc123"}],
        "response_headers": {},
        "tech_stack": [],
        "forms_count": 0,
        "crawled_at": "2026-07-15T00:00:00Z",
    }


def _single_candidate(**overrides) -> dict:
    candidate = {
        "endpoint": f"https://{DOMAIN}/api/orders/1001",
        "id_param": "order_id",
        "manipulated_endpoint": f"https://{DOMAIN}/api/orders/1002",
        "manipulation_strategy": "increment_numeric_id",
        "requires_account_creation": False,
        "reasoning": "order_id is a small sequential integer on an authenticated endpoint",
    }
    candidate.update(overrides)
    return {"candidates": [candidate]}


def test_returns_empty_when_site_map_is_none(db_session):
    reg = _make_registration(db_session)
    scan_session = _make_scan_session(db_session, reg)

    result = idor_agent.run(db_session, scan_session, reg, _cwe_items(), site_map=None)

    assert result == []


def test_skips_cleanly_when_cwe639_not_applicable(db_session, monkeypatch):
    reg = _make_registration(db_session)
    scan_session = _make_scan_session(db_session, reg)

    def _explode():
        raise AssertionError("get_llm_client should never be called when CWE-639 is not applicable")

    monkeypatch.setattr(idor_agent, "get_llm_client", _explode)

    result = idor_agent.run(db_session, scan_session, reg, _cwe_items(applicable=False), site_map=_base_site_map())

    assert result == []
    assert db_session.query(audit_log.AuditLogEntry).count() == 0


def test_confirmed_finding_when_manipulated_returns_full_data(db_session, monkeypatch):
    reg = _make_registration(db_session)
    scan_session = _make_scan_session(db_session, reg, environment_tier=EnvironmentTier.VERIFIED_SAFE)
    cwe_items = _cwe_items()

    fake_client = _FakeLlmClient(_single_candidate())
    monkeypatch.setattr(idor_agent, "get_llm_client", lambda: fake_client)

    with respx.mock:
        respx.get(f"https://{DOMAIN}/api/orders/1001").mock(
            return_value=httpx.Response(200, json={"order_id": 1001, "total": 42.0, "owner": "me"})
        )
        respx.get(f"https://{DOMAIN}/api/orders/1002").mock(
            return_value=httpx.Response(200, json={"order_id": 1002, "total": 99.0, "owner": "someone-else"})
        )

        findings = idor_agent.run(db_session, scan_session, reg, cwe_items, site_map=_base_site_map())

    assert len(findings) == 1
    finding = findings[0]
    assert finding["cwe_id"] == "CWE-639"
    assert finding["tier"] == "tier_b"
    assert finding["detection_method"] == "custom"
    assert finding["confidence"] == 0.9
    assert "1002" in finding["endpoint"]

    assert cwe_items[0]["tested"] is True
    assert cwe_items[0]["detection_method"] == "custom"

    actions = [row.action for row in db_session.query(audit_log.AuditLogEntry).all()]
    assert "idor_probe_attempted" in actions


def test_no_finding_when_manipulated_returns_403(db_session, monkeypatch):
    reg = _make_registration(db_session)
    scan_session = _make_scan_session(db_session, reg, environment_tier=EnvironmentTier.VERIFIED_SAFE)
    cwe_items = _cwe_items()

    fake_client = _FakeLlmClient(_single_candidate())
    monkeypatch.setattr(idor_agent, "get_llm_client", lambda: fake_client)

    with respx.mock:
        respx.get(f"https://{DOMAIN}/api/orders/1001").mock(
            return_value=httpx.Response(200, json={"order_id": 1001, "total": 42.0})
        )
        respx.get(f"https://{DOMAIN}/api/orders/1002").mock(
            return_value=httpx.Response(403, json={"error": "forbidden"})
        )

        findings = idor_agent.run(db_session, scan_session, reg, cwe_items, site_map=_base_site_map())

    assert findings == []
    assert cwe_items[0]["tested"] is True
    assert cwe_items[0]["detection_method"] == "custom"


def test_no_finding_when_manipulated_returns_404(db_session, monkeypatch):
    reg = _make_registration(db_session)
    scan_session = _make_scan_session(db_session, reg, environment_tier=EnvironmentTier.VERIFIED_SAFE)
    cwe_items = _cwe_items()

    fake_client = _FakeLlmClient(_single_candidate())
    monkeypatch.setattr(idor_agent, "get_llm_client", lambda: fake_client)

    with respx.mock:
        respx.get(f"https://{DOMAIN}/api/orders/1001").mock(
            return_value=httpx.Response(200, json={"order_id": 1001, "total": 42.0})
        )
        respx.get(f"https://{DOMAIN}/api/orders/1002").mock(
            return_value=httpx.Response(404, text="not found")
        )

        findings = idor_agent.run(db_session, scan_session, reg, cwe_items, site_map=_base_site_map())

    assert findings == []


def test_tier_b_blocked_makes_zero_http_calls_to_target(db_session, monkeypatch):
    reg = _make_registration(db_session)
    scan_session = _make_scan_session(db_session, reg, environment_tier=EnvironmentTier.UNVERIFIED)
    cwe_items = _cwe_items()

    fake_client = _FakeLlmClient(_single_candidate())
    monkeypatch.setattr(idor_agent, "get_llm_client", lambda: fake_client)

    with respx.mock:
        baseline_route = respx.get(f"https://{DOMAIN}/api/orders/1001").mock(
            return_value=httpx.Response(200, json={"order_id": 1001})
        )
        manipulated_route = respx.get(f"https://{DOMAIN}/api/orders/1002").mock(
            return_value=httpx.Response(200, json={"order_id": 1002})
        )

        findings = idor_agent.run(db_session, scan_session, reg, cwe_items, site_map=_base_site_map())

        assert baseline_route.call_count == 0
        assert manipulated_route.call_count == 0

    assert findings == []
    assert cwe_items[0]["tested"] is True

    actions = [row.action for row in db_session.query(audit_log.AuditLogEntry).all()]
    assert "idor_tier_b_skipped" in actions


def test_demonstration_budget_actually_invoked_for_account_creation_path(db_session, monkeypatch):
    reg = _make_registration(db_session)
    scan_session = _make_scan_session(db_session, reg, environment_tier=EnvironmentTier.VERIFIED_SAFE)
    cwe_items = _cwe_items()

    site_map = _base_site_map()
    site_map["endpoints"].append(
        {
            "url": f"https://{DOMAIN}/signup",
            "methods": ["POST"],
            "params": [],
            "forms": [],
            "requires_auth": False,
            "source": "crawl",
        }
    )

    candidate_payload = _single_candidate(
        requires_account_creation=True,
        manipulated_endpoint=f"https://{DOMAIN}/api/orders/{{demo_account_id}}",
    )
    fake_client = _FakeLlmClient(candidate_payload)
    monkeypatch.setattr(idor_agent, "get_llm_client", lambda: fake_client)

    budget_calls: list[tuple[str, int]] = []

    def _raise_over_budget(db, registration, action_type: str, requested_count: int) -> None:
        budget_calls.append((action_type, requested_count))
        raise DemonstrationBudgetExceededError("refusing to create more than the demonstration cap")

    monkeypatch.setattr(guardrails, "enforce_demonstration_budget", _raise_over_budget)

    with respx.mock:
        signup_route = respx.post(f"https://{DOMAIN}/signup").mock(
            return_value=httpx.Response(201, json={"id": "should-never-be-created"})
        )
        manipulated_route = respx.get(f"https://{DOMAIN}/api/orders/should-never-be-created").mock(
            return_value=httpx.Response(200, json={"order_id": "should-never-be-created"})
        )

        findings = idor_agent.run(db_session, scan_session, reg, cwe_items, site_map=site_map)

        assert signup_route.call_count == 0
        assert manipulated_route.call_count == 0

    assert budget_calls == [("account_creation", 1)]
    assert findings == []

    actions = [row.action for row in db_session.query(audit_log.AuditLogEntry).all()]
    assert "idor_demo_account_blocked" in actions


def test_demo_account_budget_is_actually_persistent_across_two_real_calls(db_session):
    """Regression for the HIGH-severity finding: enforce_demonstration_budget
    used to compare the literal "1" passed in against the cap, so it never
    actually observed prior creations. This exercises the real (unmocked)
    guardrails functions directly against _create_demo_account twice."""
    reg = _make_registration(db_session)
    site_map = _base_site_map()
    site_map["endpoints"].append(
        {
            "url": f"https://{DOMAIN}/signup",
            "methods": ["POST"],
            "params": [],
            "forms": [],
            "requires_auth": False,
            "source": "crawl",
        }
    )

    with respx.mock:
        respx.post(f"https://{DOMAIN}/signup").mock(
            side_effect=[
                httpx.Response(201, json={"id": "account-1"}),
                httpx.Response(201, json={"id": "account-2"}),
            ]
        )

        first_account_id = idor_agent._create_demo_account(db_session, reg, site_map)
        assert first_account_id == "account-1"

        with pytest.raises(DemonstrationBudgetExceededError):
            idor_agent._create_demo_account(db_session, reg, site_map)


def test_filters_out_endpoints_without_id_like_params_or_auth(db_session, monkeypatch):
    reg = _make_registration(db_session)
    scan_session = _make_scan_session(db_session, reg)
    cwe_items = _cwe_items()

    def _explode():
        raise AssertionError("get_llm_client should never be called when no candidate endpoints exist")

    monkeypatch.setattr(idor_agent, "get_llm_client", _explode)

    site_map = {
        "domain": DOMAIN,
        "endpoints": [
            {
                "url": f"https://{DOMAIN}/public/about",
                "methods": ["GET"],
                "params": ["lang"],
                "forms": [],
                "requires_auth": False,
                "source": "crawl",
            },
            {
                "url": f"https://{DOMAIN}/dashboard",
                "methods": ["GET"],
                "params": ["theme"],
                "forms": [],
                "requires_auth": True,
                "source": "crawl",
            },
        ],
        "cookies": [],
        "response_headers": {},
        "tech_stack": [],
        "forms_count": 0,
        "crawled_at": "2026-07-15T00:00:00Z",
    }

    findings = idor_agent.run(db_session, scan_session, reg, cwe_items, site_map=site_map)

    assert findings == []
    assert cwe_items[0]["tested"] is True
    actions = [row.action for row in db_session.query(audit_log.AuditLogEntry).all()]
    assert "idor_no_candidate_endpoints" in actions
