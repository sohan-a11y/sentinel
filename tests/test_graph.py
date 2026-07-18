"""Contract-run integration tests for the compiled LangGraph pipeline.

The production graph only accepts a contract-bound ``recon.v1`` session.
These tests exercise the real node wiring while mocking external boundaries,
and make the policy boundary observable: recon proceeds, but active scanner
engines and live verification do not.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from sentinel.agents import (
    cwe_mapping_agent,
    dispatcher_agent,
    graph,
    kill_switch,
    persistence,
    recon_agent,
    report_agent,
    verification_agent,
)
from sentinel.config import settings
from sentinel.control_plane import service
from sentinel.db.models import (
    ActionLease,
    ActionLeaseStatus,
    ActionTier,
    CweApplicability,
    EnvironmentTier,
    Finding,
    ScanSession,
    ScanStatus,
    ScanContract,
    TargetRegistration,
)
from sentinel.security import audit_log
from sentinel.security.guardrails import ScanHaltedError

DOMAIN = "graph-e2e-test.com"


@pytest.fixture(autouse=True)
def _fresh_kill_switch_singletons():
    kill_switch._monitor_singleton = None
    kill_switch._registry_singleton = None
    yield
    kill_switch._monitor_singleton = None
    kill_switch._registry_singleton = None


@pytest.fixture(autouse=True)
def _control_plane_settings(monkeypatch):
    monkeypatch.setattr(settings, "control_plane_signing_key", "graph-test-signing-key")
    monkeypatch.setattr(settings, "control_plane_max_lease_seconds", 900)


@contextmanager
def _wrap(session):
    yield session


def _patch_get_session(monkeypatch, db_session):
    ctx = lambda: _wrap(db_session)  # noqa: E731
    for module in (
        graph,
        recon_agent,
        cwe_mapping_agent,
        dispatcher_agent,
        persistence,
        verification_agent,
        report_agent,
    ):
        monkeypatch.setattr(module, "get_session", ctx)


def _registration(db_session) -> TargetRegistration:
    registration = TargetRegistration(
        domain=DOMAIN,
        account_owner="alice@corp.com",
        verification_token="tok",
        canary_marker="marker",
        canary_check_url_template=f"https://{DOMAIN}/api/{{marker}}",
        verification_passed_at=datetime.now(timezone.utc),
    )
    db_session.add(registration)
    db_session.flush()
    return registration


def _contract_scan(
    db_session, registration: TargetRegistration
) -> tuple[ScanSession, ScanContract, ActionLease]:
    contract = service.create_scan_contract(
        db_session,
        registration=registration,
        approved_by="security.approver@example.com",
        allowed_tier=ActionTier.TIER_A,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        max_scan_sessions=1,
        max_requests=20,
    )
    lease, lease_token = service.issue_action_lease(
        db_session,
        contract=contract,
        requested_tier=ActionTier.TIER_A,
    )
    scan_session = ScanSession(
        target_id=registration.id,
        status=ScanStatus.RUNNING,
        environment_tier=EnvironmentTier.VERIFIED_SAFE,
    )
    db_session.add(scan_session)
    db_session.flush()
    service.activate_lease_for_scan(db_session, lease_token=lease_token, scan_session=scan_session)
    return scan_session, contract, lease


_FAKE_SITE_MAP = {
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
    "cookies": [{"name": "session", "secure": True, "httponly": True}],
    "response_headers": {"server": "nginx"},
    "tech_stack": ["nginx"],
    "forms_count": 0,
    "crawled_at": datetime.now(timezone.utc).isoformat(),
}


def _run_contract_pipeline_with_mocks(db_session, monkeypatch, scan_session):
    _patch_get_session(monkeypatch, db_session)

    with patch("sentinel.agents.recon_agent.Crawler") as mock_crawler, \
         patch(
             "sentinel.agents.cwe_mapping_agent.get_llm_client",
             side_effect=cwe_mapping_agent.LlmConfigurationError("no key"),
         ), \
         patch("sentinel.agents.dispatcher_agent.nuclei_wrapper.run") as mock_nuclei, \
         patch("sentinel.agents.dispatcher_agent.zap_wrapper.run") as mock_zap, \
         patch("sentinel.agents.dispatcher_agent.idor_agent.run") as mock_idor:
        mock_crawler.return_value.crawl.return_value = _FAKE_SITE_MAP
        mock_crawler.return_value.close.return_value = None
        mock_crawler.return_value.visited = {f"https://{DOMAIN}/"}
        mock_crawler.return_value.external_links_seen = []

        # The retained arguments intentionally disagree with the DB record;
        # graph entry must reload authoritative scope rather than trust them.
        result = graph.run_scan_pipeline(
            scan_session.id,
            "attacker-controlled.invalid",
            EnvironmentTier.UNVERIFIED.value,
        )

    return result, mock_crawler, mock_nuclei, mock_zap, mock_idor


def test_contract_recon_pipeline_completes_without_active_engines(db_session, monkeypatch):
    registration = _registration(db_session)
    scan_session, contract, lease = _contract_scan(db_session, registration)

    result, mock_crawler, mock_nuclei, mock_zap, mock_idor = _run_contract_pipeline_with_mocks(
        db_session,
        monkeypatch,
        scan_session,
    )

    assert result["current_phase"] == "report_complete"
    assert result["halted"] is False
    assert mock_crawler.call_args.args[0].domain == DOMAIN
    assert callable(mock_crawler.call_args.kwargs["before_request"])
    mock_nuclei.assert_not_called()
    mock_zap.assert_not_called()
    mock_idor.assert_not_called()

    db_session.refresh(scan_session)
    db_session.refresh(lease)
    assert scan_session.contract_id == contract.id
    assert scan_session.status == ScanStatus.COMPLETED
    assert lease.status == ActionLeaseStatus.COMPLETED
    assert db_session.query(Finding).filter(Finding.scan_session_id == scan_session.id).count() == 0
    assert db_session.query(CweApplicability).filter(CweApplicability.scan_session_id == scan_session.id).count() > 0

    actions = [entry.action for entry in db_session.query(audit_log.AuditLogEntry).all()]
    assert "contract_recipe_engines_blocked" in actions


def test_graph_rejects_unbound_legacy_session_before_crawl(db_session, monkeypatch):
    registration = _registration(db_session)
    legacy_session = ScanSession(
        target_id=registration.id,
        status=ScanStatus.RUNNING,
        environment_tier=EnvironmentTier.VERIFIED_SAFE,
    )
    db_session.add(legacy_session)
    db_session.flush()
    _patch_get_session(monkeypatch, db_session)

    with patch("sentinel.agents.recon_agent.Crawler") as mock_crawler:
        with pytest.raises(service.ContractStateError, match="contract-backed recon.v1"):
            graph.run_scan_pipeline(legacy_session.id)

    mock_crawler.assert_not_called()
    db_session.refresh(legacy_session)
    assert legacy_session.status == ScanStatus.FAILED


def test_graph_refuses_pre_halted_contract_without_starting_nodes(db_session, monkeypatch):
    registration = _registration(db_session)
    scan_session, _, lease = _contract_scan(db_session, registration)
    kill_switch.get_halt_registry().trigger_halt(
        db_session,
        scan_session.id,
        "operator stopped this contract run",
    )
    _patch_get_session(monkeypatch, db_session)

    with patch("sentinel.agents.recon_agent.Crawler") as mock_crawler, \
         patch("sentinel.agents.dispatcher_agent.nuclei_wrapper.run") as mock_nuclei, \
         patch("sentinel.agents.dispatcher_agent.zap_wrapper.run") as mock_zap, \
         patch("sentinel.agents.dispatcher_agent.idor_agent.run") as mock_idor:
        with pytest.raises(ScanHaltedError, match="operator stopped this contract run"):
            graph.run_scan_pipeline(scan_session.id)

    mock_crawler.assert_not_called()
    mock_nuclei.assert_not_called()
    mock_zap.assert_not_called()
    mock_idor.assert_not_called()
    db_session.refresh(scan_session)
    db_session.refresh(lease)
    assert scan_session.status == ScanStatus.HALTED
    assert lease.status == ActionLeaseStatus.REVOKED
