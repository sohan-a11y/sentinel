from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from sentinel.agents import dispatcher_agent, kill_switch
from sentinel.config import settings
from sentinel.control_plane import service
from sentinel.db.models import ActionTier, EnvironmentTier, ScanSession, ScanStatus, TargetRegistration
from sentinel.security.guardrails import ScanHaltedError


@pytest.fixture(autouse=True)
def _fresh_kill_switch_singletons():
    """dispatcher_agent feeds the process-wide AnomalyMonitor/HaltRegistry
    singletons. Every test here builds a ScanSession with id=1 in its own
    fresh in-memory DB, so without resetting these singletons between tests,
    samples recorded in one test would leak into the next test's threshold
    checks (same scan_session_id key, same process-wide singleton)."""
    kill_switch._monitor_singleton = None
    kill_switch._registry_singleton = None
    yield
    kill_switch._monitor_singleton = None
    kill_switch._registry_singleton = None


def _registration(db_session, domain="example-test.com") -> TargetRegistration:
    reg = TargetRegistration(
        domain=domain,
        account_owner="alice@corp.com",
        verification_token="tok",
        canary_marker="marker",
        canary_check_url_template="https://x/{marker}",
        verification_passed_at=datetime.now(timezone.utc),
    )
    db_session.add(reg)
    db_session.flush()
    return reg


def _scan_session(db_session, reg, tier=EnvironmentTier.VERIFIED_SAFE) -> ScanSession:
    session_row = ScanSession(target_id=reg.id, status=ScanStatus.RUNNING, environment_tier=tier)
    db_session.add(session_row)
    db_session.flush()
    return session_row


def test_runs_all_three_engines_and_collects_findings(db_session):
    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)

    nuclei_finding = {"cwe_id": "CWE-79", "endpoint": "e1", "tier": "tier_a", "detection_method": "nuclei", "poc_evidence": "x", "confidence": 0.7}
    zap_finding = {"cwe_id": "CWE-89", "endpoint": "e2", "tier": "tier_a", "detection_method": "zap", "poc_evidence": "y", "confidence": 0.8}
    idor_finding = {"cwe_id": "CWE-639", "endpoint": "e3", "tier": "tier_b", "detection_method": "custom", "poc_evidence": "z", "confidence": 0.9}

    with patch("sentinel.agents.dispatcher_agent.nuclei_wrapper.run", return_value=[nuclei_finding]) as m_nuclei, \
         patch("sentinel.agents.dispatcher_agent.zap_wrapper.run", return_value=[zap_finding]) as m_zap, \
         patch("sentinel.agents.dispatcher_agent.idor_agent.run", return_value=[idor_finding]) as m_idor:
        findings = dispatcher_agent.run_all_engines(db_session, scan_session, reg, [], {"domain": reg.domain})

    assert len(findings) == 3
    assert nuclei_finding in findings
    assert zap_finding in findings
    assert idor_finding in findings
    m_nuclei.assert_called_once()
    m_zap.assert_called_once()
    m_idor.assert_called_once()


def test_contract_run_blocks_all_scanner_engines(monkeypatch, db_session):
    """recon.v1 is deliberately the only executable contract recipe."""
    monkeypatch.setattr(settings, "control_plane_signing_key", "test-signing-key")
    reg = _registration(db_session)
    contract = service.create_scan_contract(
        db_session,
        registration=reg,
        approved_by="approver@example.com",
        allowed_tier=ActionTier.TIER_A,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    _, lease_token = service.issue_action_lease(
        db_session, contract=contract, requested_tier=ActionTier.TIER_A
    )
    scan_session = _scan_session(db_session, reg)
    service.activate_lease_for_scan(db_session, lease_token=lease_token, scan_session=scan_session)

    with patch("sentinel.agents.dispatcher_agent.nuclei_wrapper.run") as m_nuclei, \
         patch("sentinel.agents.dispatcher_agent.zap_wrapper.run") as m_zap, \
         patch("sentinel.agents.dispatcher_agent.idor_agent.run") as m_idor:
        findings = dispatcher_agent.run_all_engines(db_session, scan_session, reg, [], {})

    assert findings == []
    m_nuclei.assert_not_called()
    m_zap.assert_not_called()
    m_idor.assert_not_called()


def test_stops_remaining_engines_when_scan_already_halted(db_session):
    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)
    scan_session.status = ScanStatus.HALTED
    scan_session.halted_reason = "anomaly"
    db_session.flush()

    with patch("sentinel.agents.dispatcher_agent.nuclei_wrapper.run") as m_nuclei, \
         patch("sentinel.agents.dispatcher_agent.zap_wrapper.run") as m_zap, \
         patch("sentinel.agents.dispatcher_agent.idor_agent.run") as m_idor:
        findings = dispatcher_agent.run_all_engines(db_session, scan_session, reg, [], {})

    assert findings == []
    m_nuclei.assert_not_called()
    m_zap.assert_not_called()
    m_idor.assert_not_called()


def test_halt_mid_run_stops_subsequent_engines(db_session):
    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)

    with patch("sentinel.agents.dispatcher_agent.nuclei_wrapper.run", side_effect=ScanHaltedError("halted")) as m_nuclei, \
         patch("sentinel.agents.dispatcher_agent.zap_wrapper.run") as m_zap, \
         patch("sentinel.agents.dispatcher_agent.idor_agent.run") as m_idor:
        findings = dispatcher_agent.run_all_engines(db_session, scan_session, reg, [], {})

    assert findings == []
    m_nuclei.assert_called_once()
    m_zap.assert_not_called()
    m_idor.assert_not_called()


def test_one_engine_error_does_not_sink_the_others(db_session):
    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)
    zap_finding = {"cwe_id": "CWE-89", "endpoint": "e2", "tier": "tier_a", "detection_method": "zap", "poc_evidence": "y", "confidence": 0.8}

    with patch("sentinel.agents.dispatcher_agent.nuclei_wrapper.run", side_effect=RuntimeError("boom")), \
         patch("sentinel.agents.dispatcher_agent.zap_wrapper.run", return_value=[zap_finding]), \
         patch("sentinel.agents.dispatcher_agent.idor_agent.run", return_value=[]):
        findings = dispatcher_agent.run_all_engines(db_session, scan_session, reg, [], {})

    assert findings == [zap_finding]


def test_dispatcher_node_loads_session_and_registration_from_db(db_session, monkeypatch):
    import sentinel.db.session as db_session_module

    monkeypatch.setattr(dispatcher_agent, "get_session", lambda: _FakeSessionCtx(db_session))

    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)

    nuclei_finding = {"cwe_id": "CWE-79", "endpoint": "e1", "tier": "tier_a", "detection_method": "nuclei", "poc_evidence": "x", "confidence": 0.7}
    with patch("sentinel.agents.dispatcher_agent.nuclei_wrapper.run", return_value=[nuclei_finding]), \
         patch("sentinel.agents.dispatcher_agent.zap_wrapper.run", return_value=[]), \
         patch("sentinel.agents.dispatcher_agent.idor_agent.run", return_value=[]):
        result = dispatcher_agent.dispatcher_node(
            {"scan_session_id": scan_session.id, "cwe_checklist": [], "site_map": {}}
        )

    assert result["raw_findings"] == [nuclei_finding]
    assert result["current_phase"] == "dispatch_complete"
    assert result["halted"] is False
    assert result["halt_reason"] is None


def test_dispatcher_node_reports_halted_state_when_engine_gets_halted_mid_run(db_session, monkeypatch):
    monkeypatch.setattr(dispatcher_agent, "get_session", lambda: _FakeSessionCtx(db_session))

    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)

    def _halt_and_raise(*args, **kwargs):
        kill_switch.get_halt_registry().trigger_halt(db_session, scan_session.id, "anomaly detected mid-scan")
        raise ScanHaltedError("halted")

    with patch("sentinel.agents.dispatcher_agent.nuclei_wrapper.run", side_effect=_halt_and_raise), \
         patch("sentinel.agents.dispatcher_agent.zap_wrapper.run") as m_zap, \
         patch("sentinel.agents.dispatcher_agent.idor_agent.run") as m_idor:
        result = dispatcher_agent.dispatcher_node(
            {"scan_session_id": scan_session.id, "cwe_checklist": [], "site_map": {}}
        )

    assert result["halted"] is True
    assert result["halt_reason"] == "anomaly detected mid-scan"
    m_zap.assert_not_called()
    m_idor.assert_not_called()


class _FakeSessionCtx:
    def __init__(self, session):
        self._session = session

    def __enter__(self):
        return self._session

    def __exit__(self, exc_type, exc, tb):
        return False
