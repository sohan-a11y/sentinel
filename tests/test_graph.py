"""End-to-end test of the compiled LangGraph pipeline.

Every external boundary (recon's HTTP crawl, the LLM client, the three scan
engines) is mocked, but the wiring between nodes — the real SentinelState
handoffs, the real DB persistence, the real conditional routing on a halt —
is exercised for real. This is what catches integration gaps that each
module's own isolated unit tests can't see (like the poc_evidence format
mismatch fixed alongside this test).
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
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
from sentinel.db.models import (
    CweApplicability,
    EnvironmentTier,
    Finding,
    FindingStatus,
    ScanSession,
    ScanStatus,
    TargetRegistration,
)

DOMAIN = "graph-e2e-test.com"


@pytest.fixture(autouse=True)
def _fresh_kill_switch_singletons():
    kill_switch._monitor_singleton = None
    kill_switch._registry_singleton = None
    yield
    kill_switch._monitor_singleton = None
    kill_switch._registry_singleton = None


@contextmanager
def _wrap(session):
    yield session


def _patch_get_session(monkeypatch, db_session):
    ctx = lambda: _wrap(db_session)  # noqa: E731
    for module in (recon_agent, cwe_mapping_agent, dispatcher_agent, persistence, verification_agent, report_agent):
        monkeypatch.setattr(module, "get_session", ctx)


def _registration(db_session) -> TargetRegistration:
    reg = TargetRegistration(
        domain=DOMAIN,
        account_owner="alice@corp.com",
        verification_token="tok",
        canary_marker="marker",
        canary_check_url_template=f"https://{DOMAIN}/api/{{marker}}",
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


def _run_pipeline_with_mocks(db_session, monkeypatch, scan_session, *, nuclei_findings, zap_findings, idor_findings):
    _patch_get_session(monkeypatch, db_session)

    with patch("sentinel.agents.recon_agent.Crawler") as MockCrawler, \
         patch("sentinel.agents.cwe_mapping_agent.get_llm_client", side_effect=cwe_mapping_agent.LlmConfigurationError("no key")), \
         patch("sentinel.agents.dispatcher_agent.nuclei_wrapper.run", return_value=nuclei_findings), \
         patch("sentinel.agents.dispatcher_agent.zap_wrapper.run", return_value=zap_findings), \
         patch("sentinel.agents.dispatcher_agent.idor_agent.run", return_value=idor_findings):
        MockCrawler.return_value.crawl.return_value = _FAKE_SITE_MAP
        MockCrawler.return_value.close.return_value = None
        MockCrawler.return_value.visited = {f"https://{DOMAIN}/"}
        MockCrawler.return_value.external_links_seen = []

        result = graph.run_scan_pipeline(scan_session.id, DOMAIN, scan_session.environment_tier.value)
    return result


def test_full_pipeline_happy_path_persists_everything(db_session, monkeypatch):
    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)

    nuclei_finding = {
        "cwe_id": "CWE-79",
        "endpoint": f"https://{DOMAIN}/search",
        "tier": "tier_a",
        "detection_method": "nuclei",
        "poc_evidence": f"xss-reflected | https://{DOMAIN}/search?q=marker\nmatched-at: https://{DOMAIN}/search?q=marker\npattern: marker",
        "confidence": 0.7,
    }

    with patch("httpx.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "marker"

        result = _run_pipeline_with_mocks(
            db_session,
            monkeypatch,
            scan_session,
            nuclei_findings=[nuclei_finding],
            zap_findings=[],
            idor_findings=[],
        )

    assert result["current_phase"] == "report_complete"
    assert result["halted"] is False

    persisted = db_session.query(Finding).filter(Finding.scan_session_id == scan_session.id).all()
    assert len(persisted) == 1
    assert persisted[0].cwe_id == "CWE-79"

    applicability_rows = (
        db_session.query(CweApplicability).filter(CweApplicability.scan_session_id == scan_session.id).all()
    )
    assert len(applicability_rows) > 0

    refreshed_session = db_session.get(ScanSession, scan_session.id)
    assert refreshed_session.applicable_cwe_count > 0


def test_full_pipeline_halted_mid_dispatch_skips_verification_but_still_reports(db_session, monkeypatch):
    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)

    idor_finding = {
        "cwe_id": "CWE-639",
        "endpoint": f"https://{DOMAIN}/api/orders/1002",
        "tier": "tier_b",
        "detection_method": "custom",
        "poc_evidence": f"baseline-url: https://{DOMAIN}/api/orders/1001\nmanipulated-url: https://{DOMAIN}/api/orders/1002",
        "confidence": 0.9,
    }

    def _nuclei_halts(*args, **kwargs):
        kill_switch.get_halt_registry().trigger_halt(db_session, scan_session.id, "anomaly during nuclei phase")
        return []

    _patch_get_session(monkeypatch, db_session)
    with patch("sentinel.agents.recon_agent.Crawler") as MockCrawler, \
         patch(
             "sentinel.agents.cwe_mapping_agent.get_llm_client",
             side_effect=cwe_mapping_agent.LlmConfigurationError("no key"),
         ), \
         patch("sentinel.agents.dispatcher_agent.nuclei_wrapper.run", side_effect=_nuclei_halts), \
         patch("sentinel.agents.dispatcher_agent.zap_wrapper.run") as m_zap, \
         patch("sentinel.agents.dispatcher_agent.idor_agent.run") as m_idor:
        MockCrawler.return_value.crawl.return_value = _FAKE_SITE_MAP
        MockCrawler.return_value.close.return_value = None
        MockCrawler.return_value.visited = {f"https://{DOMAIN}/"}
        MockCrawler.return_value.external_links_seen = []

        result = graph.run_scan_pipeline(scan_session.id, DOMAIN, scan_session.environment_tier.value)

    assert result["halted"] is True
    assert result["current_phase"] == "report_complete"
    m_zap.assert_not_called()
    m_idor.assert_not_called()

    refreshed_session = db_session.get(ScanSession, scan_session.id)
    assert refreshed_session.status == ScanStatus.HALTED

    summary = report_agent.build_summary(db_session, scan_session.id)
    assert summary is not None
