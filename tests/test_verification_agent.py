from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone

import httpx
import pytest
import respx

from sentinel.agents import verification_agent
from sentinel.db.models import EnvironmentTier, ScanSession, ScanStatus, TargetRegistration


def _registration(db_session, domain: str = "verify-target.com") -> TargetRegistration:
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


def _scan_session(
    db_session,
    registration: TargetRegistration,
    environment_tier: EnvironmentTier = EnvironmentTier.VERIFIED_SAFE,
    status: ScanStatus = ScanStatus.RUNNING,
) -> ScanSession:
    session_row = ScanSession(target_id=registration.id, status=status, environment_tier=environment_tier)
    db_session.add(session_row)
    db_session.flush()
    return session_row


class TestNucleiVerification:
    @respx.mock
    def test_reverifies_true_confirms(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        url = "https://verify-target.com/search?q=sentinel-xss-marker"
        respx.get(url).mock(
            return_value=httpx.Response(200, text="<html>reflected: sentinel-xss-marker</html>")
        )
        raw_findings = [
            {
                "cwe_id": "CWE-79",
                "endpoint": "https://verify-target.com/search",
                "tier": "tier_a",
                "detection_method": "nuclei",
                "poc_evidence": f"matched-at: {url}\npattern: sentinel-xss-marker",
                "confidence": 0.8,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert len(result) == 1
        assert result[0]["status"] == "confirmed"
        assert result[0]["verification_method"] == "nuclei_xss_pattern_replay"
        assert "sentinel-xss-marker" in result[0]["verification_note"]

    @respx.mock
    def test_reverifies_false_unconfirms(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        url = "https://verify-target.com/search?q=sentinel-xss-marker"
        respx.get(url).mock(return_value=httpx.Response(200, text="<html>no marker here, escaped &lt;script&gt;</html>"))
        raw_findings = [
            {
                "cwe_id": "CWE-79",
                "endpoint": "https://verify-target.com/search",
                "tier": "tier_a",
                "detection_method": "nuclei",
                "poc_evidence": f"matched-at: {url}\npattern: sentinel-xss-marker",
                "confidence": 0.8,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert result[0]["status"] == "unconfirmed"
        assert result[0]["verification_method"] == "nuclei_xss_pattern_replay"

    @respx.mock
    def test_reachability_fallback_never_auto_confirms(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        url = "https://verify-target.com/some/generic/endpoint"
        respx.get(url).mock(return_value=httpx.Response(200, text="ok"))
        raw_findings = [
            {
                "cwe_id": "CWE-9999",
                "endpoint": "https://verify-target.com/some/generic/endpoint",
                "tier": "tier_a",
                "detection_method": "nuclei",
                "poc_evidence": f"matched-at: {url}",
                "confidence": 0.9,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert result[0]["status"] == "unconfirmed"
        assert result[0]["verification_method"] == "nuclei_reachability_fallback"
        assert result[0]["confidence"] <= 0.3


class TestZapVerification:
    @respx.mock
    def test_reverifies_true_confirms(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        url = "https://verify-target.com/account/profile"
        respx.get(url).mock(
            return_value=httpx.Response(200, headers={"X-Powered-By": "PHP/5.3.1"}, text="profile page")
        )
        raw_findings = [
            {
                "cwe_id": "CWE-200",
                "endpoint": "https://verify-target.com/account/profile",
                "tier": "tier_a",
                "detection_method": "zap",
                "poc_evidence": f"matched-at: {url}\nevidence: PHP/5.3.1",
                "confidence": 0.7,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert result[0]["status"] == "confirmed"
        assert result[0]["verification_method"] == "zap_evidence_replay"

    @respx.mock
    def test_reverifies_false_unconfirms(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        url = "https://verify-target.com/account/profile"
        respx.get(url).mock(return_value=httpx.Response(200, headers={"X-Powered-By": "PHP/8.2.0"}, text="profile page"))
        raw_findings = [
            {
                "cwe_id": "CWE-200",
                "endpoint": "https://verify-target.com/account/profile",
                "tier": "tier_a",
                "detection_method": "zap",
                "poc_evidence": f"matched-at: {url}\nevidence: PHP/5.3.1",
                "confidence": 0.7,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert result[0]["status"] == "unconfirmed"
        assert result[0]["verification_method"] == "zap_evidence_replay"


class TestCustomIdorVerification:
    @respx.mock
    def test_agreeing_reprobe_confirms(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        baseline_url = "https://verify-target.com/api/orders/1001"
        manipulated_url = "https://verify-target.com/api/orders/1002"
        respx.get(baseline_url).mock(return_value=httpx.Response(200, text='{"order_id": 1001}'))
        respx.get(manipulated_url).mock(
            return_value=httpx.Response(200, text='{"order_id": 1002, "customer_email": "victim@example.com"}')
        )
        raw_findings = [
            {
                "cwe_id": "CWE-639",
                "endpoint": manipulated_url,
                "tier": "tier_b",
                "detection_method": "custom",
                "poc_evidence": (
                    f"baseline-url: {baseline_url}\nmanipulated-url: {manipulated_url}\n"
                    "unauthorized-marker: customer_email"
                ),
                "confidence": 0.85,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert result[0]["status"] == "confirmed"
        assert result[0]["verification_method"] == "idor_reprobe"

    @respx.mock
    def test_disagreeing_reprobe_unconfirms(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        baseline_url = "https://verify-target.com/api/orders/1001"
        manipulated_url = "https://verify-target.com/api/orders/1002"
        respx.get(baseline_url).mock(return_value=httpx.Response(200, text='{"order_id": 1001}'))
        respx.get(manipulated_url).mock(return_value=httpx.Response(403, text='{"error": "forbidden"}'))
        raw_findings = [
            {
                "cwe_id": "CWE-639",
                "endpoint": manipulated_url,
                "tier": "tier_b",
                "detection_method": "custom",
                "poc_evidence": (
                    f"baseline-url: {baseline_url}\nmanipulated-url: {manipulated_url}\n"
                    "unauthorized-marker: customer_email"
                ),
                "confidence": 0.85,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert result[0]["status"] == "unconfirmed"
        assert result[0]["verification_method"] == "idor_reprobe"


class TestCustomIdorVerificationWithoutMarker:
    """Regression coverage: idor_agent.py's real poc_evidence has no
    unauthorized-marker line (its detector is shape/status based, not
    marker based) — verification must not treat that as "cannot re-probe"."""

    @respx.mock
    def test_real_idor_agent_style_evidence_still_confirms_substantive_leak(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        baseline_url = "https://verify-target.com/api/orders/1001"
        manipulated_url = "https://verify-target.com/api/orders/1002"
        respx.get(baseline_url).mock(return_value=httpx.Response(200, text='{"order_id": 1001}'))
        respx.get(manipulated_url).mock(
            return_value=httpx.Response(200, text='{"order_id": 1002, "customer_email": "victim@example.com"}')
        )
        raw_findings = [
            {
                "cwe_id": "CWE-639",
                "endpoint": manipulated_url,
                "tier": "tier_b",
                "detection_method": "custom",
                "poc_evidence": (
                    f"Baseline GET {baseline_url} -> 200 (18 bytes). Manipulated GET {manipulated_url} "
                    "(id_param='order_id', strategy='increment_numeric_id') -> 200 (58 bytes). "
                    "Manipulated body sample: '...'. LLM reasoning: sibling order id.\n"
                    f"baseline-url: {baseline_url}\nmanipulated-url: {manipulated_url}"
                ),
                "confidence": 0.9,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert result[0]["status"] == "confirmed"
        assert result[0]["verification_method"] == "idor_reprobe"
        assert "substantive" in result[0]["verification_note"]

    @respx.mock
    def test_real_idor_agent_style_evidence_unconfirms_when_reprobe_now_forbidden(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        baseline_url = "https://verify-target.com/api/orders/1001"
        manipulated_url = "https://verify-target.com/api/orders/1002"
        respx.get(baseline_url).mock(return_value=httpx.Response(200, text='{"order_id": 1001}'))
        respx.get(manipulated_url).mock(return_value=httpx.Response(403, text='{"error": "forbidden"}'))
        raw_findings = [
            {
                "cwe_id": "CWE-639",
                "endpoint": manipulated_url,
                "tier": "tier_b",
                "detection_method": "custom",
                "poc_evidence": f"baseline-url: {baseline_url}\nmanipulated-url: {manipulated_url}",
                "confidence": 0.9,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert result[0]["status"] == "unconfirmed"
        assert result[0]["verification_method"] == "idor_reprobe"


class TestUnknownDetectionMethod:
    def test_falls_back_safely_without_crashing(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        raw_findings = [
            {
                "cwe_id": "CWE-1",
                "endpoint": "https://verify-target.com/whatever",
                "tier": "tier_a",
                "detection_method": "future_engine_v2",
                "poc_evidence": "matched-at: https://verify-target.com/whatever",
                "confidence": 0.5,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert len(result) == 1
        assert result[0]["status"] == "unconfirmed"
        assert result[0]["verification_method"] == "unknown_method_fallback"


class TestNetworkErrorHandling:
    @respx.mock
    def test_network_error_resolves_to_unconfirmed_not_raised(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        url = "https://verify-target.com/flaky"
        respx.get(url).mock(side_effect=httpx.ConnectError("connection refused"))
        raw_findings = [
            {
                "cwe_id": "CWE-79",
                "endpoint": "https://verify-target.com/flaky",
                "tier": "tier_a",
                "detection_method": "nuclei",
                "poc_evidence": f"matched-at: {url}\npattern: sentinel-xss-marker",
                "confidence": 0.8,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert len(result) == 1
        assert result[0]["status"] == "unconfirmed"
        assert "network_error" in result[0]["verification_method"]

    @respx.mock
    def test_one_failing_finding_does_not_abort_the_rest(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        broken_url = "https://verify-target.com/broken"
        good_url = "https://verify-target.com/search?q=sentinel-xss-marker"
        respx.get(broken_url).mock(side_effect=httpx.TimeoutException("timed out"))
        respx.get(good_url).mock(return_value=httpx.Response(200, text="sentinel-xss-marker"))
        raw_findings = [
            {
                "cwe_id": "CWE-79",
                "endpoint": "https://verify-target.com/broken",
                "tier": "tier_a",
                "detection_method": "nuclei",
                "poc_evidence": f"matched-at: {broken_url}\npattern: sentinel-xss-marker",
                "confidence": 0.8,
            },
            {
                "cwe_id": "CWE-79",
                "endpoint": "https://verify-target.com/search",
                "tier": "tier_a",
                "detection_method": "nuclei",
                "poc_evidence": f"matched-at: {good_url}\npattern: sentinel-xss-marker",
                "confidence": 0.8,
            },
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert len(result) == 2
        assert result[0]["status"] == "unconfirmed"
        assert "network_error" in result[0]["verification_method"]
        assert result[1]["status"] == "confirmed"


class TestNeverDropsFindings:
    @respx.mock
    def test_all_findings_returned_regardless_of_outcome(self, db_session):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        url = "https://verify-target.com/x"
        respx.get(url).mock(return_value=httpx.Response(500))
        raw_findings = [
            {
                "cwe_id": "CWE-79",
                "endpoint": "https://verify-target.com/x",
                "tier": "tier_a",
                "detection_method": "nuclei",
                "poc_evidence": f"matched-at: {url}\npattern: nope",
                "confidence": 0.6,
            }
        ]

        result = verification_agent.verify_findings(db_session, scan, raw_findings)

        assert len(result) == 1


class TestEnforceNotHalted:
    def test_raises_when_scan_already_halted(self, db_session):
        from sentinel.security.guardrails import ScanHaltedError

        reg = _registration(db_session)
        scan = _scan_session(db_session, reg, status=ScanStatus.HALTED)
        scan.halted_reason = "anomaly detected"

        with pytest.raises(ScanHaltedError):
            verification_agent.verify_findings(db_session, scan, [])


@contextmanager
def _wrap_session(session):
    yield session


class TestVerificationNode:
    @respx.mock
    def test_wraps_verify_findings_and_returns_expected_shape(self, db_session, monkeypatch):
        reg = _registration(db_session)
        scan = _scan_session(db_session, reg)
        url = "https://verify-target.com/search?q=sentinel-xss-marker"
        respx.get(url).mock(return_value=httpx.Response(200, text="sentinel-xss-marker"))

        monkeypatch.setattr(verification_agent, "get_session", lambda: _wrap_session(db_session))

        state = {
            "scan_session_id": scan.id,
            "raw_findings": [
                {
                    "cwe_id": "CWE-79",
                    "endpoint": "https://verify-target.com/search",
                    "tier": "tier_a",
                    "detection_method": "nuclei",
                    "poc_evidence": f"matched-at: {url}\npattern: sentinel-xss-marker",
                    "confidence": 0.8,
                }
            ],
        }

        result = verification_agent.verification_node(state)

        assert result["current_phase"] == "verification_complete"
        assert len(result["verified_findings"]) == 1
        assert result["verified_findings"][0]["status"] == "confirmed"
