from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest
import respx

from sentinel.agents.dispatch import zap_wrapper
from sentinel.config import settings
from sentinel.db.models import EnvironmentTier, ScanSession, ScanStatus, TargetRegistration

ZAP_BASE = settings.zap_api_url

SPIDER_SCAN_URL = f"{ZAP_BASE}/JSON/spider/action/scan/"
SPIDER_STATUS_URL = f"{ZAP_BASE}/JSON/spider/view/status/"
ASCAN_SCAN_URL = f"{ZAP_BASE}/JSON/ascan/action/scan/"
ASCAN_STATUS_URL = f"{ZAP_BASE}/JSON/ascan/view/status/"
ALERTS_URL = f"{ZAP_BASE}/JSON/core/view/alerts/"


def _registration(db_session, domain: str = "zap-test.com") -> TargetRegistration:
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
    reg: TargetRegistration,
    environment_tier: EnvironmentTier = EnvironmentTier.VERIFIED_SAFE,
    status: ScanStatus = ScanStatus.RUNNING,
) -> ScanSession:
    session_row = ScanSession(target_id=reg.id, status=status, environment_tier=environment_tier)
    db_session.add(session_row)
    db_session.flush()
    return session_row


def _cwe_items() -> list[dict]:
    return [
        {"cwe_id": "CWE-79", "name": "XSS", "category": "injection", "applicable": True, "reason": "r", "tested": False, "detection_method": None},
        {"cwe_id": "CWE-89", "name": "SQLi", "category": "injection", "applicable": True, "reason": "r", "tested": False, "detection_method": None},
    ]


class TestZapWrapperFullHappyPath:
    @respx.mock
    def test_both_tiers_return_findings_with_valid_cwe_ids(self, db_session):
        reg = _registration(db_session)
        scan_session = _scan_session(db_session, reg, environment_tier=EnvironmentTier.VERIFIED_SAFE)
        cwe_items = _cwe_items()

        respx.get(SPIDER_SCAN_URL).mock(return_value=httpx.Response(200, json={"scan": "1"}))
        respx.get(SPIDER_STATUS_URL).mock(return_value=httpx.Response(200, json={"status": "100"}))
        respx.get(ASCAN_SCAN_URL).mock(return_value=httpx.Response(200, json={"scan": "2"}))
        respx.get(ASCAN_STATUS_URL).mock(return_value=httpx.Response(200, json={"status": "100"}))

        passive_alerts = {
            "alerts": [
                {
                    "name": "Cross Site Scripting",
                    "url": "https://zap-test.com/search?q=1",
                    "cweid": "79",
                    "risk": "High",
                    "confidence": "Medium",
                    "evidence": "<script>alert(1)</script>",
                }
            ]
        }
        full_alerts = {
            "alerts": [
                {
                    "name": "Cross Site Scripting",
                    "url": "https://zap-test.com/search?q=1",
                    "cweid": "79",
                    "risk": "High",
                    "confidence": "Medium",
                    "evidence": "<script>alert(1)</script>",
                },
                {
                    "name": "SQL Injection",
                    "url": "https://zap-test.com/login",
                    "cweid": "89",
                    "risk": "Medium",
                    "confidence": "High",
                    "attack": "' OR '1'='1",
                },
            ]
        }
        respx.get(ALERTS_URL).mock(
            side_effect=[
                httpx.Response(200, json=passive_alerts),
                httpx.Response(200, json=full_alerts),
            ]
        )

        findings = zap_wrapper.run(db_session, scan_session, reg, cwe_items)

        assert len(findings) == 3
        tier_a_findings = [f for f in findings if f["tier"] == "tier_a"]
        tier_b_findings = [f for f in findings if f["tier"] == "tier_b"]
        assert len(tier_a_findings) == 1
        assert tier_a_findings[0]["cwe_id"] == "CWE-79"
        assert tier_a_findings[0]["detection_method"] == "zap"
        assert tier_a_findings[0]["confidence"] > 0

        assert len(tier_b_findings) == 2
        assert {f["cwe_id"] for f in tier_b_findings} == {"CWE-79", "CWE-89"}

        cwe79 = next(item for item in cwe_items if item["cwe_id"] == "CWE-79")
        cwe89 = next(item for item in cwe_items if item["cwe_id"] == "CWE-89")
        assert cwe79["tested"] is True
        assert cwe79["detection_method"] == "zap"
        assert cwe89["tested"] is True
        assert cwe89["detection_method"] == "zap"


class TestZapWrapperUnmappedCwe:
    @respx.mock
    def test_cweid_zero_is_logged_as_unmapped_not_dropped_silently(self, db_session):
        reg = _registration(db_session)
        scan_session = _scan_session(db_session, reg, environment_tier=EnvironmentTier.UNVERIFIED)
        cwe_items = _cwe_items()

        respx.get(SPIDER_SCAN_URL).mock(return_value=httpx.Response(200, json={"scan": "1"}))
        respx.get(SPIDER_STATUS_URL).mock(return_value=httpx.Response(200, json={"status": "100"}))

        alerts_with_unmapped = {
            "alerts": [
                {
                    "name": "Information Disclosure",
                    "url": "https://zap-test.com/debug",
                    "cweid": "0",
                    "risk": "Informational",
                    "confidence": "Low",
                },
                {
                    "name": "Cross Site Scripting",
                    "url": "https://zap-test.com/search?q=1",
                    "cweid": "79",
                    "risk": "High",
                    "confidence": "High",
                    "evidence": "<script>alert(1)</script>",
                },
            ]
        }
        respx.get(ALERTS_URL).mock(return_value=httpx.Response(200, json=alerts_with_unmapped))

        findings = zap_wrapper.run(db_session, scan_session, reg, cwe_items)

        assert len(findings) == 1
        assert findings[0]["cwe_id"] == "CWE-79"

        from sentinel.db.models import AuditLogEntry

        unmapped_entries = (
            db_session.query(AuditLogEntry)
            .filter(AuditLogEntry.action == "zap_alert_unmapped_cwe")
            .all()
        )
        assert len(unmapped_entries) == 1
        assert '"cweid": "0"' in unmapped_entries[0].payload_json


class TestZapWrapperTierBSkipped:
    @respx.mock
    def test_tier_b_skipped_when_environment_unverified(self, db_session):
        reg = _registration(db_session)
        scan_session = _scan_session(db_session, reg, environment_tier=EnvironmentTier.UNVERIFIED)
        cwe_items = _cwe_items()

        respx.get(SPIDER_SCAN_URL).mock(return_value=httpx.Response(200, json={"scan": "1"}))
        respx.get(SPIDER_STATUS_URL).mock(return_value=httpx.Response(200, json={"status": "100"}))
        ascan_scan_route = respx.get(ASCAN_SCAN_URL).mock(return_value=httpx.Response(200, json={"scan": "2"}))
        ascan_status_route = respx.get(ASCAN_STATUS_URL).mock(return_value=httpx.Response(200, json={"status": "100"}))

        passive_alerts = {
            "alerts": [
                {
                    "name": "Cross Site Scripting",
                    "url": "https://zap-test.com/search?q=1",
                    "cweid": "79",
                    "risk": "High",
                    "confidence": "Medium",
                }
            ]
        }
        alerts_route = respx.get(ALERTS_URL).mock(return_value=httpx.Response(200, json=passive_alerts))

        findings = zap_wrapper.run(db_session, scan_session, reg, cwe_items)

        assert ascan_scan_route.call_count == 0
        assert ascan_status_route.call_count == 0
        assert alerts_route.call_count == 1
        assert len(findings) == 1
        assert findings[0]["tier"] == "tier_a"

        from sentinel.db.models import AuditLogEntry

        skip_entries = (
            db_session.query(AuditLogEntry).filter(AuditLogEntry.action == "zap_ascan_skipped").all()
        )
        assert len(skip_entries) == 1


class TestZapWrapperUnreachable:
    @respx.mock
    def test_zap_unreachable_returns_empty_list_without_raising(self, db_session):
        reg = _registration(db_session)
        scan_session = _scan_session(db_session, reg, environment_tier=EnvironmentTier.VERIFIED_SAFE)
        cwe_items = _cwe_items()

        respx.get(SPIDER_SCAN_URL).mock(side_effect=httpx.ConnectError("refused"))

        findings = zap_wrapper.run(db_session, scan_session, reg, cwe_items)

        assert findings == []

        from sentinel.db.models import AuditLogEntry

        unavailable_entries = (
            db_session.query(AuditLogEntry).filter(AuditLogEntry.action == "zap_unavailable").all()
        )
        assert len(unavailable_entries) == 1

    @respx.mock
    def test_zap_unreachable_partway_returns_findings_already_collected(self, db_session):
        reg = _registration(db_session)
        scan_session = _scan_session(db_session, reg, environment_tier=EnvironmentTier.VERIFIED_SAFE)
        cwe_items = _cwe_items()

        respx.get(SPIDER_SCAN_URL).mock(return_value=httpx.Response(200, json={"scan": "1"}))
        respx.get(SPIDER_STATUS_URL).mock(return_value=httpx.Response(200, json={"status": "100"}))
        passive_alerts = {
            "alerts": [
                {
                    "name": "Cross Site Scripting",
                    "url": "https://zap-test.com/search?q=1",
                    "cweid": "79",
                    "risk": "High",
                    "confidence": "Medium",
                }
            ]
        }
        respx.get(ALERTS_URL).mock(return_value=httpx.Response(200, json=passive_alerts))
        respx.get(ASCAN_SCAN_URL).mock(side_effect=httpx.ConnectError("refused mid-run"))

        findings = zap_wrapper.run(db_session, scan_session, reg, cwe_items)

        assert len(findings) == 1
        assert findings[0]["tier"] == "tier_a"


class TestZapWrapperGuardrails:
    def test_raises_when_scan_halted(self, db_session):
        reg = _registration(db_session)
        scan_session = _scan_session(db_session, reg, status=ScanStatus.HALTED)
        cwe_items = _cwe_items()

        from sentinel.security.guardrails import ScanHaltedError

        with pytest.raises(ScanHaltedError):
            zap_wrapper.run(db_session, scan_session, reg, cwe_items)
