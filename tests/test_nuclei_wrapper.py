from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from sentinel.agents.dispatch import nuclei_wrapper
from sentinel.db.models import (
    AuditLogEntry,
    EnvironmentTier,
    ScanSession,
    ScanStatus,
    TargetRegistration,
)
from sentinel.security.guardrails import ScanHaltedError


def _registration(db_session, domain: str = "example-test.com") -> TargetRegistration:
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
    status: ScanStatus = ScanStatus.RUNNING,
    environment_tier: EnvironmentTier = EnvironmentTier.UNVERIFIED,
) -> ScanSession:
    session_row = ScanSession(target_id=registration.id, status=status, environment_tier=environment_tier)
    db_session.add(session_row)
    db_session.flush()
    return session_row


def _completed(stdout: str) -> MagicMock:
    completed = MagicMock()
    completed.stdout = stdout
    completed.returncode = 0
    return completed


def _audit_actions(db_session, action: str) -> list[AuditLogEntry]:
    return db_session.query(AuditLogEntry).filter(AuditLogEntry.action == action).all()


MAPPED_LINE = (
    '{"template-id": "xss-reflected", "matched-at": "https://example-test.com/search?q=1", '
    '"info": {"severity": "high", "classification": {"cwe-id": ["CWE-79"]}}, '
    '"extracted-results": ["<script>alert(1)</script>"]}'
)

UNMAPPED_LINE = (
    '{"template-id": "tech-detect-generic", "matched-at": "https://example-test.com/", '
    '"info": {"severity": "info"}}'
)


class TestCweMapping:
    def test_maps_cwe_correctly(self, db_session):
        reg = _registration(db_session)
        session_row = _scan_session(db_session, reg)
        cwe_items = [{"cwe_id": "CWE-79", "name": "XSS", "tested": False, "detection_method": None}]

        with patch("sentinel.agents.dispatch.nuclei_wrapper.subprocess.run") as mock_run:
            mock_run.return_value = _completed(MAPPED_LINE + "\n")
            findings = nuclei_wrapper.run(db_session, session_row, reg, cwe_items)

        assert len(findings) == 1
        finding = findings[0]
        assert finding["cwe_id"] == "CWE-79"
        assert finding["tier"] == "tier_a"
        assert finding["detection_method"] == "nuclei"
        assert finding["confidence"] == pytest.approx(0.8)
        assert "xss-reflected" in finding["poc_evidence"]
        assert "example-test.com/search" in finding["poc_evidence"]

        assert cwe_items[0]["tested"] is True
        assert cwe_items[0]["detection_method"] == "nuclei"

        detected = _audit_actions(db_session, "finding_detected")
        assert len(detected) == 1

    def test_unmapped_finding_is_logged_not_dropped(self, db_session):
        reg = _registration(db_session)
        session_row = _scan_session(db_session, reg)
        cwe_items: list = []

        with patch("sentinel.agents.dispatch.nuclei_wrapper.subprocess.run") as mock_run:
            mock_run.return_value = _completed(UNMAPPED_LINE + "\n")
            findings = nuclei_wrapper.run(db_session, session_row, reg, cwe_items)

        assert findings == []
        unmapped = _audit_actions(db_session, "nuclei_finding_unmapped")
        assert len(unmapped) == 1
        assert unmapped[0].payload_json.count("tech-detect-generic") == 1

    def test_mapped_and_unmapped_together_neither_silently_dropped(self, db_session):
        reg = _registration(db_session)
        session_row = _scan_session(db_session, reg)
        cwe_items = [{"cwe_id": "CWE-79", "name": "XSS", "tested": False, "detection_method": None}]

        stdout = MAPPED_LINE + "\n" + UNMAPPED_LINE + "\n"
        with patch("sentinel.agents.dispatch.nuclei_wrapper.subprocess.run") as mock_run:
            mock_run.return_value = _completed(stdout)
            findings = nuclei_wrapper.run(db_session, session_row, reg, cwe_items)

        assert len(findings) == 1
        assert len(_audit_actions(db_session, "finding_detected")) == 1
        assert len(_audit_actions(db_session, "nuclei_finding_unmapped")) == 1


class TestSeverityConfidenceMapping:
    @pytest.mark.parametrize(
        "severity,expected_confidence",
        [
            ("info", 0.3),
            ("low", 0.5),
            ("medium", 0.65),
            ("high", 0.8),
            ("critical", 0.9),
        ],
    )
    def test_severity_maps_to_confidence(self, db_session, severity, expected_confidence):
        reg = _registration(db_session)
        session_row = _scan_session(db_session, reg)
        cwe_items: list = []
        line = (
            '{"template-id": "generic-check", "matched-at": "https://example-test.com/", '
            f'"info": {{"severity": "{severity}", "classification": {{"cwe-id": ["CWE-89"]}}}}}}'
        )

        with patch("sentinel.agents.dispatch.nuclei_wrapper.subprocess.run") as mock_run:
            mock_run.return_value = _completed(line + "\n")
            findings = nuclei_wrapper.run(db_session, session_row, reg, cwe_items)

        assert len(findings) == 1
        assert findings[0]["confidence"] == pytest.approx(expected_confidence)


class TestCommandConstruction:
    def test_excludes_dos_and_fuzz_tags(self, db_session):
        reg = _registration(db_session)
        session_row = _scan_session(db_session, reg)

        with patch("sentinel.agents.dispatch.nuclei_wrapper.subprocess.run") as mock_run:
            mock_run.return_value = _completed("")
            nuclei_wrapper.run(db_session, session_row, reg, [])

        command = mock_run.call_args[0][0]
        assert "-etags" in command
        etags_index = command.index("-etags")
        assert command[etags_index + 1] == "dos,fuzz"

    def test_targets_registered_domain_over_https(self, db_session):
        reg = _registration(db_session, domain="scope-test.com")
        session_row = _scan_session(db_session, reg)

        with patch("sentinel.agents.dispatch.nuclei_wrapper.subprocess.run") as mock_run:
            mock_run.return_value = _completed("")
            nuclei_wrapper.run(db_session, session_row, reg, [])

        command = mock_run.call_args[0][0]
        assert "-u" in command
        assert command[command.index("-u") + 1] == "https://scope-test.com"


class TestUnavailableFallback:
    def test_file_not_found_returns_empty_list(self, db_session):
        reg = _registration(db_session)
        session_row = _scan_session(db_session, reg)

        with patch("sentinel.agents.dispatch.nuclei_wrapper.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("nuclei binary not found")
            findings = nuclei_wrapper.run(db_session, session_row, reg, [])

        assert findings == []
        unavailable = _audit_actions(db_session, "nuclei_unavailable")
        assert len(unavailable) == 1
        assert "binary_not_found" in unavailable[0].payload_json

    def test_timeout_returns_empty_list(self, db_session):
        reg = _registration(db_session)
        session_row = _scan_session(db_session, reg)

        with patch("sentinel.agents.dispatch.nuclei_wrapper.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=300)
            findings = nuclei_wrapper.run(db_session, session_row, reg, [])

        assert findings == []
        unavailable = _audit_actions(db_session, "nuclei_unavailable")
        assert len(unavailable) == 1
        assert "timeout" in unavailable[0].payload_json


class TestGuardrails:
    def test_halted_session_raises_before_subprocess(self, db_session):
        reg = _registration(db_session)
        session_row = _scan_session(db_session, reg, status=ScanStatus.HALTED)

        with patch("sentinel.agents.dispatch.nuclei_wrapper.subprocess.run") as mock_run:
            with pytest.raises(ScanHaltedError):
                nuclei_wrapper.run(db_session, session_row, reg, [])

        mock_run.assert_not_called()

    def test_tier_a_allowed_even_when_environment_unverified(self, db_session):
        reg = _registration(db_session)
        session_row = _scan_session(db_session, reg, environment_tier=EnvironmentTier.UNVERIFIED)

        with patch("sentinel.agents.dispatch.nuclei_wrapper.subprocess.run") as mock_run:
            mock_run.return_value = _completed("")
            findings = nuclei_wrapper.run(db_session, session_row, reg, [])

        assert findings == []
        mock_run.assert_called_once()
