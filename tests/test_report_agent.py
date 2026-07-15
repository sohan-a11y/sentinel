from __future__ import annotations

import contextlib
from datetime import datetime, timezone

import pytest

from sentinel.agents import report_agent
from sentinel.agents.report_agent import build_summary, export_markdown, export_pdf, report_node
from sentinel.db.models import (
    ActionTier,
    CweApplicability,
    EnvironmentTier,
    Finding,
    FindingStatus,
    ScanSession,
    ScanStatus,
    TargetRegistration,
)


def _make_scan_session(db_session, *, status: ScanStatus = ScanStatus.RUNNING, halted_reason=None) -> ScanSession:
    registration = TargetRegistration(
        domain="report-test.com",
        account_owner="alice@corp.com",
        verification_token="tok",
        canary_marker="marker",
        canary_check_url_template="https://x/{marker}",
        verification_passed_at=datetime.now(timezone.utc),
    )
    db_session.add(registration)
    db_session.flush()

    scan_session = ScanSession(
        target_id=registration.id,
        status=status,
        environment_tier=EnvironmentTier.VERIFIED_SAFE,
        started_at=datetime(2026, 7, 15, 9, 0, tzinfo=timezone.utc),
        ended_at=datetime(2026, 7, 15, 9, 45, tzinfo=timezone.utc),
        halted_reason=halted_reason,
    )
    db_session.add(scan_session)
    db_session.flush()
    return scan_session


def _populate_cwe_and_findings(db_session, scan_session_id: int) -> None:
    db_session.add_all(
        [
            CweApplicability(
                scan_session_id=scan_session_id,
                cwe_id="CWE-89",
                cwe_name="SQL Injection",
                applicable=True,
                reason="Login form accepts free-text input passed to a query",
                tested=True,
                detection_method="nuclei",
            ),
            CweApplicability(
                scan_session_id=scan_session_id,
                cwe_id="CWE-79",
                cwe_name="Cross-Site Scripting",
                applicable=True,
                reason="Search endpoint reflects query param unescaped",
                tested=True,
                detection_method="zap",
            ),
            CweApplicability(
                scan_session_id=scan_session_id,
                cwe_id="CWE-22",
                cwe_name="Path Traversal",
                applicable=True,
                reason="File download endpoint accepts a filename parameter",
                tested=False,
                detection_method=None,
            ),
            CweApplicability(
                scan_session_id=scan_session_id,
                cwe_id="CWE-352",
                cwe_name="CSRF",
                applicable=False,
                reason="No session-authenticated state-changing forms found",
                tested=False,
                detection_method=None,
            ),
        ]
    )
    db_session.add_all(
        [
            Finding(
                scan_session_id=scan_session_id,
                cwe_id="CWE-89",
                endpoint="/login",
                tier=ActionTier.TIER_A,
                detection_method="nuclei",
                poc_evidence="' OR '1'='1 returned all rows",
                confidence=0.95,
                status=FindingStatus.CONFIRMED,
            ),
            Finding(
                scan_session_id=scan_session_id,
                cwe_id="CWE-79",
                endpoint="/search",
                tier=ActionTier.TIER_A,
                detection_method="zap",
                poc_evidence="<script>alert(1)</script> reflected unescaped",
                confidence=0.6,
                status=FindingStatus.UNCONFIRMED,
            ),
            Finding(
                scan_session_id=scan_session_id,
                cwe_id="CWE-89",
                endpoint="/admin",
                tier=ActionTier.TIER_B,
                detection_method="nuclei",
                poc_evidence="second-order injection candidate",
                confidence=0.4,
                status=FindingStatus.PENDING_VERIFICATION,
            ),
        ]
    )
    db_session.flush()


class TestBuildSummary:
    def test_headline_numbers_and_string_are_exact(self, db_session):
        scan_session = _make_scan_session(db_session)
        _populate_cwe_and_findings(db_session, scan_session.id)

        summary = build_summary(db_session, scan_session.id)

        assert summary["applicable_cwe_count"] == 3
        assert summary["not_applicable_cwe_count"] == 1
        assert summary["tested_cwe_count"] == 2
        assert summary["confirmed_count"] == 1
        assert summary["unconfirmed_count"] == 1
        assert summary["pending_count"] == 1
        assert summary["headline"] == (
            "2/3 applicable CWEs tested, 1 confirmed exploitable, 1 unconfirmed"
        )

    def test_raises_for_missing_scan_session(self, db_session):
        with pytest.raises(ValueError):
            build_summary(db_session, 999999)


class TestExportMarkdown:
    def test_contains_domain_and_every_finding_cwe_id(self, db_session):
        scan_session = _make_scan_session(db_session)
        _populate_cwe_and_findings(db_session, scan_session.id)

        markdown = export_markdown(db_session, scan_session.id)

        assert "report-test.com" in markdown
        assert "CWE-89" in markdown
        assert "CWE-79" in markdown
        assert "2/3 applicable CWEs tested, 1 confirmed exploitable, 1 unconfirmed" in markdown
        assert "CWE-22" in markdown
        assert "CWE-352" in markdown

    def test_halted_banner_reason_included(self, db_session):
        scan_session = _make_scan_session(
            db_session, status=ScanStatus.HALTED, halted_reason="anomalous error rate detected"
        )
        _populate_cwe_and_findings(db_session, scan_session.id)

        markdown = export_markdown(db_session, scan_session.id)

        assert "anomalous error rate detected" in markdown


class TestExportPdf:
    def test_writes_valid_pdf_file(self, db_session, tmp_path):
        scan_session = _make_scan_session(db_session)
        _populate_cwe_and_findings(db_session, scan_session.id)

        output_path = tmp_path / "sentinel_report.pdf"
        export_pdf(db_session, scan_session.id, str(output_path))

        assert output_path.exists()
        content = output_path.read_bytes()
        assert content.startswith(b"%PDF")
        assert len(content) > 100

    def test_handles_xss_style_payloads_without_crashing(self, db_session, tmp_path):
        scan_session = _make_scan_session(db_session)
        _populate_cwe_and_findings(db_session, scan_session.id)

        output_path = tmp_path / "sentinel_report_xss.pdf"
        export_pdf(db_session, scan_session.id, str(output_path))

        assert output_path.read_bytes().startswith(b"%PDF")


class TestReportNode:
    def test_marks_terminal_phase(self, db_session, monkeypatch):
        scan_session = _make_scan_session(db_session)
        _populate_cwe_and_findings(db_session, scan_session.id)

        @contextlib.contextmanager
        def _fake_get_session():
            yield db_session

        monkeypatch.setattr(report_agent, "get_session", _fake_get_session)

        result = report_node({"scan_session_id": scan_session.id})

        assert result == {"current_phase": "report_complete"}
