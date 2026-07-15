from __future__ import annotations

from datetime import datetime, timezone

from sentinel.agents import persistence
from sentinel.db.models import (
    ActionTier,
    CweApplicability,
    Finding,
    FindingStatus,
    ScanSession,
    ScanStatus,
    TargetRegistration,
)


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


def _scan_session(db_session, reg) -> ScanSession:
    session_row = ScanSession(target_id=reg.id, status=ScanStatus.RUNNING)
    db_session.add(session_row)
    db_session.flush()
    return session_row


def test_sync_cwe_checklist_updates_tested_flags_and_scan_session_count(db_session):
    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)
    db_session.add(
        CweApplicability(
            scan_session_id=scan_session.id, cwe_id="CWE-79", cwe_name="XSS", applicable=True, reason="r", tested=False
        )
    )
    db_session.add(
        CweApplicability(
            scan_session_id=scan_session.id, cwe_id="CWE-89", cwe_name="SQLi", applicable=True, reason="r", tested=False
        )
    )
    db_session.flush()

    checklist = [
        {"cwe_id": "CWE-79", "tested": True, "detection_method": "nuclei"},
        {"cwe_id": "CWE-89", "tested": False, "detection_method": None},
    ]
    tested_count = persistence.sync_cwe_checklist(db_session, scan_session.id, checklist)

    assert tested_count == 1
    row79 = db_session.query(CweApplicability).filter_by(cwe_id="CWE-79").one()
    assert row79.tested is True
    assert row79.detection_method == "nuclei"
    row89 = db_session.query(CweApplicability).filter_by(cwe_id="CWE-89").one()
    assert row89.tested is False

    refreshed_session = db_session.get(ScanSession, scan_session.id)
    assert refreshed_session.tested_cwe_count == 1


def test_sync_cwe_checklist_ignores_unknown_cwe_ids(db_session):
    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)
    checklist = [{"cwe_id": "CWE-999", "tested": True, "detection_method": "nuclei"}]
    tested_count = persistence.sync_cwe_checklist(db_session, scan_session.id, checklist)
    assert tested_count == 0


def test_persist_findings_creates_finding_rows(db_session):
    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)

    verified = [
        {
            "cwe_id": "CWE-79",
            "endpoint": "https://example-test.com/x",
            "tier": "tier_a",
            "detection_method": "nuclei",
            "poc_evidence": "evidence",
            "confidence": 0.7,
            "status": "confirmed",
            "verification_method": "nuclei_xss_pattern_replay",
            "verification_note": "still reflected",
        },
        {
            "cwe_id": "CWE-639",
            "endpoint": "https://example-test.com/y",
            "tier": "tier_b",
            "detection_method": "custom",
            "poc_evidence": "evidence2",
            "confidence": 0.6,
            "status": "unconfirmed",
            "verification_method": "idor_reprobe",
            "verification_note": "did not reproduce",
        },
    ]
    rows = persistence.persist_findings(db_session, scan_session.id, verified)

    assert len(rows) == 2
    persisted = db_session.query(Finding).filter(Finding.scan_session_id == scan_session.id).all()
    assert len(persisted) == 2
    confirmed = [f for f in persisted if f.status == FindingStatus.CONFIRMED]
    assert len(confirmed) == 1
    assert confirmed[0].cwe_id == "CWE-79"
    assert confirmed[0].tier == ActionTier.TIER_A

    unconfirmed = [f for f in persisted if f.status == FindingStatus.UNCONFIRMED]
    assert len(unconfirmed) == 1
    assert unconfirmed[0].tier == ActionTier.TIER_B


def test_persist_findings_defaults_unknown_status_to_pending(db_session):
    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)
    verified = [
        {
            "cwe_id": "CWE-79",
            "endpoint": "e",
            "tier": "tier_a",
            "detection_method": "nuclei",
            "poc_evidence": "x",
            "confidence": 0.5,
        }
    ]
    rows = persistence.persist_findings(db_session, scan_session.id, verified)
    assert rows[0].status == FindingStatus.PENDING_VERIFICATION


def test_sync_cwe_checklist_node_and_persist_findings_node_use_get_session(db_session, monkeypatch):
    reg = _registration(db_session)
    scan_session = _scan_session(db_session, reg)
    db_session.add(
        CweApplicability(
            scan_session_id=scan_session.id, cwe_id="CWE-79", cwe_name="XSS", applicable=True, reason="r", tested=False
        )
    )
    db_session.flush()

    class _FakeCtx:
        def __enter__(self):
            return db_session

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(persistence, "get_session", lambda: _FakeCtx())

    result1 = persistence.sync_cwe_checklist_node(
        {"scan_session_id": scan_session.id, "cwe_checklist": [{"cwe_id": "CWE-79", "tested": True, "detection_method": "zap"}]}
    )
    assert result1["current_phase"] == "cwe_checklist_synced"

    result2 = persistence.persist_findings_node(
        {
            "scan_session_id": scan_session.id,
            "verified_findings": [
                {
                    "cwe_id": "CWE-79",
                    "endpoint": "e",
                    "tier": "tier_a",
                    "detection_method": "zap",
                    "poc_evidence": "x",
                    "confidence": 0.5,
                    "status": "confirmed",
                }
            ],
        }
    )
    assert result2["current_phase"] == "findings_persisted"
    assert db_session.query(Finding).filter(Finding.scan_session_id == scan_session.id).count() == 1


def test_mark_unverified_due_to_halt_demotes_without_dropping():
    raw = [
        {"cwe_id": "CWE-79", "endpoint": "e", "tier": "tier_a", "detection_method": "nuclei", "poc_evidence": "x", "confidence": 0.7},
        {"cwe_id": "CWE-639", "endpoint": "e2", "tier": "tier_b", "detection_method": "custom", "poc_evidence": "y", "confidence": 0.9},
    ]
    result = persistence.mark_unverified_due_to_halt(raw)

    assert len(result) == 2
    for original, marked in zip(raw, result):
        assert marked["status"] == "unconfirmed"
        assert marked["verification_method"] == "skipped_scan_halted"
        assert "halted" in marked["verification_note"]
        assert marked["cwe_id"] == original["cwe_id"]
        assert marked["endpoint"] == original["endpoint"]


def test_finalize_halted_findings_node_wraps_raw_findings():
    raw = [{"cwe_id": "CWE-79", "endpoint": "e", "tier": "tier_a", "detection_method": "nuclei", "poc_evidence": "x", "confidence": 0.7}]
    result = persistence.finalize_halted_findings_node({"raw_findings": raw})

    assert result["current_phase"] == "verification_skipped_scan_halted"
    assert len(result["verified_findings"]) == 1
    assert result["verified_findings"][0]["status"] == "unconfirmed"


def test_finalize_halted_findings_node_handles_no_findings():
    result = persistence.finalize_halted_findings_node({"raw_findings": []})
    assert result["verified_findings"] == []
