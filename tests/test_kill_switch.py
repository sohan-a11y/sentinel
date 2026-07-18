from __future__ import annotations

import itertools
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from sentinel.agents import kill_switch
from sentinel.config import settings
from sentinel.db.models import AuditLogEntry, ScanSession, ScanStatus, TargetRegistration

_session_id_counter = itertools.count(1)


def _next_session_id() -> int:
    return next(_session_id_counter)


def _make_scan_session(db_session, session_id: int) -> ScanSession:
    reg = TargetRegistration(
        domain=f"killswitch-test-{session_id}.com",
        account_owner="alice@corp.com",
        verification_token="tok",
        canary_marker="marker",
        canary_check_url_template="https://x/{marker}",
        verification_passed_at=datetime.now(timezone.utc),
    )
    db_session.add(reg)
    db_session.flush()

    scan_session = ScanSession(id=session_id, target_id=reg.id, status=ScanStatus.RUNNING)
    db_session.add(scan_session)
    db_session.flush()
    return scan_session


@pytest.fixture(autouse=True)
def _redirect_audit_log_file(tmp_path, monkeypatch):
    monkeypatch.setattr(kill_switch.audit_log.settings, "audit_log_file", str(tmp_path / "audit.ndjson"))


class TestShouldHalt:
    def test_below_min_samples_never_halts_regardless_of_badness(self):
        monitor = kill_switch.AnomalyMonitor()
        session_id = _next_session_id()
        for _ in range(settings.killswitch_min_samples - 1):
            monitor.record_result(session_id, success=False, latency_ms=999_999.0)

        halted, reason = monitor.should_halt(session_id)
        assert halted is False
        assert reason is None

    def test_error_rate_above_threshold_triggers_halt(self):
        monitor = kill_switch.AnomalyMonitor()
        session_id = _next_session_id()
        n = settings.killswitch_min_samples
        failures = min(n, int(n * (settings.killswitch_error_rate_threshold + 0.25)) + 1)

        for i in range(n):
            success = i >= failures
            monitor.record_result(session_id, success=success, latency_ms=100.0)

        halted, reason = monitor.should_halt(session_id)
        assert halted is True
        assert reason is not None
        assert "error rate" in reason.lower()

    def test_latency_spike_triggers_halt(self):
        monitor = kill_switch.AnomalyMonitor()
        session_id = _next_session_id()
        n = max(settings.killswitch_min_samples, 20)
        quarter = max(1, n // 4)
        spike_latency = 50.0 * settings.killswitch_latency_multiplier * 10

        for i in range(n):
            latency = spike_latency if i >= n - quarter else 50.0
            monitor.record_result(session_id, success=True, latency_ms=latency)

        halted, reason = monitor.should_halt(session_id)
        assert halted is True
        assert reason is not None
        assert "latency" in reason.lower()

    def test_good_samples_never_halt(self):
        monitor = kill_switch.AnomalyMonitor()
        session_id = _next_session_id()
        n = max(settings.killswitch_min_samples, 20)
        for _ in range(n):
            monitor.record_result(session_id, success=True, latency_ms=100.0)

        halted, reason = monitor.should_halt(session_id)
        assert halted is False
        assert reason is None


class TestTriggerHalt:
    def test_updates_scan_session_and_writes_one_audit_entry(self, db_session):
        session_id = _next_session_id()
        scan_session = _make_scan_session(db_session, session_id)

        registry = kill_switch.HaltRegistry()
        registry.trigger_halt(db_session, session_id, "test reason")

        db_session.refresh(scan_session)
        assert scan_session.status == ScanStatus.HALTED
        assert scan_session.halted_reason == "test reason"
        assert scan_session.ended_at is not None

        entries = db_session.query(AuditLogEntry).filter(AuditLogEntry.action == "scan_halted").all()
        assert len(entries) == 1
        assert "test reason" in entries[0].payload_json
        assert str(session_id) in entries[0].payload_json

    def test_raises_for_unknown_scan_session(self, db_session):
        registry = kill_switch.HaltRegistry()
        with pytest.raises(ValueError):
            registry.trigger_halt(db_session, 999_999_999, "nope")

    def test_halt_revokes_any_bound_action_lease(self, db_session):
        session_id = _next_session_id()
        scan_session = _make_scan_session(db_session, session_id)
        # A non-null binding is enough to verify the control-plane handoff;
        # the lease service owns the precise lookup/revocation behavior.
        scan_session.contract_id = 123
        db_session.flush()

        registry = kill_switch.HaltRegistry()
        with patch("sentinel.control_plane.service.revoke_lease_for_scan") as revoke_lease:
            registry.trigger_halt(db_session, session_id, "operator stop")

        revoke_lease.assert_called_once()
        assert revoke_lease.call_args.kwargs["scan_session"].id == session_id
        assert revoke_lease.call_args.kwargs["reason"] == "operator stop"


class TestIsHalted:
    def test_reflects_event_state_before_and_after_trigger(self, db_session):
        session_id = _next_session_id()
        _make_scan_session(db_session, session_id)

        registry = kill_switch.HaltRegistry()
        assert registry.is_halted(session_id) is False

        registry.trigger_halt(db_session, session_id, "boom")
        assert registry.is_halted(session_id) is True


class TestCheckAndMaybeHalt:
    def test_end_to_end_halts_on_bad_samples(self, db_session):
        session_id = _next_session_id()
        scan_session = _make_scan_session(db_session, session_id)

        result = False
        for _ in range(settings.killswitch_min_samples):
            result = kill_switch.check_and_maybe_halt(
                db_session, scan_session, success=False, latency_ms=100.0
            )

        assert result is True
        db_session.refresh(scan_session)
        assert scan_session.status == ScanStatus.HALTED
        assert kill_switch.get_halt_registry().is_halted(session_id) is True

        entries = (
            db_session.query(AuditLogEntry)
            .filter(AuditLogEntry.action == "scan_halted")
            .all()
        )
        assert len(entries) == 1

    def test_returns_false_and_no_halt_for_healthy_traffic(self, db_session):
        session_id = _next_session_id()
        scan_session = _make_scan_session(db_session, session_id)

        result = False
        for _ in range(settings.killswitch_min_samples):
            result = kill_switch.check_and_maybe_halt(
                db_session, scan_session, success=True, latency_ms=100.0
            )

        assert result is False
        db_session.refresh(scan_session)
        assert scan_session.status == ScanStatus.RUNNING
        assert kill_switch.get_halt_registry().is_halted(session_id) is False


class TestManualHalt:
    def test_manual_halt_updates_db_via_session_id_lookup(self, db_session):
        session_id = _next_session_id()
        scan_session = _make_scan_session(db_session, session_id)

        kill_switch.manual_halt(db_session, session_id, reason="stop now")

        db_session.refresh(scan_session)
        assert scan_session.status == ScanStatus.HALTED
        assert scan_session.halted_reason == "stop now"
        assert scan_session.ended_at is not None
        assert kill_switch.get_halt_registry().is_halted(session_id) is True

        entries = db_session.query(AuditLogEntry).filter(AuditLogEntry.action == "scan_halted").all()
        assert len(entries) == 1

    def test_manual_halt_raises_for_unknown_scan_session(self, db_session):
        with pytest.raises(ValueError):
            kill_switch.manual_halt(db_session, 999_999_998, reason="stop now")
