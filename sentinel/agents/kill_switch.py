"""Agent 6 — Kill Switch Monitor.

Watches per-scan-session traffic for anomalous target behavior (error-rate
spikes, latency spikes) and auto-halts; also exposes the one human touchpoint
after the Phase 0 gate (manual_halt); and is the audit log's primary consumer
for proving halts stick — every halt, automatic or manual, flips
ScanSession.status to HALTED in the DB (the source of truth every other
process reads) and writes exactly one immutable audit_log entry before this
module returns control to the caller.

The in-memory threading.Event per scan_session_id is a fast-path check for
tight dispatch loops (guardrails.enforce_not_halted still reads the DB row —
that stays the hard boundary); it is never the sole record of a halt.
"""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from sentinel.config import settings
from sentinel.db.models import ScanSession, ScanStatus
from sentinel.security import audit_log


class AnomalyMonitor:
    """Tracks rolling (success, latency_ms) samples per scan_session_id."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._samples: dict[int, deque[tuple[bool, float]]] = {}

    def record_result(self, scan_session_id: int, *, success: bool, latency_ms: float) -> None:
        with self._lock:
            bucket = self._samples.setdefault(scan_session_id, deque())
            bucket.append((success, latency_ms))

    def should_halt(self, scan_session_id: int) -> tuple[bool, str | None]:
        with self._lock:
            bucket = self._samples.get(scan_session_id)
            samples = list(bucket) if bucket is not None else []

        total = len(samples)
        if total < settings.killswitch_min_samples:
            return False, None

        failures = sum(1 for success, _ in samples if not success)
        error_rate = failures / total
        if error_rate > settings.killswitch_error_rate_threshold:
            return (
                True,
                f"error rate {error_rate:.2%} over {total} samples exceeds threshold "
                f"{settings.killswitch_error_rate_threshold:.2%}",
            )

        half = max(1, total // 2)
        baseline_latencies = [latency for _, latency in samples[:half]]
        baseline_mean = sum(baseline_latencies) / len(baseline_latencies)

        quarter = max(1, total // 4)
        recent_latencies = [latency for _, latency in samples[-quarter:]]
        recent_mean = sum(recent_latencies) / len(recent_latencies)

        if baseline_mean > 0 and recent_mean > baseline_mean * settings.killswitch_latency_multiplier:
            return (
                True,
                f"recent mean latency {recent_mean:.1f}ms exceeds baseline {baseline_mean:.1f}ms "
                f"x{settings.killswitch_latency_multiplier} (baseline first-half vs recent-quarter)",
            )

        return False, None


_monitor_singleton: AnomalyMonitor | None = None


def get_anomaly_monitor() -> AnomalyMonitor:
    global _monitor_singleton
    if _monitor_singleton is None:
        _monitor_singleton = AnomalyMonitor()
    return _monitor_singleton


class HaltRegistry:
    """Process-wide scan_session_id -> threading.Event map, guarded by a lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[int, threading.Event] = {}

    def is_halted(self, scan_session_id: int) -> bool:
        with self._lock:
            event = self._events.setdefault(scan_session_id, threading.Event())
        return event.is_set()

    def trigger_halt(
        self, db: Session, scan_session_id: int, reason: str, *, agent: str = "kill_switch"
    ) -> None:
        with self._lock:
            event = self._events.setdefault(scan_session_id, threading.Event())
            event.set()

        scan_session = db.get(ScanSession, scan_session_id)
        if scan_session is None:
            raise ValueError(f"ScanSession {scan_session_id} does not exist")

        scan_session.status = ScanStatus.HALTED
        scan_session.halted_reason = reason
        scan_session.ended_at = datetime.now(timezone.utc)
        db.flush()

        audit_log.record(
            db,
            agent=agent,
            action="scan_halted",
            payload={"scan_session_id": scan_session_id, "reason": reason},
        )


_registry_singleton: HaltRegistry | None = None


def get_halt_registry() -> HaltRegistry:
    global _registry_singleton
    if _registry_singleton is None:
        _registry_singleton = HaltRegistry()
    return _registry_singleton


def check_and_maybe_halt(
    db: Session, scan_session: ScanSession, *, success: bool, latency_ms: float
) -> bool:
    """Call after every real network round-trip to the target. Records the
    sample, checks the anomaly thresholds, and halts if warranted."""
    monitor = get_anomaly_monitor()
    monitor.record_result(scan_session.id, success=success, latency_ms=latency_ms)

    should_halt, reason = monitor.should_halt(scan_session.id)
    if not should_halt:
        return False

    get_halt_registry().trigger_halt(db, scan_session.id, reason or "anomaly detected", agent="kill_switch")
    return True


def manual_halt(db: Session, scan_session_id: int, reason: str = "manual operator halt") -> None:
    """The one human touchpoint after the Phase 0 gate: an operator-initiated
    halt. The HTTP endpoint that calls this lives in the FastAPI layer."""
    scan_session = db.get(ScanSession, scan_session_id)
    if scan_session is None:
        raise ValueError(f"ScanSession {scan_session_id} does not exist")

    get_halt_registry().trigger_halt(db, scan_session_id, reason, agent="operator")
