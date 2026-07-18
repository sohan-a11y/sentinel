"""Agent 3 — Detection Dispatcher.

Routes the CWE checklist to the three scan engines (nuclei, ZAP, and the
custom IDOR agent), each of which implements the same
`run(db, scan_session, registration, cwe_items) -> list[RawFinding]`
interface (the IDOR agent additionally accepts `site_map`). This module does
not itself decide safety — every engine enforces its own guardrail checks;
this is pure routing plus a session-level halt check between engines so a
kill-switch trip stops the remaining engines from running at all.

This is also where Agent 6 (kill switch) gets fed real traffic: each engine
invocation is timed and its outcome (raised vs returned) is recorded into the
process-wide AnomalyMonitor via check_and_maybe_halt. That's per-engine
granularity, not per-HTTP-request — the ideal would be each wrapper recording
every individual request, but wiring it here, once, for all three engines is
the safe integration point that doesn't require re-touching three
already-tested modules for a coarser-but-real first cut.
"""
from __future__ import annotations

import time

from sqlalchemy.orm import Session

from sentinel.agents.dispatch import idor_agent, nuclei_wrapper, zap_wrapper
from sentinel.agents.kill_switch import check_and_maybe_halt
from sentinel.agents.state import RawFinding, SentinelState
from sentinel.db.models import ScanSession, ScanStatus, TargetRegistration
from sentinel.db.session import get_session
from sentinel.security import audit_log, guardrails
from sentinel.security.guardrails import ScanHaltedError


def run_all_engines(
    db: Session,
    scan_session: ScanSession,
    registration: TargetRegistration,
    cwe_items: list,
    site_map: dict | None,
) -> list[RawFinding]:
    if scan_session.contract_id is not None:
        # A signed contract currently authorizes only recon.v1. These engines
        # have direct or out-of-process egress paths, so a lease cannot yet
        # enforce every action they send. Keep them policy-blocked rather than
        # treating a Tier-A label as permission to run them.
        guardrails.enforce_not_halted(db, scan_session)
        audit_log.record(
            db,
            agent="dispatcher_agent",
            action="contract_recipe_engines_blocked",
            payload={
                "scan_session_id": scan_session.id,
                "contract_id": scan_session.contract_id,
                "blocked_engines": ["nuclei", "zap", "custom_idor"],
                "reason": "recon.v1 is the only contract-authorized recipe",
            },
        )
        return []

    engines = [
        ("nuclei", lambda: nuclei_wrapper.run(db, scan_session, registration, cwe_items)),
        ("zap", lambda: zap_wrapper.run(db, scan_session, registration, cwe_items)),
        ("custom_idor", lambda: idor_agent.run(db, scan_session, registration, cwe_items, site_map)),
    ]

    all_findings: list[RawFinding] = []
    for name, invoke in engines:
        try:
            guardrails.enforce_not_halted(db, scan_session)
        except ScanHaltedError as exc:
            audit_log.record(
                db,
                agent="dispatcher_agent",
                action="engine_skipped_scan_halted",
                payload={"engine": name, "reason": str(exc)},
            )
            break

        started_at = time.monotonic()
        try:
            findings = invoke()
        except ScanHaltedError as exc:
            check_and_maybe_halt(db, scan_session, success=False, latency_ms=(time.monotonic() - started_at) * 1000)
            audit_log.record(
                db,
                agent="dispatcher_agent",
                action="engine_halted_mid_run",
                payload={"engine": name, "reason": str(exc)},
            )
            break
        except Exception as exc:  # a single engine's bug must not sink the whole dispatch
            check_and_maybe_halt(db, scan_session, success=False, latency_ms=(time.monotonic() - started_at) * 1000)
            audit_log.record(
                db,
                agent="dispatcher_agent",
                action="engine_error",
                payload={"engine": name, "error": str(exc)},
            )
            continue

        just_halted = check_and_maybe_halt(
            db, scan_session, success=True, latency_ms=(time.monotonic() - started_at) * 1000
        )
        audit_log.record(
            db,
            agent="dispatcher_agent",
            action="engine_complete",
            payload={"engine": name, "finding_count": len(findings)},
        )
        all_findings.extend(findings)
        if just_halted:
            audit_log.record(
                db,
                agent="dispatcher_agent",
                action="engines_stopped_anomaly_halt",
                payload={"engine": name},
            )
            break

    return all_findings


def dispatcher_node(state: SentinelState) -> dict:
    scan_session_id = state["scan_session_id"]
    cwe_checklist = state.get("cwe_checklist", [])
    site_map = state.get("site_map")

    with get_session() as db:
        scan_session = db.get(ScanSession, scan_session_id)
        if scan_session is None:
            raise ValueError(f"ScanSession {scan_session_id} does not exist")
        registration = db.get(TargetRegistration, scan_session.target_id)

        findings = run_all_engines(db, scan_session, registration, cwe_checklist, site_map)
        halted = scan_session.status == ScanStatus.HALTED
        halt_reason = scan_session.halted_reason

    return {
        "raw_findings": findings,
        "cwe_checklist": cwe_checklist,
        "halted": halted,
        "halt_reason": halt_reason,
        "current_phase": "dispatch_complete",
    }
