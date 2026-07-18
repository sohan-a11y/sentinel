"""LangGraph wiring — the six agents as nodes sharing SentinelState.

    recon -> cwe_mapping -> dispatch -+-> (halted)     -> finalize_halted -+-> persist_findings -> report -> END
                                      +-> (not halted) -> verification    -+

Agent 6 (kill switch) is not a graph node — it runs "in parallel throughout"
by design (per the spec), which in this codebase means: every dispatch call
checks guardrails.enforce_not_halted before acting, and dispatcher_agent feeds
real traffic into the AnomalyMonitor after every engine invocation. If a halt
fires mid-dispatch, the conditional edge below routes straight to
finalize_halted instead of verification — because verification also makes
live requests to the target, and running it after a halt would violate the
halt it's supposed to respect.
"""
from __future__ import annotations

from langgraph.graph import END, StateGraph

from sentinel.agents.cwe_mapping_agent import cwe_mapping_node
from sentinel.agents.dispatcher_agent import dispatcher_node
from sentinel.agents.persistence import (
    finalize_halted_findings_node,
    persist_findings_node,
    sync_cwe_checklist_node,
)
from sentinel.agents.recon_agent import recon_node
from sentinel.agents.report_agent import report_node
from sentinel.agents.state import SentinelState
from sentinel.agents.verification_agent import verification_node
from sentinel.control_plane import service
from sentinel.db.models import ActionTier, ScanSession, ScanStatus, TargetRegistration
from sentinel.db.session import get_session
from sentinel.security import guardrails
from sentinel.security.guardrails import ScanHaltedError


def _route_after_dispatch(state: SentinelState) -> str:
    return "finalize_halted" if state.get("halted") else "verification"


def build_graph():
    graph = StateGraph(SentinelState)

    graph.add_node("recon", recon_node)
    graph.add_node("cwe_mapping", cwe_mapping_node)
    graph.add_node("dispatch", dispatcher_node)
    graph.add_node("sync_cwe_checklist", sync_cwe_checklist_node)
    graph.add_node("finalize_halted", finalize_halted_findings_node)
    graph.add_node("verification", verification_node)
    graph.add_node("persist_findings", persist_findings_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("recon")
    graph.add_edge("recon", "cwe_mapping")
    graph.add_edge("cwe_mapping", "dispatch")
    graph.add_edge("dispatch", "sync_cwe_checklist")
    graph.add_conditional_edges(
        "sync_cwe_checklist",
        _route_after_dispatch,
        {"finalize_halted": "finalize_halted", "verification": "verification"},
    )
    graph.add_edge("finalize_halted", "persist_findings")
    graph.add_edge("verification", "persist_findings")
    graph.add_edge("persist_findings", "report")
    graph.add_edge("report", END)

    return graph.compile()


_compiled_graph = None


def get_compiled_graph():
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph()
    return _compiled_graph


def run_scan_pipeline(
    scan_session_id: int,
    target_domain: str | None = None,
    environment_tier: str | None = None,
) -> SentinelState:
    """Execute only a committed, contract-bound recon.v1 session.

    The retained parameters preserve the background-task call shape but are
    intentionally ignored as authority. Target and tier are reloaded from
    the committed database record so a future caller cannot smuggle a domain
    or turn an old Phase-0 session into an unleased scan.
    """
    try:
        with get_session() as db:
            scan_session = db.get(ScanSession, scan_session_id)
            if scan_session is None:
                raise ValueError(f"ScanSession {scan_session_id} does not exist")
            # Preserve the semantic terminal halt signal. A halted worker is
            # not a malformed contract run, and the guard also records any
            # lease state that made the halt necessary.
            if scan_session.status == ScanStatus.HALTED:
                guardrails.enforce_not_halted(db, scan_session)
            if (
                scan_session.status != ScanStatus.RUNNING
                or scan_session.contract_id is None
                or scan_session.permitted_action_tier != ActionTier.TIER_A
            ):
                raise service.ContractStateError(
                    f"Scan session {scan_session_id} is not an active contract-backed recon.v1 run"
                )
            guardrails.enforce_not_halted(db, scan_session)
            target = db.get(TargetRegistration, scan_session.target_id)
            if target is None:
                raise service.ContractStateError(
                    f"Scan session {scan_session_id} has no registered target"
                )
            authoritative_domain = target.domain
            authoritative_tier = scan_session.environment_tier.value
    except ScanHaltedError:
        # A policy halt is already durable; do not relabel it as a worker
        # failure simply because graph startup observes it.
        raise
    except Exception as exc:
        with get_session() as db:
            failed_session = db.get(ScanSession, scan_session_id)
            if failed_session is not None:
                service.fail_contract_scan(
                    db,
                    scan_session=failed_session,
                    reason=f"pipeline entry rejected: {type(exc).__name__}",
                )
        raise

    initial_state: SentinelState = {
        "scan_session_id": scan_session_id,
        "target_domain": authoritative_domain,
        "environment_tier": authoritative_tier,
        "halted": False,
        "halt_reason": None,
        "errors": [],
        "current_phase": "starting",
    }
    graph = get_compiled_graph()
    try:
        return graph.invoke(initial_state)
    except ScanHaltedError:
        raise
    except Exception as exc:
        with get_session() as db:
            failed_session = db.get(ScanSession, scan_session_id)
            if failed_session is not None:
                service.fail_contract_scan(
                    db,
                    scan_session=failed_session,
                    reason=f"pipeline execution failed: {type(exc).__name__}",
                )
        raise
