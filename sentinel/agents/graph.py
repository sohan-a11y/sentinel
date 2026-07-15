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


def run_scan_pipeline(scan_session_id: int, target_domain: str, environment_tier: str) -> SentinelState:
    """Synchronous entry point — invoked by the API after Phase 0's
    start_scan_session() has already authorized and tiered this session."""
    initial_state: SentinelState = {
        "scan_session_id": scan_session_id,
        "target_domain": target_domain,
        "environment_tier": environment_tier,
        "halted": False,
        "halt_reason": None,
        "errors": [],
        "current_phase": "starting",
    }
    graph = get_compiled_graph()
    return graph.invoke(initial_state)
