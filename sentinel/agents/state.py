"""The shared state threaded through every LangGraph node.

This is the ONE contract all six agents agree on. Every node function has the
signature `def node(state: SentinelState) -> dict` (a partial update, per
LangGraph convention) and reads/writes only these keys. Keeping this file
stable is what let recon/cwe-mapping/dispatch/verification/report/killswitch
get built independently against a fixed shape.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal, TypedDict

CweId = str


class EndpointInfo(TypedDict, total=False):
    url: str
    methods: list[str]
    params: list[str]
    forms: list[dict[str, Any]]
    requires_auth: bool
    source: str  # how recon found it: "crawl" | "sitemap" | "js_bundle"


class SiteMap(TypedDict, total=False):
    domain: str
    endpoints: list[EndpointInfo]
    cookies: list[dict[str, Any]]
    response_headers: dict[str, str]
    tech_stack: list[str]
    forms_count: int
    crawled_at: str


class CweChecklistItem(TypedDict, total=False):
    cwe_id: CweId
    name: str
    category: str
    applicable: bool
    reason: str
    tested: bool
    detection_method: str | None  # "nuclei" | "zap" | "custom" | None


class RawFinding(TypedDict, total=False):
    cwe_id: CweId
    endpoint: str
    tier: Literal["tier_a", "tier_b"]
    detection_method: Literal["nuclei", "zap", "custom"]
    poc_evidence: str
    confidence: float


class VerifiedFinding(RawFinding, total=False):
    status: Literal["confirmed", "unconfirmed"]
    verification_method: str
    verification_note: str


def _last_write_wins(_left: Any, right: Any) -> Any:
    return right


def _append(left: list, right: list) -> list:
    return [*left, *right]


class SentinelState(TypedDict, total=False):
    # Identity / gating — set once at graph entry, read by every node
    scan_session_id: int
    target_domain: str
    environment_tier: Literal["verified_safe", "unverified"]

    # Agent 1 output
    site_map: SiteMap

    # Agent 2 output
    cwe_checklist: list[CweChecklistItem]
    applicable_count: int
    not_applicable_count: int

    # Agent 3 output
    raw_findings: Annotated[list[RawFinding], _append]

    # Agent 4 output
    verified_findings: Annotated[list[VerifiedFinding], _append]

    # Agent 6 — checked by every node before doing real work
    halted: Annotated[bool, _last_write_wins]
    halt_reason: Annotated[str | None, _last_write_wins]

    # Cross-cutting
    errors: Annotated[list[str], _append]
    current_phase: Annotated[str, _last_write_wins]
