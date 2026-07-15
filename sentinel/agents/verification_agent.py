"""Agent 4 — Verification Agent.

Every RawFinding from Agent 3 (dispatch) is re-checked by a method that is
genuinely independent of however it was first detected, before it is allowed
to become "confirmed". A finding that cannot be independently reproduced is
marked "unconfirmed" and kept — never dropped — so a human can review it.
"""
from __future__ import annotations

import json
from typing import Callable

import httpx
from sqlalchemy.orm import Session

from sentinel.agents.state import RawFinding, SentinelState, VerifiedFinding
from sentinel.config import settings
from sentinel.db.models import ActionTier, EnvironmentTier, FindingStatus, ScanSession, TargetRegistration
from sentinel.db.session import get_session
from sentinel.security import audit_log, guardrails

AGENT_NAME = "verification_agent"

# Heuristic CWE classification used only to pick which independent signal to
# re-check. Anything not in these sets falls through to the weak reachability
# fallback rather than guessing at a check that might not apply.
XSS_CWE_IDS = {"CWE-79"}
HEADER_CWE_IDS = {"CWE-16", "CWE-693", "CWE-1021", "CWE-614"}

# idor_agent's own detector is shape/status based (no single reproducible
# marker string), so when poc_evidence has no unauthorized-marker line, the
# custom-tier re-check falls back to asking the same question idor_agent
# asked: does the manipulated response still look like real, non-error data?
_ERROR_INDICATOR_KEYS = {"error", "errors", "message", "detail", "denied", "unauthorized", "forbidden"}


def _looks_like_substantive_response(status_code: int, body: str) -> bool:
    if status_code != 200:
        return False
    stripped = body.strip()
    if not stripped:
        return False
    try:
        parsed = json.loads(stripped)
    except ValueError:
        return True
    if isinstance(parsed, dict):
        keys_lower = {str(k).lower() for k in parsed.keys()}
        if keys_lower & _ERROR_INDICATOR_KEYS and len(parsed) <= 3:
            return False
    return True

Verifier = Callable[[RawFinding, TargetRegistration, EnvironmentTier], tuple[str, str, str]]


def _parse_evidence(poc_evidence: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in poc_evidence.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key and key not in parsed:
            parsed[key] = value.strip()
    return parsed


def _maybe_enforce_tier(finding: RawFinding, environment_tier: EnvironmentTier) -> None:
    if finding.get("tier") == "tier_b":
        guardrails.enforce_tier(ActionTier.TIER_B, environment_tier)


def _verify_nuclei(
    finding: RawFinding, registration: TargetRegistration, environment_tier: EnvironmentTier
) -> tuple[str, str, str]:
    evidence = _parse_evidence(finding.get("poc_evidence", ""))
    url = evidence.get("matched-at") or finding.get("endpoint", "")
    if not url:
        return "unconfirmed", "nuclei_replay", "no matched-at URL in poc_evidence to replay"

    _maybe_enforce_tier(finding, environment_tier)
    guardrails.enforce_no_pivot(registration, url)
    response = httpx.get(url, timeout=settings.verification_http_timeout_seconds)

    cwe_id = finding.get("cwe_id", "")
    if cwe_id in XSS_CWE_IDS and evidence.get("pattern"):
        marker = evidence["pattern"]
        if marker in response.text:
            return "confirmed", "nuclei_xss_pattern_replay", f"marker '{marker}' still reflected unescaped in fresh response"
        return "unconfirmed", "nuclei_xss_pattern_replay", f"marker '{marker}' no longer present in fresh response"

    if cwe_id in HEADER_CWE_IDS and evidence.get("header"):
        header_name = evidence["header"]
        condition = evidence.get("condition", "present")
        header_value = response.headers.get(header_name)
        if condition == "missing":
            if header_value is None:
                return "confirmed", "nuclei_header_recheck", f"header '{header_name}' still absent"
            return "unconfirmed", "nuclei_header_recheck", f"header '{header_name}' now present ('{header_value}')"
        expected_value = evidence.get("value")
        if header_value is not None and (not expected_value or expected_value in header_value):
            return "confirmed", "nuclei_header_recheck", f"header '{header_name}' still present as expected"
        return "unconfirmed", "nuclei_header_recheck", f"header '{header_name}' missing or value changed"

    if 200 <= response.status_code < 400:
        return "unconfirmed", "nuclei_reachability_fallback", (
            f"no independent check coded for {cwe_id or 'this CWE'}; endpoint still reachable "
            f"(status {response.status_code}) but signal itself was not independently re-verified"
        )
    return "unconfirmed", "nuclei_reachability_fallback", f"endpoint unreachable on replay (status {response.status_code})"


def _verify_zap(
    finding: RawFinding, registration: TargetRegistration, environment_tier: EnvironmentTier
) -> tuple[str, str, str]:
    evidence = _parse_evidence(finding.get("poc_evidence", ""))
    url = evidence.get("matched-at") or finding.get("endpoint", "")
    if not url:
        return "unconfirmed", "zap_replay", "no matched-at URL in poc_evidence to replay"

    _maybe_enforce_tier(finding, environment_tier)
    guardrails.enforce_no_pivot(registration, url)
    response = httpx.get(url, timeout=settings.verification_http_timeout_seconds)

    flagged = evidence.get("evidence")
    if flagged:
        header_blob = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        if flagged in response.text or flagged in header_blob:
            return "confirmed", "zap_evidence_replay", f"ZAP evidence '{flagged}' still present in fresh response"
        return "unconfirmed", "zap_evidence_replay", f"ZAP evidence '{flagged}' no longer present in fresh response"

    if 200 <= response.status_code < 400:
        return "unconfirmed", "zap_reachability_fallback", (
            f"no evidence substring recorded for this alert; endpoint still reachable "
            f"(status {response.status_code}) but signal itself was not independently re-verified"
        )
    return "unconfirmed", "zap_reachability_fallback", f"endpoint unreachable on replay (status {response.status_code})"


def _verify_custom(
    finding: RawFinding, registration: TargetRegistration, environment_tier: EnvironmentTier
) -> tuple[str, str, str]:
    evidence = _parse_evidence(finding.get("poc_evidence", ""))
    manipulated_url = evidence.get("manipulated-url") or finding.get("endpoint", "")
    baseline_url = evidence.get("baseline-url")
    marker = evidence.get("unauthorized-marker")
    if not manipulated_url:
        return "unconfirmed", "idor_reprobe", "poc_evidence missing manipulated-url/endpoint; cannot re-probe"

    _maybe_enforce_tier(finding, environment_tier)
    guardrails.enforce_no_pivot(registration, manipulated_url)

    baseline_response = None
    if baseline_url:
        guardrails.enforce_no_pivot(registration, baseline_url)
        baseline_response = httpx.get(baseline_url, timeout=settings.verification_http_timeout_seconds)

    manipulated_response = httpx.get(manipulated_url, timeout=settings.verification_http_timeout_seconds)
    baseline_ok = baseline_response is None or (200 <= baseline_response.status_code < 300)

    if marker:
        manipulated_leaks = 200 <= manipulated_response.status_code < 300 and marker in manipulated_response.text
        subject = f"unauthorized marker '{marker}'"
    else:
        # idor_agent's own detector is shape/status based, not marker based —
        # re-apply the same question on a fresh reprobe rather than refusing
        # to verify just because there's no substring to search for.
        manipulated_leaks = _looks_like_substantive_response(manipulated_response.status_code, manipulated_response.text)
        subject = "a substantive (non-error-shaped) response"

    if baseline_ok and manipulated_leaks:
        return "confirmed", "idor_reprobe", f"fresh re-probe still returns {subject} for the manipulated request"
    return "unconfirmed", "idor_reprobe", (
        f"fresh re-probe did not reproduce the IDOR (manipulated status {manipulated_response.status_code}) — "
        "treating as race/flake, needs review"
    )


def _verify_unknown(
    finding: RawFinding, registration: TargetRegistration, environment_tier: EnvironmentTier
) -> tuple[str, str, str]:
    method = finding.get("detection_method", "unknown")
    return "unconfirmed", "unknown_method_fallback", (
        f"no independent verifier registered for detection_method '{method}'; cannot confirm — flagged for manual review"
    )


_VERIFIER_STRATEGIES: dict[str, Verifier] = {
    "nuclei": _verify_nuclei,
    "zap": _verify_zap,
    "custom": _verify_custom,
}


def verify_findings(db: Session, scan_session: ScanSession, raw_findings: list[RawFinding]) -> list[VerifiedFinding]:
    guardrails.enforce_not_halted(db, scan_session)
    registration = scan_session.target
    environment_tier = scan_session.environment_tier

    verified: list[VerifiedFinding] = []
    for raw in raw_findings:
        guardrails.enforce_not_halted(db, scan_session)
        detection_method = raw.get("detection_method", "")
        verifier = _VERIFIER_STRATEGIES.get(detection_method, _verify_unknown)

        try:
            status, method, note = verifier(raw, registration, environment_tier)
        except httpx.HTTPError as exc:
            status, method, note = (
                "unconfirmed",
                f"{detection_method or 'unknown'}_network_error",
                f"re-verification request raised {type(exc).__name__}: {exc}",
            )

        confidence = raw.get("confidence", 0.5)
        if method.endswith("_reachability_fallback"):
            confidence = min(confidence, 0.3)

        verified_finding: VerifiedFinding = {
            **raw,
            "status": status,
            "verification_method": method,
            "verification_note": note,
            "confidence": confidence,
        }
        verified.append(verified_finding)

        audit_log.record(
            db,
            agent=AGENT_NAME,
            action="finding_reverified",
            payload={
                "scan_session_id": scan_session.id,
                "cwe_id": raw.get("cwe_id"),
                "endpoint": raw.get("endpoint"),
                "detection_method": detection_method,
                "before_status": FindingStatus.PENDING_VERIFICATION.value,
                "after_status": status,
                "verification_method": method,
                "verification_note": note,
            },
        )

    return verified


def verification_node(state: SentinelState) -> dict:
    raw_findings = state.get("raw_findings", [])
    scan_session_id = state["scan_session_id"]

    with get_session() as db:
        scan_session = db.get(ScanSession, scan_session_id)
        if scan_session is None:
            raise ValueError(f"ScanSession {scan_session_id} not found")
        verified = verify_findings(db, scan_session, raw_findings)

    return {"verified_findings": verified, "current_phase": "verification_complete"}
