"""Nuclei CLI wrapper — Tier A (read-only detection) scan engine.

Implements the standard dispatch interface shared by every scan-engine
module (nuclei/zap/idor): `run(db, scan_session, registration, cwe_items) ->
list[RawFinding]`. Never talks to the target except through the nuclei
binary invoked here, and never invokes it without the guardrail checks
running first.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

from sqlalchemy.orm import Session

from sentinel.agents.state import CweChecklistItem, RawFinding
from sentinel.config import settings
from sentinel.db.models import ActionTier, ScanSession, TargetRegistration
from sentinel.security import audit_log, guardrails

EXCLUDED_TAGS = "dos,fuzz"

SEVERITY_CONFIDENCE: dict[str, float] = {
    "info": 0.3,
    "low": 0.5,
    "medium": 0.65,
    "high": 0.8,
    "critical": 0.9,
}


def _build_command(host: str) -> list[str]:
    command = [
        settings.nuclei_binary_path,
        "-u",
        f"https://{host}",
        "-jsonl",
        "-silent",
        "-etags",
        EXCLUDED_TAGS,
    ]
    if settings.nuclei_templates_path:
        command.extend(["-t", settings.nuclei_templates_path])
    return command


def _extract_cwe_id(result: dict[str, Any]) -> str | None:
    info = result.get("info") or {}
    classification = info.get("classification") or {}
    cwe_ids = classification.get("cwe-id") or []
    if not cwe_ids:
        return None
    first = cwe_ids[0]
    return str(first).upper()


def _confidence_for_severity(severity: str | None) -> float:
    return SEVERITY_CONFIDENCE.get((severity or "").lower(), 0.3)


def _build_poc_evidence(result: dict[str, Any]) -> str:
    """Human-readable summary first, then machine-parseable `key: value` lines
    (matched-at, and pattern when nuclei's extractor caught a reflected
    value) — sentinel.agents.verification_agent._parse_evidence reads these
    lines to independently re-check the finding without re-invoking nuclei."""
    template_id = result.get("template-id", "unknown-template")
    matched_at = result.get("matched-at", "")
    context = ""
    extracted = result.get("extracted-results")
    pattern_line = ""
    if extracted:
        first_extracted = extracted[0] if isinstance(extracted, list) else extracted
        context = f"extracted={first_extracted}"
        pattern_line = f"\npattern: {first_extracted}"
    elif result.get("matcher-name"):
        context = f"matcher={result['matcher-name']}"
    parts = [str(part) for part in (template_id, matched_at, context) if part]
    summary = " | ".join(parts)
    matched_at_line = f"\nmatched-at: {matched_at}" if matched_at else ""
    return f"{summary}{matched_at_line}{pattern_line}"


def _mark_checklist_item(cwe_items: list[CweChecklistItem], cwe_id: str) -> None:
    for item in cwe_items:
        if item.get("cwe_id") == cwe_id:
            item["tested"] = True
            item["detection_method"] = "nuclei"


def _build_raw_finding(result: dict[str, Any], host: str, cwe_id: str) -> RawFinding:
    severity = (result.get("info") or {}).get("severity")
    return RawFinding(
        cwe_id=cwe_id,
        endpoint=result.get("matched-at") or f"https://{host}",
        tier="tier_a",
        detection_method="nuclei",
        poc_evidence=_build_poc_evidence(result),
        confidence=_confidence_for_severity(severity),
    )


def run(
    db: Session,
    scan_session: ScanSession,
    registration: TargetRegistration,
    cwe_items: list[CweChecklistItem],
) -> list[RawFinding]:
    guardrails.enforce_not_halted(db, scan_session)
    # Phase 0 is executing here: enforce_tier checks scan_session.environment_tier,
    # which is exactly what Phase 0's canary probe decided for this session
    # (nuclei only ever runs Tier A, so this always passes — kept for consistency
    # with every other engine, which all check tier before doing anything).
    guardrails.enforce_tier(ActionTier.TIER_A, scan_session.environment_tier)

    host = guardrails.normalize_host(registration.domain)
    command = _build_command(host)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=settings.nuclei_timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        audit_log.record(
            db,
            agent="nuclei_wrapper",
            action="nuclei_unavailable",
            payload={"reason": "binary_not_found", "error": str(exc), "command": command},
        )
        return []
    except subprocess.TimeoutExpired as exc:
        audit_log.record(
            db,
            agent="nuclei_wrapper",
            action="nuclei_unavailable",
            payload={"reason": "timeout", "error": str(exc), "command": command},
        )
        return []

    findings: list[RawFinding] = []

    for line in completed.stdout.splitlines():
        guardrails.enforce_not_halted(db, scan_session)

        stripped = line.strip()
        if not stripped:
            continue

        try:
            result = json.loads(stripped)
        except json.JSONDecodeError as exc:
            audit_log.record(
                db,
                agent="nuclei_wrapper",
                action="nuclei_output_unparseable",
                payload={"line": stripped, "error": str(exc)},
            )
            continue

        template_id = result.get("template-id", "unknown-template")
        cwe_id = _extract_cwe_id(result)

        if cwe_id is None:
            audit_log.record(
                db,
                agent="nuclei_wrapper",
                action="nuclei_finding_unmapped",
                payload={"template_id": template_id, "matched_at": result.get("matched-at")},
            )
            continue

        finding = _build_raw_finding(result, host, cwe_id)
        findings.append(finding)
        _mark_checklist_item(cwe_items, cwe_id)
        audit_log.record(
            db,
            agent="nuclei_wrapper",
            action="finding_detected",
            payload=dict(finding),
        )

    return findings
