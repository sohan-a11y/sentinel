"""OWASP ZAP REST API wrapper — Tier A passive scan + Tier B active scan dispatch.

Implements the standard dispatch interface shared by every scan-engine module
(nuclei/zap/idor): `run(db, scan_session, registration, cwe_items) ->
list[RawFinding]`. Talks to ZAP only through its local REST API — never
touches the target directly itself. Alerts pulled right after the spider
phase are Tier A findings (passive scanning sends no attack payloads); alerts
re-pulled after the active scan are Tier B findings (active scan sends live
attack payloads against the target), and the active-scan phase itself is
gated by enforce_tier so it never runs outside a canary-verified session.
"""
from __future__ import annotations

import time
from typing import Any

import httpx
from sqlalchemy.orm import Session

from sentinel.agents.state import CweChecklistItem, RawFinding
from sentinel.config import settings
from sentinel.db.models import ActionTier, ScanSession, TargetRegistration
from sentinel.security import audit_log, guardrails
from sentinel.security.guardrails import TierViolationError

AGENT_NAME = "zap_wrapper"

_POLL_INTERVAL_SECONDS = 2.0
_REQUEST_TIMEOUT_SECONDS = 30.0

RISK_CONFIDENCE: dict[str, float] = {
    "informational": 0.3,
    "low": 0.5,
    "medium": 0.65,
    "high": 0.85,
}

CONFIDENCE_MULTIPLIER: dict[str, float] = {
    "low": 0.85,
    "medium": 0.95,
    "high": 1.0,
    "confirmed": 1.05,
}


def _api_params(extra: dict[str, Any]) -> dict[str, Any]:
    params = dict(extra)
    if settings.zap_api_key:
        params["apikey"] = settings.zap_api_key
    return params


def _url(path: str) -> str:
    return f"{settings.zap_api_url.rstrip('/')}{path}"


def _poll_until_complete(
    client: httpx.Client,
    db: Session,
    status_path: str,
    scan_id: str,
    timeout_seconds: float,
    scan_session: ScanSession,
) -> str:
    deadline = time.monotonic() + timeout_seconds
    status = "0"
    while True:
        guardrails.enforce_not_halted(db, scan_session)
        resp = client.get(_url(status_path), params=_api_params({"scanId": scan_id}))
        resp.raise_for_status()
        status = str(resp.json().get("status", "0"))
        if status == "100" or time.monotonic() >= deadline:
            return status
        time.sleep(_POLL_INTERVAL_SECONDS)


def _run_spider_phase(
    client: httpx.Client, db: Session, scan_session: ScanSession, target_url: str
) -> None:
    audit_log.record(db, agent=AGENT_NAME, action="zap_spider_started", payload={"target_url": target_url})
    resp = client.get(_url("/JSON/spider/action/scan/"), params=_api_params({"url": target_url}))
    resp.raise_for_status()
    scan_id = str(resp.json()["scanId"])
    final_status = _poll_until_complete(
        client, db, "/JSON/spider/status/", scan_id, settings.zap_spider_timeout_seconds, scan_session
    )
    audit_log.record(
        db,
        agent=AGENT_NAME,
        action="zap_spider_completed",
        payload={"target_url": target_url, "scan_id": scan_id, "final_status": final_status},
    )


def _run_ascan_phase(
    client: httpx.Client, db: Session, scan_session: ScanSession, target_url: str
) -> None:
    audit_log.record(db, agent=AGENT_NAME, action="zap_ascan_started", payload={"target_url": target_url})
    resp = client.get(_url("/JSON/ascan/action/scan/"), params=_api_params({"url": target_url}))
    resp.raise_for_status()
    scan_id = str(resp.json()["scanId"])
    final_status = _poll_until_complete(
        client, db, "/JSON/ascan/status/", scan_id, settings.zap_ascan_timeout_seconds, scan_session
    )
    audit_log.record(
        db,
        agent=AGENT_NAME,
        action="zap_ascan_completed",
        payload={"target_url": target_url, "scan_id": scan_id, "final_status": final_status},
    )


def _fetch_alerts(client: httpx.Client, target_url: str) -> list[dict[str, Any]]:
    resp = client.get(_url("/JSON/core/view/alerts/"), params=_api_params({"baseurl": target_url}))
    resp.raise_for_status()
    alerts = resp.json().get("alerts") or []
    return [alert for alert in alerts if isinstance(alert, dict)]


def _map_cwe(raw: Any) -> str | None:
    if raw is None:
        return None
    raw_str = str(raw).strip()
    if not raw_str or raw_str == "0":
        return None
    return f"CWE-{raw_str}"


def _confidence_for_alert(alert: dict[str, Any]) -> float:
    risk = str(alert.get("risk", "")).strip().lower()
    base = RISK_CONFIDENCE.get(risk, 0.3)
    zap_confidence = str(alert.get("confidence", "")).strip().lower()
    multiplier = CONFIDENCE_MULTIPLIER.get(zap_confidence, 1.0)
    return round(min(base * multiplier, 1.0), 3)


def _poc_evidence(alert: dict[str, Any]) -> str:
    """Human-readable summary first, then machine-parseable `key: value`
    lines — sentinel.agents.verification_agent._parse_evidence reads
    matched-at/evidence to independently re-check the finding without
    re-invoking ZAP."""
    name = alert.get("name", "ZAP Alert")
    url = alert.get("url", "")
    detail = str(alert.get("evidence") or alert.get("attack") or "")[:300]
    summary = f"{name} | {url} | {detail}"
    return f"{summary}\nmatched-at: {url}\nevidence: {detail}"


def _mark_checklist_item(cwe_items: list[CweChecklistItem], cwe_id: str) -> None:
    for item in cwe_items:
        if item.get("cwe_id") == cwe_id:
            item["tested"] = True
            item["detection_method"] = "zap"


def _convert_alerts(
    alerts: list[dict[str, Any]],
    tier: str,
    cwe_items: list[CweChecklistItem],
    db: Session,
) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for alert in alerts:
        cwe_id = _map_cwe(alert.get("cweid"))
        if cwe_id is None:
            audit_log.record(
                db,
                agent=AGENT_NAME,
                action="zap_alert_unmapped_cwe",
                payload={"name": alert.get("name"), "cweid": alert.get("cweid"), "url": alert.get("url")},
            )
            continue

        finding: RawFinding = {
            "cwe_id": cwe_id,
            "endpoint": str(alert.get("url", "")),
            "tier": tier,  # type: ignore[typeddict-item]
            "detection_method": "zap",
            "poc_evidence": _poc_evidence(alert),
            "confidence": _confidence_for_alert(alert),
        }
        findings.append(finding)
        _mark_checklist_item(cwe_items, cwe_id)
        audit_log.record(db, agent=AGENT_NAME, action="zap_finding_detected", payload=dict(finding))
    return findings


def run(
    db: Session,
    scan_session: ScanSession,
    registration: TargetRegistration,
    cwe_items: list[CweChecklistItem],
) -> list[RawFinding]:
    guardrails.enforce_not_halted(db, scan_session)
    # Phase 0 is executing here: Tier A gate — always passes, spider/passive
    # scan send no attack payloads regardless of the canary result.
    guardrails.enforce_tier(ActionTier.TIER_A, scan_session.environment_tier)

    host = guardrails.normalize_host(registration.domain)
    target_url = f"https://{host}"
    findings: list[RawFinding] = []

    try:
        with httpx.Client(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            _run_spider_phase(client, db, scan_session, target_url)

            guardrails.enforce_not_halted(db, scan_session)
            passive_alerts = _fetch_alerts(client, target_url)
            findings.extend(_convert_alerts(passive_alerts, "tier_a", cwe_items, db))

            guardrails.enforce_not_halted(db, scan_session)
            # Phase 0 is executing here: this is the check that actually
            # matters — active scan sends live attack payloads, so it only
            # proceeds if Phase 0's canary probe verified this session safe
            # (scan_session.environment_tier == VERIFIED_SAFE). Otherwise this
            # raises and we skip straight to logging it below, no active scan.
            try:
                guardrails.enforce_tier(ActionTier.TIER_B, scan_session.environment_tier)
            except TierViolationError as exc:
                audit_log.record(
                    db,
                    agent=AGENT_NAME,
                    action="zap_ascan_skipped",
                    payload={"target_url": target_url, "reason": str(exc)},
                )
            else:
                _run_ascan_phase(client, db, scan_session, target_url)
                guardrails.enforce_not_halted(db, scan_session)
                full_alerts = _fetch_alerts(client, target_url)
                findings.extend(_convert_alerts(full_alerts, "tier_b", cwe_items, db))
    except httpx.HTTPError as exc:
        audit_log.record(
            db,
            agent=AGENT_NAME,
            action="zap_unavailable",
            payload={"target_url": target_url, "error": str(exc)},
        )
        return findings

    return findings
