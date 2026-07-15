"""Agent 3 (custom tier): LLM-driven IDOR (CWE-639) business-logic agent.

SIMPLIFICATION NOTE (read before extending): a real IDOR test needs two
distinct, seeded low-privilege accounts — request a resource as user A, then
request the same resource as user B, and confirm B is refused. This build has
no multi-user session/login infrastructure (no way to authenticate as two
different real accounts against an arbitrary target), so it approximates the
check with a single-session baseline-vs-manipulated diff instead:

    (i)   GET the endpoint exactly as recon found it (baseline — "your own"
          resource, using whatever session cookies recon captured).
    (ii)  GET the same endpoint with the id-like parameter substituted for a
          sibling value the LLM chose (or with the session/auth cookie
          stripped entirely, per the LLM's chosen strategy).
    (iii) If (ii) comes back 200 with a real, non-error-shaped body, that is
          strong evidence of *no authorization check at all* — the majority
          real-world IDOR pattern. This deliberately under-detects the
          "checks auth but checks it wrong for a second real account" case,
          since that requires the two-account infrastructure described above.
          A future iteration can seed two low-privilege accounts via
          TargetRegistration metadata and do a real cross-account comparison.

Candidate identification and the specific manipulation strategy per endpoint
(increment/decrement a numeric id, swap to a sibling UUID, strip the auth
cookie, etc.) are generated dynamically by the LLM reasoning about THIS
site's specific endpoints — not a fixed template tried identically against
every endpoint.
"""
from __future__ import annotations

import json
import secrets
import uuid
from typing import Any

import httpx
from sqlalchemy.orm import Session

from sentinel.agents.state import CweChecklistItem, EndpointInfo, RawFinding, SiteMap
from sentinel.config import settings
from sentinel.db.models import ActionTier, ScanSession, TargetRegistration
from sentinel.llm.client import get_llm_client
from sentinel.security import audit_log, guardrails, safe_http
from sentinel.security.guardrails import (
    DemonstrationBudgetExceededError,
    PivotViolationError,
    TierViolationError,
)

AGENT_NAME = "idor_agent"

# Bounds cost/time of the exploitative phase regardless of how many
# candidates the LLM ranks — this is a hard local cap, not LLM-adjustable.
MAX_IDOR_CANDIDATES = 10

_ID_LIKE_EXACT = {"id", "uuid", "guid"}
_ID_LIKE_SUFFIXES = ("_id", "_uuid", "_guid")

_ERROR_INDICATOR_KEYS = {"error", "errors", "message", "detail", "denied", "unauthorized", "forbidden"}

_CANDIDATE_REQUIRED_STRING_FIELDS = (
    "endpoint",
    "id_param",
    "manipulated_endpoint",
    "manipulation_strategy",
    "reasoning",
)

_SIGNUP_URL_TOKENS = ("signup", "register", "/users", "/accounts")

_DEMO_ACCOUNT_PLACEHOLDER = "{demo_account_id}"


def run(
    db: Session,
    scan_session: ScanSession,
    registration: TargetRegistration,
    cwe_items: list[CweChecklistItem],
    site_map: SiteMap | None = None,
) -> list[RawFinding]:
    if site_map is None:
        return []

    cwe_item = _find_applicable_cwe639(cwe_items)
    if cwe_item is None:
        return []

    guardrails.enforce_not_halted(db, scan_session)

    findings: list[RawFinding] = []

    candidate_endpoints = _filter_id_like_endpoints(site_map.get("endpoints") or [])
    if not candidate_endpoints:
        audit_log.record(
            db,
            agent=AGENT_NAME,
            action="idor_no_candidate_endpoints",
            payload={"domain": site_map.get("domain")},
        )
        cwe_item["tested"] = True
        cwe_item["detection_method"] = "custom"
        return findings

    try:
        llm_candidates = _get_llm_candidates(candidate_endpoints, site_map)
    except Exception as exc:  # LLM backend/schema failures are external input, never trusted
        audit_log.record(
            db,
            agent=AGENT_NAME,
            action="idor_llm_error",
            payload={"error": str(exc)},
        )
        cwe_item["tested"] = True
        cwe_item["detection_method"] = "custom"
        return findings

    llm_candidates = llm_candidates[:MAX_IDOR_CANDIDATES]
    audit_log.record(
        db,
        agent=AGENT_NAME,
        action="idor_candidates_identified",
        payload={"count": len(llm_candidates), "candidates": llm_candidates},
    )

    # Phase 0 is executing here: this whole agent is Tier B (it creates a real
    # account and sends exploitative requests), so it is entirely gated on
    # Phase 0's canary result — checked ONCE for the whole candidate loop
    # below, not per-candidate, so a failed canary blocks every probe at once.
    tier_b_allowed = True
    try:
        guardrails.enforce_tier(ActionTier.TIER_B, scan_session.environment_tier)
    except TierViolationError as exc:
        tier_b_allowed = False
        audit_log.record(
            db,
            agent=AGENT_NAME,
            action="idor_tier_b_skipped",
            payload={"reason": str(exc), "candidate_count": len(llm_candidates)},
        )

    if tier_b_allowed:
        demo_account_id: str | None = None
        demo_account_attempted = False
        for candidate in llm_candidates:
            guardrails.enforce_not_halted(db, scan_session)

            if candidate.get("requires_account_creation") and not demo_account_attempted:
                demo_account_attempted = True
                try:
                    demo_account_id = _create_demo_account(db, registration, site_map)
                    audit_log.record(
                        db,
                        agent=AGENT_NAME,
                        action="idor_demo_account_created",
                        payload={"created": demo_account_id is not None},
                    )
                except DemonstrationBudgetExceededError as exc:
                    demo_account_id = None
                    audit_log.record(
                        db,
                        agent=AGENT_NAME,
                        action="idor_demo_account_blocked",
                        payload={"error": str(exc)},
                    )

            finding = _probe_candidate(db, registration, candidate, site_map, demo_account_id)
            if finding is not None:
                findings.append(finding)

    cwe_item["tested"] = True
    cwe_item["detection_method"] = "custom"
    return findings


def _find_applicable_cwe639(cwe_items: list[CweChecklistItem]) -> CweChecklistItem | None:
    for item in cwe_items:
        if item.get("cwe_id") == "CWE-639" and item.get("applicable"):
            return item
    return None


def _is_id_like_param(name: str) -> bool:
    lowered = name.strip().lower()
    if not lowered:
        return False
    if lowered in _ID_LIKE_EXACT:
        return True
    return any(lowered.endswith(suffix) for suffix in _ID_LIKE_SUFFIXES)


def _extract_field_names(endpoint: EndpointInfo) -> list[str]:
    names: list[str] = [str(p) for p in (endpoint.get("params") or [])]
    for form in endpoint.get("forms") or []:
        if not isinstance(form, dict):
            continue
        fields = form.get("fields") or form.get("inputs") or []
        for field in fields:
            if isinstance(field, str):
                names.append(field)
            elif isinstance(field, dict):
                field_name = field.get("name") or field.get("field")
                if field_name:
                    names.append(str(field_name))
        direct_name = form.get("name")
        if isinstance(direct_name, str):
            names.append(direct_name)
    return names


def _filter_id_like_endpoints(endpoints: list[EndpointInfo]) -> list[EndpointInfo]:
    filtered: list[EndpointInfo] = []
    for endpoint in endpoints:
        if not endpoint.get("requires_auth"):
            continue
        field_names = _extract_field_names(endpoint)
        if any(_is_id_like_param(name) for name in field_names):
            filtered.append(endpoint)
    return filtered


def _is_valid_candidate(candidate: Any) -> bool:
    if not isinstance(candidate, dict):
        return False
    return all(isinstance(candidate.get(field), str) and candidate.get(field) for field in _CANDIDATE_REQUIRED_STRING_FIELDS)


def _get_llm_candidates(candidate_endpoints: list[EndpointInfo], site_map: SiteMap) -> list[dict[str, Any]]:
    client = get_llm_client()
    system = (
        "You are an application security analyst specializing in CWE-639 "
        "(Insecure Direct Object Reference / broken object-level authorization). "
        "You are given a list of authenticated endpoints for a single web application, "
        "each with its HTTP methods, parameter/form field names, and whether it requires "
        "authentication. For each endpoint that plausibly exposes an object by an "
        "identifier (numeric id, uuid, user_id, account_id, order_id, invoice_id, etc.), "
        "design ONE concrete IDOR test: pick the specific id-like field to manipulate and "
        "the exact manipulated URL to request. Vary the manipulation strategy per endpoint "
        "based on what the identifier looks like — increment/decrement a numeric id, swap "
        "to a plausible sibling UUID, or strip the session/authorization cookie entirely "
        "(manipulation_strategy='strip_auth_header', reusing the same URL as "
        "manipulated_endpoint). If a valid manipulated id cannot be constructed without a "
        "second real account, set requires_account_creation=true and put the literal "
        "placeholder token '{demo_account_id}' where that id belongs in "
        "manipulated_endpoint. Rank candidates most-likely-vulnerable first."
    )
    user = json.dumps(
        {
            "domain": site_map.get("domain"),
            "endpoints": [
                {
                    "url": endpoint.get("url"),
                    "methods": endpoint.get("methods"),
                    "params": endpoint.get("params"),
                    "forms": endpoint.get("forms"),
                    "requires_auth": endpoint.get("requires_auth"),
                }
                for endpoint in candidate_endpoints
            ],
        },
        default=str,
    )
    schema = {
        "type": "object",
        "properties": {
            "candidates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "endpoint": {"type": "string"},
                        "id_param": {"type": "string"},
                        "manipulated_endpoint": {"type": "string"},
                        "manipulation_strategy": {"type": "string"},
                        "requires_account_creation": {"type": "boolean"},
                        "reasoning": {"type": "string"},
                    },
                    "required": [
                        "endpoint",
                        "id_param",
                        "manipulated_endpoint",
                        "manipulation_strategy",
                        "reasoning",
                    ],
                },
            }
        },
        "required": ["candidates"],
    }
    result = client.complete_json(system=system, user=user, json_schema=schema, schema_name="idor_candidates")
    candidates = result.get("candidates") or []
    return [candidate for candidate in candidates if _is_valid_candidate(candidate)]


def _find_signup_endpoint(site_map: SiteMap) -> EndpointInfo | None:
    for endpoint in site_map.get("endpoints") or []:
        url = str(endpoint.get("url") or "").lower()
        methods = [str(m).upper() for m in (endpoint.get("methods") or [])]
        if "POST" in methods and any(token in url for token in _SIGNUP_URL_TOKENS):
            return endpoint
    return None


def _create_demo_account(db: Session, registration: TargetRegistration, site_map: SiteMap) -> str | None:
    """Creates exactly one throwaway account for candidates whose manipulation
    strategy needs a real sibling identity. The budget check runs BEFORE any
    network call so it truly blocks the request rather than logging after the
    fact."""
    guardrails.enforce_demonstration_budget(db, registration, "account_creation", 1)

    signup_endpoint = _find_signup_endpoint(site_map)
    if signup_endpoint is None:
        return None

    signup_url = str(signup_endpoint["url"])
    guardrails.enforce_no_pivot(registration, signup_url)

    throwaway_email = f"sentinel-idor-{uuid.uuid4().hex[:12]}@example.com"
    throwaway_password = secrets.token_urlsafe(16)

    try:
        response = safe_http.post_same_host(
            signup_url,
            registration.domain,
            json={"email": throwaway_email, "password": throwaway_password},
            timeout=settings.verification_http_timeout_seconds,
        )
    except (httpx.HTTPError, PivotViolationError):
        return None

    if response.status_code >= 400:
        return None

    # The account now really exists on the target — persist the lifetime
    # counter regardless of whether we can parse its id back below, so a
    # second scan session can't get a fresh budget just by starting over.
    guardrails.record_demonstration_action(db, registration, "account_creation", 1)

    try:
        parsed = response.json()
    except ValueError:
        return None

    if not isinstance(parsed, dict):
        return None

    for key in ("id", "user_id", "uuid", "account_id"):
        if key in parsed:
            return str(parsed[key])
    return None


def _request_kwargs(site_map: SiteMap, *, strip_auth: bool) -> dict[str, Any]:
    cookies: dict[str, str] = {}
    if not strip_auth:
        for cookie in site_map.get("cookies") or []:
            if not isinstance(cookie, dict):
                continue
            name = cookie.get("name")
            value = cookie.get("value")
            if name and value is not None:
                cookies[str(name)] = str(value)
    return {
        "cookies": cookies,
        "timeout": settings.verification_http_timeout_seconds,
    }


def _looks_like_error_or_empty(status_code: int, body: str) -> bool:
    if status_code in (401, 403, 404):
        return True
    stripped = body.strip()
    if not stripped:
        return True
    try:
        parsed = json.loads(stripped)
    except ValueError:
        return False
    if isinstance(parsed, dict):
        keys_lower = {str(k).lower() for k in parsed.keys()}
        if keys_lower & _ERROR_INDICATOR_KEYS and len(parsed) <= 3:
            return True
    return False


def _probe_candidate(
    db: Session,
    registration: TargetRegistration,
    candidate: dict[str, Any],
    site_map: SiteMap,
    demo_account_id: str | None,
) -> RawFinding | None:
    endpoint = candidate.get("endpoint", "")
    manipulated_endpoint = candidate.get("manipulated_endpoint", "")
    id_param = candidate.get("id_param", "")
    strategy = candidate.get("manipulation_strategy", "unspecified")
    reasoning = candidate.get("reasoning", "")
    requires_account = bool(candidate.get("requires_account_creation"))

    if not endpoint or not manipulated_endpoint:
        audit_log.record(db, agent=AGENT_NAME, action="idor_candidate_invalid", payload={"candidate": candidate})
        return None

    if requires_account:
        if demo_account_id is None:
            audit_log.record(
                db,
                agent=AGENT_NAME,
                action="idor_probe_skipped_no_demo_account",
                payload={"endpoint": endpoint, "manipulated_endpoint": manipulated_endpoint},
            )
            return None
        manipulated_endpoint = manipulated_endpoint.replace(_DEMO_ACCOUNT_PLACEHOLDER, demo_account_id)

    try:
        guardrails.enforce_no_pivot(registration, endpoint)
        guardrails.enforce_no_pivot(registration, manipulated_endpoint)
    except PivotViolationError as exc:
        audit_log.record(
            db,
            agent=AGENT_NAME,
            action="idor_pivot_blocked",
            payload={"endpoint": endpoint, "manipulated_endpoint": manipulated_endpoint, "error": str(exc)},
        )
        return None

    strip_auth = strategy == "strip_auth_header"
    baseline_kwargs = _request_kwargs(site_map, strip_auth=False)
    manipulated_kwargs = _request_kwargs(site_map, strip_auth=strip_auth)

    try:
        # safe_http, not httpx directly: these requests carry the real
        # session cookie (see _request_kwargs) — a redirect followed
        # transparently to an off-target host would resend it there, since
        # httpx's dict-style cookies kwarg has no domain restriction.
        baseline_resp = safe_http.get_same_host(endpoint, registration.domain, **baseline_kwargs)
        manipulated_resp = safe_http.get_same_host(manipulated_endpoint, registration.domain, **manipulated_kwargs)
    except (httpx.HTTPError, PivotViolationError) as exc:
        audit_log.record(
            db,
            agent=AGENT_NAME,
            action="idor_probe_error",
            payload={"endpoint": endpoint, "manipulated_endpoint": manipulated_endpoint, "error": str(exc)},
        )
        return None

    manipulated_is_error = _looks_like_error_or_empty(manipulated_resp.status_code, manipulated_resp.text)
    baseline_is_error = _looks_like_error_or_empty(baseline_resp.status_code, baseline_resp.text)
    confirmed = manipulated_resp.status_code == 200 and not manipulated_is_error

    audit_log.record(
        db,
        agent=AGENT_NAME,
        action="idor_probe_attempted",
        payload={
            "endpoint": endpoint,
            "manipulated_endpoint": manipulated_endpoint,
            "id_param": id_param,
            "strategy": strategy,
            "baseline_status": baseline_resp.status_code,
            "manipulated_status": manipulated_resp.status_code,
            "confirmed": confirmed,
        },
    )

    if not confirmed:
        return None

    confidence = 0.9 if not baseline_is_error else 0.6
    # Human-readable summary first, then machine-parseable `key: value` lines —
    # sentinel.agents.verification_agent._verify_custom re-probes baseline-url
    # and manipulated-url directly rather than re-deriving them from prose.
    # No "unauthorized-marker" line: this detector's signal is response
    # shape/status, not a single reproducible substring, so verification
    # falls back to re-applying the same shape heuristic on a fresh reprobe.
    poc_evidence = (
        f"Baseline GET {endpoint} -> {baseline_resp.status_code} ({len(baseline_resp.content)} bytes). "
        f"Manipulated GET {manipulated_endpoint} (id_param={id_param!r}, strategy={strategy}) -> "
        f"{manipulated_resp.status_code} ({len(manipulated_resp.content)} bytes). "
        f"Manipulated body sample: {manipulated_resp.text[:300]!r}. LLM reasoning: {reasoning}\n"
        f"baseline-url: {endpoint}\nmanipulated-url: {manipulated_endpoint}"
    )

    finding: RawFinding = {
        "cwe_id": "CWE-639",
        "endpoint": manipulated_endpoint,
        "tier": "tier_b",
        "detection_method": "custom",
        "poc_evidence": poc_evidence,
        "confidence": confidence,
    }
    return finding
