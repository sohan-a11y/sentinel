"""Agent 2 — CWE Mapping Agent.

Reads the site map produced by recon (Agent 1) and, for every CWE in the
curated catalog (sentinel/cwe/data/cwe_web_relevant.json), decides whether it
is plausibly applicable to this target. A deterministic rule pass handles
whatever a concrete site-map signal can decide (forms, endpoint parameters,
cookies, response headers, fingerprinted tech stack). Whatever the rules
cannot confidently decide is batched to the LLM (~20 CWEs per call) for a
judgment call — mostly business-logic and nuanced access-control/API
categories that need reasoning a fixed rule can't express.

This node never sends a byte to the target itself — it only reasons over
already-collected recon data and, optionally, calls the LLM API — so no
guardrails.enforce_* call applies here (that boundary is for anything that
touches the target network).
"""
from __future__ import annotations

import json
from typing import Callable

from sentinel.agents.state import CweChecklistItem, SentinelState, SiteMap
from sentinel.cwe.mapping import load_cwe_catalog
from sentinel.db.models import CweApplicability, ScanSession
from sentinel.db.session import get_session
from sentinel.llm.client import LlmClient, LlmConfigurationError, get_llm_client
from sentinel.security import audit_log

AGENT_NAME = "cwe_mapping_agent"

LLM_BATCH_SIZE = 20
LLM_UNAVAILABLE_REASON = "LLM unavailable — defaulting to applicable, needs manual triage"

Verdict = tuple[bool, str]
RuleFn = Callable[[SiteMap], "Verdict | None"]


# --------------------------------------------------------------------------
# Site-map signal helpers
# --------------------------------------------------------------------------


def _endpoints(site_map: SiteMap) -> list[dict]:
    return list(site_map.get("endpoints") or [])


def _has_endpoints(site_map: SiteMap) -> bool:
    return bool(_endpoints(site_map))


def _has_input_surface(site_map: SiteMap) -> bool:
    if site_map.get("forms_count", 0):
        return True
    for endpoint in _endpoints(site_map):
        if endpoint.get("params") or endpoint.get("forms"):
            return True
    return False


def _has_file_upload_form(site_map: SiteMap) -> bool:
    for endpoint in _endpoints(site_map):
        for form in endpoint.get("forms", []) or []:
            if not isinstance(form, dict):
                continue
            enctype = str(form.get("enctype", "")).lower()
            if "multipart" in enctype:
                return True
            fields = form.get("fields") or form.get("inputs") or []
            for field in fields:
                if isinstance(field, dict) and str(field.get("type", "")).lower() == "file":
                    return True
    return False


def _has_cookies(site_map: SiteMap) -> bool:
    return bool(site_map.get("cookies"))


def _has_state_changing_endpoint(site_map: SiteMap) -> bool:
    if site_map.get("forms_count", 0):
        return True
    for endpoint in _endpoints(site_map):
        methods = {str(m).upper() for m in (endpoint.get("methods") or [])}
        if methods & {"POST", "PUT", "PATCH", "DELETE"}:
            return True
    return False


def _param_names(site_map: SiteMap) -> list[str]:
    names: list[str] = []
    for endpoint in _endpoints(site_map):
        names.extend(str(p).lower() for p in (endpoint.get("params") or []))
    return names


def _has_param_matching(site_map: SiteMap, tokens: tuple[str, ...]) -> bool:
    return any(token in name for name in _param_names(site_map) for token in tokens)


def _has_id_like_param(site_map: SiteMap) -> bool:
    for name in _param_names(site_map):
        if name in ("id", "uuid", "guid") or name.endswith(("_id", "_uuid", "_guid")):
            return True
    return False


def _header(site_map: SiteMap, header_name: str) -> str | None:
    headers = site_map.get("response_headers") or {}
    lowered = {str(k).lower(): v for k, v in headers.items()}
    return lowered.get(header_name.lower())


def _tech_stack_lower(site_map: SiteMap) -> list[str]:
    return [str(t).lower() for t in (site_map.get("tech_stack") or [])]


# --------------------------------------------------------------------------
# Deterministic per-category rules. Each returns (applicable, reason) when it
# can confidently decide, or None to defer the CWE to the LLM pass.
# --------------------------------------------------------------------------


def _rule_file_upload(site_map: SiteMap) -> Verdict:
    if _has_file_upload_form(site_map):
        return True, "File upload form (multipart enctype or file input) detected in recon site map."
    return False, "No file upload form detected in site map."


def _rule_input_surface(site_map: SiteMap) -> Verdict:
    if _has_input_surface(site_map):
        return True, "Site map shows attacker-controllable input (endpoint parameters or forms) — requires testing."
    return False, "No endpoint parameters or forms observed in site map — no input surface to attack."


def _rule_csrf(site_map: SiteMap) -> Verdict:
    if _has_state_changing_endpoint(site_map):
        return True, "State-changing forms or POST/PUT/PATCH/DELETE endpoints detected — CSRF testing applicable."
    return False, "No state-changing forms or endpoints detected in site map."


def _rule_cookie_dependent(site_map: SiteMap) -> Verdict:
    if _has_cookies(site_map):
        return True, "Cookies observed in recon site map — session/cookie-handling weakness plausible."
    return False, "No cookies observed in site map — cookie/session-management CWE not applicable."


def _rule_path_traversal(site_map: SiteMap) -> Verdict:
    for endpoint in _endpoints(site_map):
        if endpoint.get("params"):
            return True, "Endpoint(s) with query/path parameters observed — path traversal testing applicable."
    return False, "No endpoint parameters observed — no file-path-controlling input detected."


def _rule_idor(site_map: SiteMap) -> Verdict | None:
    if _has_id_like_param(site_map):
        return True, "Endpoint parameter(s) resembling an object identifier detected — IDOR testing applicable."
    return None


_SSRF_TOKENS = ("url", "uri", "link", "callback", "webhook", "src", "target", "endpoint", "feed")


def _rule_ssrf(site_map: SiteMap) -> Verdict | None:
    if _has_param_matching(site_map, _SSRF_TOKENS):
        return True, "Endpoint parameter resembling a URL/callback/webhook detected — SSRF testing applicable."
    return None


_REDIRECT_TOKENS = ("redirect", "return", "next", "continue", "dest")


def _rule_open_redirect(site_map: SiteMap) -> Verdict | None:
    if _has_param_matching(site_map, _REDIRECT_TOKENS):
        return True, "Endpoint parameter resembling a redirect target detected — open-redirect testing applicable."
    return None


def _rule_cors(site_map: SiteMap) -> Verdict | None:
    if _header(site_map, "access-control-allow-origin") is not None:
        return True, "CORS response header observed in recon — CORS-misconfiguration testing applicable."
    return None


def _rule_clickjacking(site_map: SiteMap) -> Verdict:
    if _header(site_map, "x-frame-options") is not None:
        return False, "X-Frame-Options header present in recon response headers."
    return True, "No X-Frame-Options header observed in recon — clickjacking testing applicable."


def _rule_cleartext_transmission(site_map: SiteMap) -> Verdict | None:
    if _header(site_map, "strict-transport-security") is not None:
        return None
    return True, "No Strict-Transport-Security header observed — cleartext-transmission risk applicable."


def _rule_outdated_components(site_map: SiteMap) -> Verdict | None:
    if _tech_stack_lower(site_map):
        return True, "Technology stack fingerprinted by recon — outdated/vulnerable component testing applicable."
    return None


def _rule_no_endpoints_means_not_applicable(site_map: SiteMap) -> Verdict | None:
    if _has_endpoints(site_map):
        return None
    return False, "No endpoints discovered by recon — nothing to exercise for this weakness class."


_FILE_UPLOAD_IDS = {"CWE-434", "CWE-646", "CWE-616"}
_CSRF_IDS = {"CWE-352"}
_COOKIE_IDS = {
    "CWE-384", "CWE-613", "CWE-1004", "CWE-614", "CWE-1275",
    "CWE-522", "CWE-315", "CWE-256", "CWE-257", "CWE-640", "CWE-620",
}
_PATH_TRAVERSAL_IDS = {"CWE-22", "CWE-23", "CWE-36", "CWE-73"}
_IDOR_IDS = {"CWE-639"}
_SSRF_IDS = {"CWE-918", "CWE-441"}
_OPEN_REDIRECT_IDS = {"CWE-601"}
_CORS_IDS = {"CWE-942", "CWE-346"}
_CLICKJACKING_IDS = {"CWE-1021", "CWE-451"}
_CLEARTEXT_IDS = {"CWE-319"}
_OUTDATED_COMPONENT_IDS = {"CWE-1104", "CWE-937", "CWE-1035"}

_INPUT_SURFACE_CATEGORIES = {"injection", "xss", "input_validation", "mass_assignment"}


def _build_specific_rules() -> dict[str, RuleFn]:
    table: dict[str, RuleFn] = {}
    for group, rule in (
        (_FILE_UPLOAD_IDS, _rule_file_upload),
        (_CSRF_IDS, _rule_csrf),
        (_COOKIE_IDS, _rule_cookie_dependent),
        (_PATH_TRAVERSAL_IDS, _rule_path_traversal),
        (_IDOR_IDS, _rule_idor),
        (_SSRF_IDS, _rule_ssrf),
        (_OPEN_REDIRECT_IDS, _rule_open_redirect),
        (_CORS_IDS, _rule_cors),
        (_CLICKJACKING_IDS, _rule_clickjacking),
        (_CLEARTEXT_IDS, _rule_cleartext_transmission),
        (_OUTDATED_COMPONENT_IDS, _rule_outdated_components),
    ):
        for cwe_id in group:
            table[cwe_id] = rule
    return table


_SPECIFIC_RULES: dict[str, RuleFn] = _build_specific_rules()

# Stack fingerprints strong enough to force an applicable=True verdict
# regardless of what the base rule pass decided — presence of the stack is
# itself the positive signal for these CWEs.
_STACK_HINTS: dict[str, dict[str, str]] = {
    "wordpress": {
        "CWE-1392": "WordPress detected in tech stack — default/weak admin credentials are a common finding.",
        "CWE-1104": "WordPress detected in tech stack — plugins/themes are frequently unmaintained third-party code.",
        "CWE-937": "WordPress detected in tech stack — plugin/theme ecosystem is a common source of known-vulnerable components.",
        "CWE-1035": "WordPress detected in tech stack — plugin/theme ecosystem is a common source of known-vulnerable components.",
    },
    "php": {
        "CWE-98": "PHP detected in tech stack — remote/local file inclusion testing applicable.",
        "CWE-616": "PHP detected in tech stack — uploaded-file-variable handling testing applicable.",
    },
    "jquery": {
        "CWE-79": "jQuery detected in tech stack — older jQuery versions have known DOM XSS sinks.",
    },
}


def _apply_stack_hints(site_map: SiteMap, decided: dict[str, Verdict]) -> None:
    stacks = _tech_stack_lower(site_map)
    for stack_keyword, hints in _STACK_HINTS.items():
        if not any(stack_keyword in stack for stack in stacks):
            continue
        for cwe_id, reason in hints.items():
            decided[cwe_id] = (True, reason)


def _make_item(cwe: dict, applicable: bool, reason: str) -> CweChecklistItem:
    return {
        "cwe_id": cwe["cwe_id"],
        "name": cwe.get("name", ""),
        "category": cwe.get("category", ""),
        "applicable": applicable,
        "reason": reason,
        "tested": False,
        "detection_method": None,
    }


def apply_rule_based_pass(catalog: list[dict], site_map: SiteMap) -> tuple[list[CweChecklistItem], list[dict]]:
    """Deterministic pass over the full catalog.

    Returns (decided_items, undecided_catalog_entries) — the latter is what
    gets handed to the LLM pass.
    """
    decided: dict[str, Verdict] = {}
    undecided: list[dict] = []

    for cwe in catalog:
        cwe_id = cwe["cwe_id"]
        category = cwe.get("category", "")

        rule = _SPECIFIC_RULES.get(cwe_id)
        if rule is not None:
            verdict = rule(site_map)
        elif category in _INPUT_SURFACE_CATEGORIES:
            verdict = _rule_input_surface(site_map)
        else:
            verdict = _rule_no_endpoints_means_not_applicable(site_map)

        if verdict is not None:
            decided[cwe_id] = verdict
        else:
            undecided.append(cwe)

    _apply_stack_hints(site_map, decided)
    undecided = [cwe for cwe in undecided if cwe["cwe_id"] not in decided]

    decided_items = [_make_item(cwe, *decided[cwe["cwe_id"]]) for cwe in catalog if cwe["cwe_id"] in decided]
    return decided_items, undecided


# --------------------------------------------------------------------------
# LLM pass for whatever the rules couldn't decide
# --------------------------------------------------------------------------

_LLM_SYSTEM_PROMPT = (
    "You are a web-application security triage assistant helping a pentesting "
    "platform decide which CWE weakness classes are plausibly applicable to a "
    "specific target, based only on reconnaissance data (no exploitation has "
    "happened yet). For each CWE given, decide whether it is plausibly "
    "applicable to this site given the site map, and give a one-sentence "
    "reason. Default to applicable when genuinely uncertain — a false "
    "negative here means a real vulnerability class is never tested; a false "
    "positive just costs one wasted test."
)

_VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cwe_id": {"type": "string"},
                    "applicable": {"type": "boolean"},
                    "reason": {"type": "string"},
                },
                "required": ["cwe_id", "applicable", "reason"],
            },
        }
    },
    "required": ["verdicts"],
}


def _chunked(items: list[dict], size: int) -> list[list[dict]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _site_map_summary(site_map: SiteMap) -> str:
    cookies = site_map.get("cookies") or []
    return json.dumps(
        {
            "domain": site_map.get("domain"),
            "tech_stack": site_map.get("tech_stack"),
            "forms_count": site_map.get("forms_count"),
            "cookie_names": [c.get("name") for c in cookies if isinstance(c, dict)],
            "endpoint_count": len(_endpoints(site_map)),
            "sample_endpoints": [
                {
                    "url": e.get("url"),
                    "methods": e.get("methods"),
                    "params": e.get("params"),
                    "requires_auth": e.get("requires_auth"),
                }
                for e in _endpoints(site_map)[:15]
            ],
        },
        default=str,
    )


def _judge_batch(client: LlmClient, batch: list[dict], site_map: SiteMap) -> dict[str, Verdict]:
    user = (
        f"Site map summary:\n{_site_map_summary(site_map)}\n\n"
        "CWEs to judge:\n"
        + "\n".join(f"- {c['cwe_id']}: {c.get('name', '')} (category: {c.get('category', '')})" for c in batch)
    )
    result = client.complete_json(
        system=_LLM_SYSTEM_PROMPT, user=user, json_schema=_VERDICT_SCHEMA, schema_name="cwe_verdicts"
    )
    verdicts: dict[str, Verdict] = {}
    for entry in result.get("verdicts") or []:
        cwe_id = entry.get("cwe_id")
        if not cwe_id:
            continue
        verdicts[str(cwe_id).upper()] = (bool(entry.get("applicable", True)), str(entry.get("reason") or "LLM judgment"))
    return verdicts


def apply_llm_pass(undecided: list[dict], site_map: SiteMap) -> tuple[list[CweChecklistItem], bool]:
    """Judges whatever the rule pass couldn't decide.

    Returns (items, llm_available). When no LLM API key is configured, OR
    when a batch call itself fails (bad model name, rate limit, transient API
    error — anything, not just missing credentials), every undecided CWE in
    that batch defaults to applicable=True with a fixed manual-triage reason
    — a fail-open default so a flaky/misconfigured LLM never silently drops
    CWE coverage or crashes the whole mapping pass.
    """
    if not undecided:
        return [], True

    try:
        client = get_llm_client()
    except LlmConfigurationError:
        return [_make_item(cwe, True, LLM_UNAVAILABLE_REASON) for cwe in undecided], False

    verdicts: dict[str, Verdict] = {}
    all_batches_succeeded = True
    for batch in _chunked(undecided, LLM_BATCH_SIZE):
        try:
            verdicts.update(_judge_batch(client, batch, site_map))
        except Exception:
            all_batches_succeeded = False
            continue

    items: list[CweChecklistItem] = []
    for cwe in undecided:
        if cwe["cwe_id"] in verdicts:
            applicable, reason = verdicts[cwe["cwe_id"]]
        else:
            applicable, reason = (
                True,
                "LLM did not return a verdict for this CWE — defaulting to applicable, needs manual triage",
            )
        items.append(_make_item(cwe, applicable, reason))
    return items, all_batches_succeeded


# --------------------------------------------------------------------------
# LangGraph node
# --------------------------------------------------------------------------


def cwe_mapping_node(state: SentinelState) -> dict:
    site_map: SiteMap = state.get("site_map") or {}
    scan_session_id = state["scan_session_id"]
    catalog = load_cwe_catalog()

    decided_items, undecided = apply_rule_based_pass(catalog, site_map)
    llm_items, llm_available = apply_llm_pass(undecided, site_map)

    items_by_id = {item["cwe_id"]: item for item in (*decided_items, *llm_items)}
    checklist: list[CweChecklistItem] = [items_by_id[cwe["cwe_id"]] for cwe in catalog]

    applicable_count = sum(1 for item in checklist if item["applicable"])
    not_applicable_count = len(checklist) - applicable_count

    with get_session() as db:
        scan_session = db.get(ScanSession, scan_session_id)
        if scan_session is None:
            raise ValueError(f"ScanSession {scan_session_id} not found")

        if not llm_available:
            audit_log.record(
                db,
                agent=AGENT_NAME,
                action="llm_unavailable_default",
                payload={
                    "scan_session_id": scan_session_id,
                    "deferred_cwe_count": len(undecided),
                    "default_reason": LLM_UNAVAILABLE_REASON,
                },
            )

        db.query(CweApplicability).filter(CweApplicability.scan_session_id == scan_session_id).delete()
        for item in checklist:
            db.add(
                CweApplicability(
                    scan_session_id=scan_session_id,
                    cwe_id=item["cwe_id"],
                    cwe_name=item.get("name", ""),
                    applicable=item["applicable"],
                    reason=item.get("reason", ""),
                    tested=False,
                    detection_method=None,
                )
            )
        scan_session.applicable_cwe_count = applicable_count
        scan_session.not_applicable_cwe_count = not_applicable_count
        db.flush()

        audit_log.record(
            db,
            agent=AGENT_NAME,
            action="cwe_mapping_complete",
            payload={
                "scan_session_id": scan_session_id,
                "applicable_count": applicable_count,
                "not_applicable_count": not_applicable_count,
                "catalog_size": len(catalog),
                "llm_judged_count": len(undecided) if llm_available else 0,
            },
        )

    return {
        "cwe_checklist": checklist,
        "applicable_count": applicable_count,
        "not_applicable_count": not_applicable_count,
        "current_phase": "cwe_mapping_complete",
    }
