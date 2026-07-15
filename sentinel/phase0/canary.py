"""Step 2 of Phase 0: prove this is a real, disposable test environment.

The user seeds one random UUID (the "canary marker") into their target's own
database at registration time (e.g. a seeded user record, a config row —
whatever their app's data layer already exposes for reading). Before any
Tier B (destructive/exploitative) action runs THIS session, we ask the
target's own app to hand the marker back to us, via a URL template the user
supplied (e.g. "https://app.example.com/api/debug/echo?id={marker}" or
"https://app.example.com/api/users/{marker}"). If the marker doesn't come
back, we do not trust the user's claim that this is a safe environment —
we downgrade to Tier A silently-to-the-user but loudly-to-the-audit-log.
"""
from __future__ import annotations

import uuid

import httpx

from sentinel.config import settings
from sentinel.db.models import EnvironmentTier
from sentinel.security import safe_http
from sentinel.security.guardrails import PivotViolationError, normalize_host


def generate_canary_marker() -> str:
    # Phase 0 is executing here: mints the random marker the user must seed
    # into their own target's data layer for the environment canary check.
    return uuid.uuid4().hex


def render_canary_url(url_template: str, marker: str) -> str:
    # Phase 0 is executing here: substitutes the real marker into the
    # user-supplied canary_check_url_template before it gets probed.
    if "{marker}" not in url_template:
        raise ValueError("canary_check_url_template must contain the literal placeholder '{marker}'")
    return url_template.replace("{marker}", marker)


def probe_canary(url_template: str, marker: str, method: str = "GET") -> bool:
    """Hit the user-supplied URL and confirm the marker is echoed back.

    Fails closed: any transport error, timeout, non-2xx response, or a
    redirect to a host other than the one url_template started on is treated
    as "marker absent" — never assumed present. The redirect check matters
    because a plain follow_redirects=True would otherwise let a misbehaving
    endpoint hand this probe (and, elsewhere, real session cookies attached
    to guardrailed requests) off to an arbitrary third-party host.
    """
    # Phase 0 is executing here: the live environment-canary probe — this is
    # the ONLY place that ever confirms an environment is safe for Tier B.
    url = render_canary_url(url_template, marker)
    expected_host = normalize_host(url)
    try:
        response = safe_http.request_same_host(
            method.upper(),
            url,
            expected_host,
            timeout=settings.verification_http_timeout_seconds,
        )
    except (httpx.HTTPError, PivotViolationError):
        return False
    if not (200 <= response.status_code < 300):
        return False
    return marker in response.text


def determine_environment_tier(url_template: str, marker: str, method: str = "GET") -> EnvironmentTier:
    """The only function allowed to produce EnvironmentTier.VERIFIED_SAFE.

    Every other code path defaults to UNVERIFIED (fail closed).
    """
    # Phase 0 is executing here: converts the canary probe result into the
    # session's environment tier — VERIFIED_SAFE only on a live, passing probe;
    # UNVERIFIED (Tier A only) for every other outcome, including a probe that
    # was never set up to begin with.
    if probe_canary(url_template, marker, method):
        return EnvironmentTier.VERIFIED_SAFE
    return EnvironmentTier.UNVERIFIED
