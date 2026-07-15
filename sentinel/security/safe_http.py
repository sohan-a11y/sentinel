"""Redirect-safe HTTP helpers — closes a real pivot hole.

httpx's `follow_redirects=True` transparently follows a target's `Location`
header to ANY host, and httpx's dict-style `cookies={...}` kwarg attaches
domain-unscoped cookies (`domain_specified=False`), which `http.cookiejar`
matches against every host. Combined, a single guardrailed request whose
target redirects to an off-target host will silently resend real session
cookies to that host, with `guardrails.enforce_no_pivot` never having seen
the second hop — it only ever validated the URL string before the request
was sent.

Every function here re-validates the resolved host against `expected_host`
(via guardrails.normalize_host) BEFORE following each hop, including the
first, and never delegates redirect-following to httpx itself.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

import httpx

from sentinel.security.guardrails import PivotViolationError, normalize_host

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS = 5


def request_same_host(method: str, url: str, expected_host: str, **kwargs: Any) -> httpx.Response:
    """Like httpx.request(..., follow_redirects=True), except every hop
    (including the first request) must resolve to expected_host or this
    raises PivotViolationError instead of silently following elsewhere."""
    kwargs.pop("follow_redirects", None)
    current_url = url
    for _ in range(_MAX_REDIRECTS + 1):
        if normalize_host(current_url) != normalize_host(expected_host):
            raise PivotViolationError(
                f"Refusing to follow request to '{current_url}' — resolved host does not match "
                f"expected target '{expected_host}'"
            )
        response = httpx.request(method, current_url, follow_redirects=False, **kwargs)
        if response.status_code not in _REDIRECT_STATUSES or "location" not in response.headers:
            return response
        current_url = urljoin(current_url, response.headers["location"])
    raise PivotViolationError(f"Too many redirects (>{_MAX_REDIRECTS}) while fetching '{url}'")


def get_same_host(url: str, expected_host: str, **kwargs: Any) -> httpx.Response:
    return request_same_host("GET", url, expected_host, **kwargs)


def post_same_host(url: str, expected_host: str, **kwargs: Any) -> httpx.Response:
    return request_same_host("POST", url, expected_host, **kwargs)
