"""Step 1 of Phase 0: prove the requester owns the domain.

Two independent methods, either one sufficient:
  1. HTTP: a file at https://{domain}/.well-known/sentinel-auth.txt containing
     the exact token.
  2. DNS:  a TXT record at _sentinel-verify.{domain} containing the exact
     token (as a full string, or as a "sentinel-verify=<token>" pair).

Both checks fail closed: any network error, timeout, non-200, or missing
token is treated as "not verified" — never as "verified by default".
"""
from __future__ import annotations

import secrets

import dns.exception
import dns.resolver
import httpx

from sentinel.config import settings
from sentinel.db.models import VerificationMethod
from sentinel.security import safe_http
from sentinel.security.guardrails import PivotViolationError


def generate_verification_token() -> str:
    # Phase 0 is executing here: mints the token the requester must place at
    # the well-known URL or DNS TXT record to prove domain ownership.
    return secrets.token_urlsafe(24)


def _well_known_url(domain: str) -> str:
    return f"https://{domain}{settings.well_known_path}"


def check_well_known(domain: str, token: str) -> bool:
    """Fails closed on a redirect to a different host, too: safe_http.get_same_host
    re-validates every hop against `domain` rather than trusting httpx's
    follow_redirects to land somewhere still worth trusting."""
    # Phase 0 is executing here: HTTP method of domain-ownership verification —
    # live-fetches the well-known token file and checks the token is present.
    url = _well_known_url(domain)
    try:
        response = safe_http.get_same_host(
            url,
            domain,
            timeout=settings.verification_http_timeout_seconds,
        )
    except (httpx.HTTPError, PivotViolationError):
        return False
    if response.status_code != 200:
        return False
    return token in response.text


def check_dns_txt(domain: str, token: str) -> bool:
    # Phase 0 is executing here: DNS method of domain-ownership verification —
    # live-resolves the _sentinel-verify TXT record and checks the token is present.
    record_name = f"{settings.dns_txt_prefix}.{domain}"
    resolver = dns.resolver.Resolver()
    resolver.timeout = settings.verification_dns_timeout_seconds
    resolver.lifetime = settings.verification_dns_timeout_seconds
    try:
        answer = resolver.resolve(record_name, "TXT")
    except (dns.exception.DNSException, OSError):
        return False

    for record in answer:
        # dnspython yields TXT records as one-or-more quoted byte-strings;
        # join multi-part records before comparing.
        value = b"".join(record.strings).decode("utf-8", errors="ignore")
        if token in value:
            return True
    return False


def verify_domain_ownership(domain: str, token: str) -> VerificationMethod | None:
    """Try both methods. Returns the method that passed, or None if neither did."""
    # Phase 0 is executing here: orchestrates domain-ownership verification —
    # tries the HTTP well-known method first, then falls back to DNS TXT.
    if check_well_known(domain, token):
        return VerificationMethod.WELL_KNOWN_HTTP
    if check_dns_txt(domain, token):
        return VerificationMethod.DNS_TXT
    return None
