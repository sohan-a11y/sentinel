"""Create privacy-safe finding envelopes inside a customer's boundary.

This module deliberately has no persistence, networking, or logging.  It
accepts a scanner finding locally and returns a strict allowlist of metadata
that may leave the customer's environment.  Raw requests, responses,
headers, bodies, credentials, and evidence are neither retained nor exported.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import re
from typing import Any
from urllib.parse import urlsplit


_SCHEMA_VERSION = "zero-trust-finding.v1"
_ALLOWED_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_CATEGORY_TITLES = {
    "authentication": "Potential authentication control weakness",
    "authorization": "Potential authorization control weakness",
    "business logic": "Potential business logic control weakness",
    "cross-site request forgery": "Potential cross-site request forgery weakness",
    "cross-site scripting": "Potential cross-site scripting weakness",
    "cryptography": "Potential cryptographic control weakness",
    "dependency security": "Potential dependency security weakness",
    "injection": "Potential injection weakness",
    "information disclosure": "Potential information disclosure weakness",
    "insecure deserialization": "Potential insecure deserialization weakness",
    "input validation": "Potential input validation weakness",
    "path traversal": "Potential path traversal weakness",
    "rate limiting": "Potential rate-limiting weakness",
    "security configuration": "Potential security configuration weakness",
    "server-side request forgery": "Potential server-side request forgery weakness",
    "session management": "Potential session-management weakness",
    "transport security": "Potential transport security weakness",
}
_MAX_TITLE_LENGTH = 256
_MAX_CATEGORY_LENGTH = 128
_MAX_ENDPOINT_LENGTH = 2_048
_MAX_EVIDENCE_ITEMS = 16
_MAX_EVIDENCE_BYTES = 65_536
_MIN_EVIDENCE_HMAC_KEY_BYTES = 32

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
# Route names can themselves be customer-sensitive (for example a branded
# product, a tenant slug, or an employee name). Only a tiny universal routing
# vocabulary is preserved; every other segment becomes a generic route-shape
# marker. The output is for coarse remediation correlation, not navigation.
_SAFE_ROUTE_SEGMENTS = frozenset(
    {
        ".well-known",
        "api",
        "auth",
        "docs",
        "graphql",
        "health",
        "healthz",
        "live",
        "liveness",
        "login",
        "logout",
        "oauth",
        "openapi.json",
        "ready",
        "readiness",
        "swagger",
        "v1",
        "v2",
        "v3",
    }
)


class EvidenceRedactionError(ValueError):
    """Raised when local finding data cannot be safely reduced to metadata."""


@dataclass(frozen=True)
class RedactedFindingEnvelope:
    """The complete, deliberately small data shape allowed to leave locally."""

    schema_version: str
    title: str
    category: str
    severity: str
    endpoint_path: str
    observed_at: str
    evidence_hmac_sha256: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return only serializable, explicitly approved outbound fields."""
        return {
            "schema_version": self.schema_version,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "endpoint_path": self.endpoint_path,
            "observed_at": self.observed_at,
            "evidence_hmac_sha256": list(self.evidence_hmac_sha256),
        }


def create_redacted_finding_envelope(
    finding: Mapping[str, Any],
    *,
    observed_at: datetime | None = None,
    evidence_hmac_key: bytes | bytearray | None = None,
) -> RedactedFindingEnvelope:
    """Reduce a local scanner finding to privacy-safe, redacted metadata.

    Only ``title``, ``category``, ``severity``, ``endpoint``, and ``evidence``
    are read from ``finding``. Every other key, including request/response
    material and secrets, is intentionally ignored. The scanner-supplied
    title is validated locally but never exported: the envelope derives a
    fixed, taxonomy-controlled title from its category. Evidence is converted
    to a customer-local HMAC-SHA-256 digest and is not stored in the returned
    envelope. A plain digest would let an external recipient guess low-entropy
    evidence values, so a local key is mandatory and never exported.
    """
    if not isinstance(finding, Mapping):
        raise EvidenceRedactionError("finding must be a mapping")

    _required_text(finding, "title", _MAX_TITLE_LENGTH)
    category = _canonical_category(finding)
    severity = _required_text(finding, "severity", 16).lower()
    endpoint_path = _endpoint_path(_required_text(finding, "endpoint", _MAX_ENDPOINT_LENGTH))

    if severity not in _ALLOWED_SEVERITIES:
        raise EvidenceRedactionError("severity is not allowed")

    evidence_key = _validate_evidence_hmac_key(evidence_hmac_key)
    evidence_hashes = _hash_evidence(finding.get("evidence"), evidence_key)
    timestamp = _format_timestamp(observed_at)

    return RedactedFindingEnvelope(
        schema_version=_SCHEMA_VERSION,
        title=_CATEGORY_TITLES[category],
        category=category,
        severity=severity,
        endpoint_path=endpoint_path,
        observed_at=timestamp,
        evidence_hmac_sha256=evidence_hashes,
    )


def _required_text(finding: Mapping[str, Any], name: str, maximum_length: int) -> str:
    value = finding.get(name)
    if not isinstance(value, str):
        raise EvidenceRedactionError(f"{name} must be text")
    if not value or len(value) > maximum_length or _CONTROL_CHARACTERS.search(value):
        raise EvidenceRedactionError(f"{name} is invalid")

    if not value.strip():
        raise EvidenceRedactionError(f"{name} is invalid")
    return value


def _canonical_category(finding: Mapping[str, Any]) -> str:
    """Accept only a fixed, non-customer-specific finding taxonomy."""
    category = _required_text(finding, "category", _MAX_CATEGORY_LENGTH).lower()
    if category not in _CATEGORY_TITLES:
        raise EvidenceRedactionError("category is not allowed")
    return category


def _endpoint_path(endpoint: str) -> str:
    """Keep only a root-relative endpoint path; discard host, query, fragment."""
    try:
        parsed = urlsplit(endpoint)
    except ValueError as exc:
        raise EvidenceRedactionError("endpoint is invalid") from exc

    if parsed.scheme:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise EvidenceRedactionError("endpoint is invalid")
        if parsed.username is not None or parsed.password is not None:
            raise EvidenceRedactionError("endpoint is invalid")
    elif parsed.netloc or not parsed.path.startswith("/"):
        raise EvidenceRedactionError("endpoint is invalid")

    path = parsed.path or "/"
    if len(path) > _MAX_ENDPOINT_LENGTH or _CONTROL_CHARACTERS.search(path):
        raise EvidenceRedactionError("endpoint is invalid")
    return _redact_path_identifiers(path)


def _redact_path_identifiers(path: str) -> str:
    """Export only a conservative route shape, never customer route names."""
    parts = path.split("/")
    redacted_parts: list[str] = []
    for part in parts:
        if not part:
            redacted_parts.append("")
        elif part.casefold() in _SAFE_ROUTE_SEGMENTS:
            redacted_parts.append(part.casefold())
        else:
            redacted_parts.append("{segment}")
    return "/".join(redacted_parts)


def _validate_evidence_hmac_key(value: bytes | bytearray | None) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise EvidenceRedactionError("evidence_hmac_key must be customer-local bytes")
    key = bytes(value)
    if len(key) < _MIN_EVIDENCE_HMAC_KEY_BYTES:
        raise EvidenceRedactionError("evidence_hmac_key must be at least 32 bytes")
    return key


def _hash_evidence(value: Any, evidence_hmac_key: bytes) -> tuple[str, ...]:
    """HMAC bounded local evidence without retaining it in the envelope."""
    if value is None:
        return ()
    if isinstance(value, (str, bytes, bytearray)):
        items: Sequence[object] = (value,)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items = value
    else:
        raise EvidenceRedactionError("evidence must be text, bytes, or a sequence")

    if len(items) > _MAX_EVIDENCE_ITEMS:
        raise EvidenceRedactionError("too many evidence items")

    hashes: list[str] = []
    for item in items:
        if isinstance(item, str):
            try:
                encoded = item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise EvidenceRedactionError("evidence cannot be encoded") from exc
        elif isinstance(item, (bytes, bytearray)):
            encoded = bytes(item)
        else:
            raise EvidenceRedactionError("evidence item must be text or bytes")
        if len(encoded) > _MAX_EVIDENCE_BYTES:
            raise EvidenceRedactionError("evidence item is too large")
        hashes.append(hmac.new(evidence_hmac_key, encoded, sha256).hexdigest())
    return tuple(hashes)


def _format_timestamp(observed_at: datetime | None) -> str:
    if observed_at is None:
        observed_at = datetime.now(timezone.utc)
    if not isinstance(observed_at, datetime) or observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise EvidenceRedactionError("observed_at must be timezone-aware")
    normalized = observed_at.astimezone(timezone.utc)
    return normalized.isoformat(timespec="seconds").replace("+00:00", "Z")
