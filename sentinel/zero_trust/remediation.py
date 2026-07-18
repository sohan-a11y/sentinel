"""Offline, privacy-preserving remediation guidance for redacted findings.

The module is deliberately a pure transformation: it takes an already
redacted finding envelope and an optional canonical CWE identifier, then
selects generic advice from a fixed local catalogue.  It performs no I/O,
does not inspect evidence digests, and cannot carry scan artifacts forward.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from sentinel.zero_trust.evidence import RedactedFindingEnvelope


_SCHEMA_VERSION = "zero-trust-remediation.v1"
_CWE_ID = re.compile(r"^CWE-[1-9][0-9]{0,5}$")
_PRIORITY_BY_SEVERITY = {
    "critical": "P0",
    "high": "P1",
    "medium": "P2",
    "low": "P3",
    "info": "P4",
}


class RemediationGuidanceError(ValueError):
    """Raised when safe local remediation guidance cannot be created."""


@dataclass(frozen=True, slots=True)
class RemediationGuidance:
    """Small, immutable advice suitable for privacy-safe reporting."""

    schema_version: str
    category: str
    priority: str
    cwe_id: str | None
    risk: str
    fix: str
    validation: str

    def to_dict(self) -> dict[str, str | None]:
        """Return the complete allowlisted guidance payload."""
        return {
            "schema_version": self.schema_version,
            "category": self.category,
            "priority": self.priority,
            "cwe_id": self.cwe_id,
            "risk": self.risk,
            "fix": self.fix,
            "validation": self.validation,
        }


def create_remediation_guidance(
    finding: RedactedFindingEnvelope,
    *,
    cwe_id: str | None = None,
) -> RemediationGuidance:
    """Create generic local guidance from one redacted finding envelope.

    Only the envelope's category and severity influence the result.  Its
    title, endpoint, timestamp, and evidence digests are intentionally not
    read or returned.
    """
    _validate_finding(finding)
    normalized_cwe_id = _validate_cwe_id(cwe_id)
    category, risk, fix, validation = _advice_for_category(finding.category)

    return RemediationGuidance(
        schema_version=_SCHEMA_VERSION,
        category=category,
        priority=_PRIORITY_BY_SEVERITY[finding.severity],
        cwe_id=normalized_cwe_id,
        risk=risk,
        fix=fix,
        validation=validation,
    )


def _validate_finding(finding: RedactedFindingEnvelope) -> None:
    """Require the explicit safe envelope type and known metadata values."""
    if type(finding) is not RedactedFindingEnvelope:
        raise RemediationGuidanceError("finding must be a redacted finding envelope")
    if finding.schema_version != "zero-trust-finding.v1":
        raise RemediationGuidanceError("finding has an unsupported schema version")
    if finding.severity not in _PRIORITY_BY_SEVERITY:
        raise RemediationGuidanceError("finding has an unsupported severity")
    if not isinstance(finding.category, str) or not finding.category.strip():
        raise RemediationGuidanceError("finding has an invalid category")


def _validate_cwe_id(cwe_id: str | None) -> str | None:
    if cwe_id is None:
        return None
    if not isinstance(cwe_id, str) or not _CWE_ID.fullmatch(cwe_id):
        raise RemediationGuidanceError("CWE identifier must use the canonical CWE-<number> form")
    return cwe_id


def _advice_for_category(category: str) -> tuple[str, str, str, str]:
    normalized = category.casefold().strip()
    if normalized in {"authorization", "access control", "idor", "broken access control"}:
        return (
            "authorization",
            "Unauthorized users may be able to access or change protected resources.",
            "Enforce server-side ownership and role checks for every protected action; deny by default.",
            "Add regression tests that exercise permitted and non-permitted roles for the same resource.",
        )
    if normalized in {"authentication", "identity", "session management"}:
        return (
            "authentication",
            "Identity or session controls may not reliably distinguish legitimate users from attackers.",
            "Strengthen identity verification, session lifecycle controls, and rate limits using approved platform mechanisms.",
            "Verify that invalid, expired, and downgraded sessions are rejected in an isolated test environment.",
        )
    if normalized in {"injection", "sql injection", "cross-site scripting", "xss", "command injection"}:
        return (
            "injection",
            "Untrusted input may influence a sensitive interpreter or rendering context.",
            "Use context-appropriate parameterization, strict allowlists, and framework-provided output encoding.",
            "Add focused automated checks for malformed input and confirm the application handles it safely.",
        )
    if normalized in {"configuration", "security configuration", "misconfiguration"}:
        return (
            "configuration",
            "A missing or weakened security control may leave the application exposed.",
            "Apply a documented hardened baseline and remove insecure defaults from the relevant service configuration.",
            "Validate the intended configuration through a repeatable non-production deployment check.",
        )
    if normalized in {"information disclosure", "data exposure", "sensitive data exposure"}:
        return (
            "information-disclosure",
            "Sensitive information may be exposed beyond the audience that needs it.",
            "Minimize returned data, enforce audience checks, and use safe error handling that avoids unnecessary detail.",
            "Confirm representative error and success paths reveal only the approved data classification.",
        )
    return (
        "general-security",
        "A security weakness may increase risk if it is combined with another issue or unsafe deployment setting.",
        "Triage the finding with the application owner, apply the relevant secure design control, and record the decision.",
        "Add a small regression check in an isolated environment before closing the finding.",
    )
