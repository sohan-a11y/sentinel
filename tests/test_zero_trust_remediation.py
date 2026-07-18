from __future__ import annotations

from dataclasses import FrozenInstanceError
import inspect
import json

import pytest

from sentinel.zero_trust.evidence import RedactedFindingEnvelope
from sentinel.zero_trust.remediation import (
    RemediationGuidanceError,
    create_remediation_guidance,
)


def _envelope(*, category: str = "authorization", severity: str = "high") -> RedactedFindingEnvelope:
    return RedactedFindingEnvelope(
        schema_version="zero-trust-finding.v1",
        title="Broken access control",
        category=category,
        severity=severity,
        endpoint_path="/api/accounts/{id}",
        observed_at="2026-07-18T09:30:00Z",
        evidence_hmac_sha256=("a" * 64, "b" * 64),
    )


@pytest.mark.parametrize(
    ("category", "expected_category", "risk_fragment"),
    [
        ("authorization", "authorization", "unauthorized"),
        ("authentication", "authentication", "identity"),
        ("injection", "injection", "untrusted"),
        ("security configuration", "configuration", "security control"),
        ("information disclosure", "information-disclosure", "sensitive"),
        ("unexpected scanner category", "general-security", "security weakness"),
    ],
)
def test_maps_safe_broad_categories_to_generic_remediation(category, expected_category, risk_fragment):
    guidance = create_remediation_guidance(_envelope(category=category), cwe_id="CWE-639")

    assert guidance.category == expected_category
    assert risk_fragment in guidance.risk.lower()
    assert guidance.cwe_id == "CWE-639"
    assert guidance.fix
    assert guidance.validation


@pytest.mark.parametrize(
    ("severity", "expected_priority"),
    [
        ("critical", "P0"),
        ("high", "P1"),
        ("medium", "P2"),
        ("low", "P3"),
        ("info", "P4"),
    ],
)
def test_assigns_priority_from_the_envelope_severity(severity, expected_priority):
    guidance = create_remediation_guidance(_envelope(severity=severity))

    assert guidance.priority == expected_priority


def test_guidance_is_immutable_and_excludes_all_evidence_and_location_data():
    envelope = _envelope()
    guidance = create_remediation_guidance(envelope, cwe_id="CWE-89")
    payload = guidance.to_dict()
    encoded = json.dumps(payload, sort_keys=True)

    assert set(payload) == {
        "schema_version",
        "category",
        "priority",
        "cwe_id",
        "risk",
        "fix",
        "validation",
    }
    for forbidden in (
        "a" * 64,
        "b" * 64,
        envelope.title,
        envelope.endpoint_path,
        envelope.observed_at,
        "evidence_hmac_sha256",
    ):
        assert forbidden not in encoded
    with pytest.raises(FrozenInstanceError):
        guidance.priority = "P0"  # type: ignore[misc]


@pytest.mark.parametrize("cwe_id", ["CWE-89", "CWE-639", "CWE-1000"])
def test_accepts_only_canonical_cwe_identifiers(cwe_id):
    assert create_remediation_guidance(_envelope(), cwe_id=cwe_id).cwe_id == cwe_id


@pytest.mark.parametrize(
    "cwe_id",
    ["cwe-89", "CWE-089", "CWE-0", "CWE-89 ", "CWE-89; DROP", 89, "CWE-1234567"],
)
def test_rejects_ambiguous_or_malformed_cwe_identifiers(cwe_id):
    with pytest.raises(RemediationGuidanceError, match="CWE"):
        create_remediation_guidance(_envelope(), cwe_id=cwe_id)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "finding",
    [
        {},
        {"category": "authorization", "severity": "high"},
        _envelope(severity="urgent"),
        _envelope(category="authorization"),
    ],
)
def test_rejects_anything_other_than_a_valid_redacted_finding_envelope(finding):
    if isinstance(finding, RedactedFindingEnvelope) and finding.category == "authorization" and finding.severity == "high":
        finding = RedactedFindingEnvelope(
            schema_version="other.v1",
            title=finding.title,
            category=finding.category,
            severity=finding.severity,
            endpoint_path=finding.endpoint_path,
            observed_at=finding.observed_at,
            evidence_hmac_sha256=finding.evidence_hmac_sha256,
        )

    with pytest.raises(RemediationGuidanceError):
        create_remediation_guidance(finding)  # type: ignore[arg-type]


def test_public_api_has_no_raw_artifact_or_network_parameters_or_imports():
    signature = inspect.signature(create_remediation_guidance)
    assert tuple(signature.parameters) == ("finding", "cwe_id")

    import sentinel.zero_trust.remediation as remediation

    source = inspect.getsource(remediation).lower()
    for forbidden in (
        "requests",
        "urllib.request",
        "socket",
        "http.client",
        "raw_request",
        "raw_response",
        "credentials",
        "source_code",
    ):
        assert forbidden not in source
