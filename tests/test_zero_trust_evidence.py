from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import hmac
import json

import pytest

from sentinel.zero_trust.evidence import EvidenceRedactionError, create_redacted_finding_envelope


_EVIDENCE_HMAC_KEY = b"local-customer-evidence-hmac-key-for-tests"


def test_creates_a_safe_envelope_from_a_raw_scanner_finding():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature"
    finding = {
        "title": "Potential authorization control weakness",
        "category": "authorization",
        "severity": "high",
        "endpoint": "https://uat.example.test/api/accounts/42?access_token=top-secret&page=2#details",
        "evidence": ["ownership marker was returned", b"role matrix mismatch"],
        "request": "GET /api/accounts/42?access_token=top-secret HTTP/1.1\\r\\nAuthorization: Bearer abc123\\r\\nCookie: session=abc",
        "response": f"HTTP/1.1 200 OK\\r\\nSet-Cookie: session=abc\\r\\n{{\"token\": \"{jwt}\"}}",
        "authorization": "Bearer abc123",
        "password": "correct-horse-battery-staple",
        "api_key": "api-key-value",
        "session": "session-value",
        "token": jwt,
    }

    envelope = create_redacted_finding_envelope(
        finding,
        observed_at=datetime(2026, 7, 18, 9, 30, tzinfo=timezone.utc),
        evidence_hmac_key=_EVIDENCE_HMAC_KEY,
    )
    payload = envelope.to_dict()
    encoded = json.dumps(payload, sort_keys=True)

    assert payload == {
        "schema_version": "zero-trust-finding.v1",
        "title": "Potential authorization control weakness",
        "category": "authorization",
        "severity": "high",
        "endpoint_path": "/api/{segment}/{segment}",
        "observed_at": "2026-07-18T09:30:00Z",
        "evidence_hmac_sha256": [
            hmac.new(_EVIDENCE_HMAC_KEY, b"ownership marker was returned", sha256).hexdigest(),
            hmac.new(_EVIDENCE_HMAC_KEY, b"role matrix mismatch", sha256).hexdigest(),
        ],
    }
    for forbidden in (
        "top-secret",
        "abc123",
        "correct-horse-battery-staple",
        "api-key-value",
        "session-value",
        jwt,
        "GET /api/accounts",
        "HTTP/1.1 200 OK",
    ):
        assert forbidden not in encoded


def test_redacts_secrets_that_are_accidentally_placed_in_safe_metadata():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.signature"
    envelope = create_redacted_finding_envelope(
        {
            "title": (
                f"Authorization: Bearer bearer-secret; password=hunter2; api_key=api-secret; "
                f"cookie=cookie-secret; set-cookie=set-cookie-secret; session=session-secret; "
                f"token=token-secret; jwt={jwt}"
            ),
            "category": "authentication",
            "severity": "medium",
            "endpoint": "/login?password=hunter2&next=/home",
            "evidence": "a local marker",
        },
        observed_at=datetime(2026, 7, 18, tzinfo=timezone.utc),
        evidence_hmac_key=_EVIDENCE_HMAC_KEY,
    )
    encoded = json.dumps(envelope.to_dict())

    for secret in (
        "bearer-secret",
        "hunter2",
        "api-secret",
        "cookie-secret",
        "set-cookie-secret",
        "session-secret",
        "token-secret",
        jwt,
    ):
        assert secret not in encoded
    assert envelope.endpoint_path == "/login"
    assert envelope.title == "Potential authentication control weakness"


def test_never_exports_a_scanner_supplied_title_even_when_it_contains_unrecognised_customer_data():
    scanner_title = "Alicia Smith's Acme invoice 004221 can be read by another tenant"
    envelope = create_redacted_finding_envelope(
        {
            "title": scanner_title,
            "category": "authorization",
            "severity": "high",
            "endpoint": "/api/invoices/004221",
            "evidence": "local-only marker",
        },
        evidence_hmac_key=_EVIDENCE_HMAC_KEY,
    )

    exported = json.dumps(envelope.to_dict())

    assert envelope.title == "Potential authorization control weakness"
    assert scanner_title not in exported
    assert "Alicia Smith" not in exported
    assert "Acme" not in exported
    assert envelope.endpoint_path == "/api/{segment}/{segment}"


def test_rejects_a_scanner_controlled_category_outside_the_fixed_taxonomy():
    with pytest.raises(EvidenceRedactionError, match="category is not allowed"):
        create_redacted_finding_envelope(
            {
                "title": "A harmless-looking title",
                "category": "Acme customer escalation for Alice",
                "severity": "medium",
                "endpoint": "/api/orders/42",
            },
            evidence_hmac_key=_EVIDENCE_HMAC_KEY,
        )


def test_replaces_short_human_or_business_identifiers_with_route_shape_segments():
    for endpoint in (
        "/api/customers/Alice-Smith",
        "/api/orders/INV-42",
        "/api/tenants/acme",
    ):
        envelope = create_redacted_finding_envelope(
            {
                "title": "Potential authorization weakness",
                "category": "authorization",
                "severity": "high",
                "endpoint": endpoint,
            },
            evidence_hmac_key=_EVIDENCE_HMAC_KEY,
        )

        exported = json.dumps(envelope.to_dict())
        assert envelope.endpoint_path == "/api/{segment}/{segment}"
        assert endpoint not in exported
        assert "Alice-Smith" not in exported
        assert "INV-42" not in exported
        assert "acme" not in exported


def test_uses_only_the_explicit_safe_output_allowlist():
    envelope = create_redacted_finding_envelope(
        {
            "title": "Verbose error response",
            "category": "information disclosure",
            "severity": "low",
            "endpoint": "/api/health?verbose=true",
            "evidence": "marker",
            "raw_request": "GET /api/health HTTP/1.1",
            "raw_response": "HTTP/1.1 500 Internal Server Error",
            "headers": {"cookie": "session=secret"},
            "body": {"password": "secret"},
            "anything_else": "must never be exported",
        },
        evidence_hmac_key=_EVIDENCE_HMAC_KEY,
    )

    payload = envelope.to_dict()

    assert set(payload) == {
        "schema_version",
        "title",
        "category",
        "severity",
        "endpoint_path",
        "observed_at",
        "evidence_hmac_sha256",
    }
    assert payload["endpoint_path"] == "/api/health"
    assert "secret" not in json.dumps(payload)


@pytest.mark.parametrize(
    "finding",
    [
        None,
        [],
        {},
        {"title": "x", "category": "y", "severity": "urgent", "endpoint": "/x"},
        {"title": "x", "category": "y", "severity": "low", "endpoint": "ftp://uat.example.test/x"},
        {"title": "x\nGET /secret", "category": "y", "severity": "low", "endpoint": "/x"},
        {"title": "x", "category": "y", "severity": "low", "endpoint": "//other.example.test/x"},
        {"title": "x", "category": "y", "severity": "low", "endpoint": "/x", "evidence": {"not": "hashable"}},
    ],
)
def test_rejects_invalid_or_ambiguous_input(finding):
    with pytest.raises(EvidenceRedactionError):
        create_redacted_finding_envelope(finding, evidence_hmac_key=_EVIDENCE_HMAC_KEY)


def test_requires_an_aware_timestamp_when_one_is_supplied():
    finding = {
        "title": "Missing security header",
        "category": "security configuration",
        "severity": "low",
        "endpoint": "/",
    }

    with pytest.raises(EvidenceRedactionError):
        create_redacted_finding_envelope(
            finding,
            observed_at=datetime(2026, 7, 18),
            evidence_hmac_key=_EVIDENCE_HMAC_KEY,
        )


def test_requires_a_customer_local_hmac_key_and_never_exports_it():
    finding = {
        "title": "Missing security header",
        "category": "security configuration",
        "severity": "low",
        "endpoint": "/health",
        "evidence": "the local evidence value",
    }

    with pytest.raises(EvidenceRedactionError, match="hmac"):
        create_redacted_finding_envelope(finding)

    one = create_redacted_finding_envelope(finding, evidence_hmac_key=b"a" * 32).to_dict()
    two = create_redacted_finding_envelope(finding, evidence_hmac_key=b"b" * 32).to_dict()

    assert one["evidence_hmac_sha256"] != two["evidence_hmac_sha256"]
    assert "the local evidence value" not in json.dumps(one)
