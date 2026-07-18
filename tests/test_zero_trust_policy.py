"""Tests for the customer-local, zero-trust request policy.

These are deliberately pure unit tests: the policy has no HTTP client and no
customer-secret handling.  A caller must ask the evaluator before sending a
request, and a successful decision consumes one local budget unit.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.zero_trust import policy as policy_module
from sentinel.zero_trust.policy import (
    Permit,
    PermitEvaluator,
    PermitSignatureError,
    PermitValidationError,
    PolicyDeniedError,
    generate_ed25519_keypair,
    public_verification_key_from_private,
)


PRIVATE_KEY, PUBLIC_KEY = generate_ed25519_keypair()
START = datetime(2026, 7, 18, 10, 0, tzinfo=timezone.utc)
END = START + timedelta(hours=1)


@pytest.fixture(autouse=True)
def policy_clock(monkeypatch):
    """The evaluator reads its own clock; callers cannot supply one per request."""
    current = [START + timedelta(minutes=1)]
    monkeypatch.setattr(policy_module, "_current_time", lambda: current[0])
    return current


def issue_permit(**overrides: object) -> Permit:
    values: dict[str, object] = {
        "permit_id": "sandbox-run-001",
        "allowed_hosts": ("app.customer.test", "api.customer.test"),
        "allowed_methods": ("GET", "POST"),
        "allowed_path_prefixes": ("/api", "/health"),
        "not_before": START,
        "expires_at": END,
        "request_budget": 2,
        "private_signing_key": PRIVATE_KEY,
    }
    values.update(overrides)
    return Permit.issue(**values)  # type: ignore[arg-type]


def evaluator() -> PermitEvaluator:
    return PermitEvaluator(PUBLIC_KEY)


def test_signed_permit_allows_an_exact_https_request_and_reserves_budget():
    permit = issue_permit()

    decision = evaluator().evaluate(
        permit,
        method="get",
        url="https://APP.customer.test:443/api/users",
    )

    assert decision.permit_id == "sandbox-run-001"
    assert decision.method == "GET"
    assert decision.host == "app.customer.test"
    assert decision.path == "/api/users"
    assert decision.request_number == 1
    assert decision.remaining_requests == 1


def test_signature_is_stable_for_equivalent_unordered_scope_inputs():
    first = issue_permit(
        allowed_hosts=("api.customer.test", "app.customer.test"),
        allowed_methods=("POST", "GET"),
        allowed_path_prefixes=("/health", "/api"),
    )
    second = issue_permit(
        allowed_hosts=("app.customer.test", "api.customer.test"),
        allowed_methods=("GET", "POST"),
        allowed_path_prefixes=("/api", "/health"),
    )

    assert first.canonical_payload() == second.canonical_payload()
    assert first.signature == second.signature


def test_safe_serialization_contains_only_signed_fields_and_signature():
    permit = issue_permit()
    serialized = permit.to_dict()

    assert serialized == {
        "version": 1,
        "permit_id": "sandbox-run-001",
        "allowed_hosts": ["api.customer.test", "app.customer.test"],
        "allowed_methods": ["GET", "POST"],
        "allowed_path_prefixes": ["/api", "/health"],
        "not_before": "2026-07-18T10:00:00.000000Z",
        "expires_at": "2026-07-18T11:00:00.000000Z",
        "request_budget": 2,
        "signature": permit.signature,
    }


def test_customer_runner_can_parse_and_verify_a_serialized_permit_without_a_private_key():
    original = issue_permit()

    parsed = Permit.from_dict(original.to_dict())
    decision = evaluator().evaluate(
        parsed,
        method="GET",
        url="https://app.customer.test/api/users",
    )

    assert parsed.to_dict() == original.to_dict()
    assert decision.permit_id == original.permit_id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("version", 2),
        ("version", True),
        ("not_before", "2026-07-18T10:00:00Z"),
        ("expires_at", "2026-07-18T11:00:00.000000+00:00"),
        ("allowed_hosts", "app.customer.test"),
        ("signature", None),
    ],
)
def test_serialized_permit_rejects_ambiguous_or_invalid_values(field, value):
    payload = dict(issue_permit().to_dict())
    payload[field] = value

    with pytest.raises(PermitValidationError):
        Permit.from_dict(payload)


def test_serialized_permit_rejects_unknown_fields():
    payload = dict(issue_permit().to_dict())
    payload["private_key"] = "must-not-be-accepted"

    with pytest.raises(PermitValidationError):
        Permit.from_dict(payload)


@pytest.mark.parametrize(
    "tampered",
    [
        lambda permit: replace(permit, request_budget=99),
        lambda permit: replace(permit, allowed_hosts=("attacker.test",)),
        lambda permit: replace(permit, allowed_methods=("DELETE",)),
        lambda permit: replace(permit, allowed_path_prefixes=("/admin",)),
        lambda permit: replace(permit, expires_at=END + timedelta(days=1)),
    ],
)
def test_tampered_permit_fails_closed_before_it_can_authorize_a_request(tampered):
    permit = tampered(issue_permit())

    with pytest.raises(PermitSignatureError):
        evaluator().evaluate(
            permit,
            method="GET",
            url="https://app.customer.test/api/users",
        )


@pytest.mark.parametrize("signature", [None, "", "0" * 64, "not-a-signature"])
def test_missing_or_invalid_signature_fails_closed(signature):
    permit = replace(issue_permit(), signature=signature)

    with pytest.raises(PermitSignatureError):
        evaluator().evaluate(
            permit,
            method="GET",
            url="https://app.customer.test/api/users",
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://app.customer.test/api/users",
        "ftp://app.customer.test/api/users",
        "https://app.customer.test:8443/api/users",
        "https://user:password@app.customer.test/api/users",
        "https://app.customer.test@attacker.test/api/users",
        "https://attacker.test/api/users",
        "https://app.customer.test.evil/api/users",
        "https://app.customer.test/%2e%2e/admin",
        "https://app.customer.test/api/%252e%252e/admin",
        "https://app.customer.test/api/users?delete=true",
        "https://app.customer.test/api/café",
    ],
)
def test_unsafe_or_off_scope_urls_fail_closed(url):
    with pytest.raises(PolicyDeniedError):
        evaluator().evaluate(
            issue_permit(),
            method="GET",
            url=url,
        )


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("DELETE", "https://app.customer.test/api/users/1"),
        ("GET", "https://app.customer.test/admin"),
        ("GET", "https://app.customer.test/apiv2/users"),
    ],
)
def test_wrong_method_or_path_fails_closed(method, url):
    with pytest.raises(PolicyDeniedError):
        evaluator().evaluate(
            issue_permit(),
            method=method,
            url=url,
        )


def test_path_prefix_boundary_allows_prefix_root_and_descendants_only():
    permit = issue_permit(request_budget=2)
    local_evaluator = evaluator()

    root = local_evaluator.evaluate(
        permit,
        method="GET",
        url="https://app.customer.test/api",
    )
    child = local_evaluator.evaluate(
        permit,
        method="GET",
        url="https://app.customer.test/api/v1/users",
    )

    assert (root.request_number, child.request_number) == (1, 2)


def test_trailing_slash_prefix_does_not_broaden_to_its_parent_path():
    permit = issue_permit(allowed_path_prefixes=("/api/",), request_budget=1)
    local_evaluator = evaluator()

    with pytest.raises(PolicyDeniedError):
        local_evaluator.evaluate(
            permit,
            method="GET",
            url="https://app.customer.test/api",
        )
    decision = local_evaluator.evaluate(
        permit,
        method="GET",
        url="https://app.customer.test/api/users",
    )

    assert decision.path == "/api/users"


def test_not_before_and_expiry_windows_fail_closed(policy_clock):
    permit = issue_permit()

    policy_clock[0] = START - timedelta(microseconds=1)
    with pytest.raises(PolicyDeniedError, match="not active"):
        evaluator().evaluate(
            permit,
            method="GET",
            url="https://app.customer.test/api/users",
        )
    policy_clock[0] = END
    with pytest.raises(PolicyDeniedError, match="expired"):
        evaluator().evaluate(
            permit,
            method="GET",
            url="https://app.customer.test/api/users",
        )


def test_budget_exhaustion_is_fail_closed_and_does_not_grant_a_third_request():
    permit = issue_permit(request_budget=2)
    local_evaluator = evaluator()

    local_evaluator.evaluate(permit, method="GET", url="https://app.customer.test/api/one")
    local_evaluator.evaluate(permit, method="POST", url="https://api.customer.test/api/two")

    with pytest.raises(PolicyDeniedError, match="budget"):
        local_evaluator.evaluate(
            permit,
            method="GET",
            url="https://app.customer.test/api/three",
        )


def test_rejected_request_does_not_consume_a_budget_unit():
    permit = issue_permit(request_budget=1)
    local_evaluator = evaluator()

    with pytest.raises(PolicyDeniedError):
        local_evaluator.evaluate(
            permit,
            method="GET",
            url="https://attacker.test/api/users",
        )
    decision = local_evaluator.evaluate(
        permit,
        method="GET",
        url="https://app.customer.test/api/users",
    )

    assert decision.request_number == 1
    assert decision.remaining_requests == 0


@pytest.mark.parametrize(
    "override",
    [
        {"allowed_hosts": ("https://app.customer.test",)},
        {"allowed_methods": ("GET\\nPOST",)},
        {"allowed_methods": ("ſET",)},
        {"allowed_path_prefixes": ("admin",)},
        {"allowed_path_prefixes": ("/api/café",)},
        {"request_budget": 0},
        {"not_before": END, "expires_at": START},
    ],
)
def test_invalid_permit_shape_cannot_be_signed(override):
    with pytest.raises(PermitValidationError):
        issue_permit(**override)


@pytest.mark.parametrize("key", ["", "not base64", "A" * 42, "A" * 44])
def test_noncanonical_ed25519_key_material_is_rejected(key):
    with pytest.raises(PermitValidationError):
        PermitEvaluator(key)


def test_wrong_public_key_cannot_validate_a_permit():
    _, other_public_key = generate_ed25519_keypair()

    with pytest.raises(PermitSignatureError):
        PermitEvaluator(other_public_key).evaluate(
            issue_permit(),
            method="GET",
            url="https://app.customer.test/api/users",
        )


def test_public_key_can_be_derived_without_exposing_private_key_material():
    private_key, public_key = generate_ed25519_keypair()

    assert public_verification_key_from_private(private_key) == public_key


def test_evaluator_does_not_accept_a_caller_controlled_time_override():
    with pytest.raises(TypeError):
        evaluator().evaluate(
            issue_permit(),
            method="GET",
            url="https://app.customer.test/api/users",
            now=START + timedelta(minutes=1),
        )
