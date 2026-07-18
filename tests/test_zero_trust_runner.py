from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel.zero_trust import policy as policy_module
from sentinel.zero_trust.policy import (
    Permit,
    PermitEvaluator,
    PolicyDeniedError,
    generate_ed25519_keypair,
)
from sentinel.zero_trust.runner import LocalRunner, RunnerClosedError, RunnerExecutionError, RunnerRevokedError


_NOW = datetime(2026, 7, 18, 10, 0, tzinfo=timezone.utc)
_PRIVATE_KEY, _PUBLIC_KEY = generate_ed25519_keypair()
_EVIDENCE_HMAC_KEY = b"customer-local-evidence-hmac-key-for-runner-tests"


@pytest.fixture(autouse=True)
def runner_clock(monkeypatch):
    monkeypatch.setattr(policy_module, "_current_time", lambda: _NOW)


def _permit() -> Permit:
    return Permit.issue(
        permit_id="permit-123",
        allowed_hosts=["uat.example.test"],
        allowed_methods=["GET", "POST"],
        allowed_path_prefixes=["/api/", "/health"],
        not_before=_NOW - timedelta(minutes=1),
        expires_at=_NOW + timedelta(minutes=5),
        request_budget=2,
        private_signing_key=_PRIVATE_KEY,
    )


def _runner(*, revoked=lambda: False) -> LocalRunner:
    return LocalRunner(
        permit=_permit(),
        evaluator=PermitEvaluator(_PUBLIC_KEY),
        evidence_hmac_key=_EVIDENCE_HMAC_KEY,
        is_revoked=revoked,
    )


def test_runner_keeps_raw_result_and_customer_secret_local_and_exports_only_redacted_evidence():
    runner = _runner()
    customer_secret = "customer-test-only-secret"
    calls: list[tuple[str, str]] = []

    def local_executor(method: str, url: str):
        # The executor represents a process inside the customer boundary. The
        # secret is captured locally rather than passed to or stored by the
        # runner/control plane.
        calls.append((method, url))
        assert customer_secret == "customer-test-only-secret"
        return {
            "title": "Broken object authorization",
            "category": "authorization",
            "severity": "high",
            "endpoint": url + "?access_token=" + customer_secret,
            "evidence": "local role-matrix marker " + customer_secret,
            "raw_request": "Authorization: Bearer " + customer_secret,
            "raw_response": '{"token": "' + customer_secret + '"}',
        }

    execution = runner.execute(
        method="GET",
        url="https://uat.example.test/api/accounts/42",
        executor=local_executor,
    )

    assert calls == [("GET", "https://uat.example.test/api/accounts/42")]
    assert execution.receipt.request_number == 1
    assert execution.envelope is not None
    exported = execution.envelope.to_dict()
    assert exported["endpoint_path"] == "/api/{segment}/{segment}"
    assert customer_secret not in str(exported)
    assert not hasattr(execution, "raw_result")


def test_runner_exposes_only_a_non_location_receipt_and_a_redacted_envelope():
    runner = _runner()
    customer_identifier = "Alice-Smith"

    execution = runner.execute(
        method="GET",
        url=f"https://uat.example.test/api/customers/{customer_identifier}",
        executor=lambda method, url: {
            "title": "Potential authorization weakness",
            "category": "authorization",
            "severity": "high",
            "endpoint": url,
        },
    )

    assert not hasattr(execution, "decision")
    assert customer_identifier not in str(execution.receipt)
    assert customer_identifier not in str(execution.envelope.to_dict())
    assert execution.receipt.to_dict() == {
        "permit_id": "permit-123",
        "request_number": 1,
        "remaining_requests": 1,
        "method": "GET",
    }


def test_runner_checks_revocation_before_local_executor_is_called():
    runner = _runner(revoked=lambda: True)
    called = False

    def local_executor(method: str, url: str):
        nonlocal called
        called = True
        return None

    with pytest.raises(RunnerRevokedError):
        runner.execute(
            method="GET",
            url="https://uat.example.test/api/accounts/42",
            executor=local_executor,
        )

    assert called is False


def test_runner_stops_before_export_when_revoked_during_a_local_executor():
    answers = iter((False, False, True))
    runner = _runner(revoked=lambda: next(answers))

    with pytest.raises(RunnerRevokedError):
        runner.execute(
            method="GET",
            url="https://uat.example.test/api/accounts/42",
            executor=lambda method, url: {
                "title": "Potential authorization weakness",
                "category": "authorization",
                "severity": "high",
                "endpoint": url,
            },
        )


def test_runner_fails_closed_before_egress_when_policy_denies_request():
    runner = _runner()
    called = False

    def local_executor(method: str, url: str):
        nonlocal called
        called = True
        return None

    with pytest.raises(PolicyDeniedError):
        runner.execute(
            method="DELETE",
            url="https://uat.example.test/api/accounts/42",
            executor=local_executor,
        )

    assert called is False


def test_runner_discards_execution_authority_when_closed():
    runner = _runner()
    runner.close()

    with pytest.raises(RunnerClosedError):
        runner.execute(
            method="GET",
            url="https://uat.example.test/api/accounts/42",
            executor=lambda method, url: None,
        )


def test_runner_returns_no_envelope_for_a_local_execution_without_a_finding():
    runner = _runner()

    execution = runner.execute(
        method="GET",
        url="https://uat.example.test/health",
        executor=lambda method, url: None,
    )

    assert execution.envelope is None
    assert execution.receipt.remaining_requests == 1


def test_runner_requires_a_customer_local_evidence_hmac_key():
    with pytest.raises(ValueError, match="evidence_hmac_key"):
        LocalRunner(
            permit=_permit(),
            evaluator=PermitEvaluator(_PUBLIC_KEY),
            evidence_hmac_key=b"too-short",
            is_revoked=lambda: False,
        )


def test_runner_requires_an_explicit_local_revocation_source():
    with pytest.raises(TypeError, match="is_revoked"):
        LocalRunner(
            permit=_permit(),
            evaluator=PermitEvaluator(_PUBLIC_KEY),
            evidence_hmac_key=_EVIDENCE_HMAC_KEY,
        )


def test_runner_does_not_attach_a_secret_bearing_executor_exception():
    runner = _runner()
    secret = "customer-secret-must-not-leave-local-executor"

    def local_executor(method: str, url: str):
        raise RuntimeError(f"request failed with {secret}")

    with pytest.raises(RunnerExecutionError) as captured:
        runner.execute(
            method="GET",
            url="https://uat.example.test/api/accounts/42",
            executor=local_executor,
        )

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_runner_does_not_attach_a_secret_bearing_revocation_checker_exception():
    secret = "revocation-feed-token-must-stay-local"

    def unavailable_revocation_source() -> bool:
        raise RuntimeError(f"feed rejected {secret}")

    runner = _runner(revoked=unavailable_revocation_source)

    with pytest.raises(RunnerRevokedError) as captured:
        runner.execute(
            method="GET",
            url="https://uat.example.test/api/accounts/42",
            executor=lambda method, url: None,
        )

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None
