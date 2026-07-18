"""Customer-local execution boundary for a zero-trust test runner.

The runner intentionally does *not* know customer credentials.  A customer
supplies an executor closure that obtains any test-only credentials locally
(for example from its own vault).  This module checks a signed permit before
calling that closure and reduces any returned finding to a redacted envelope
before returning it to a caller that may export it.

It is a library boundary, not a replacement for a customer-operated network
egress proxy.  Deployment must still prevent an untrusted scanner process
from bypassing this library and talking to a target directly.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from sentinel.zero_trust.evidence import RedactedFindingEnvelope, create_redacted_finding_envelope
from sentinel.zero_trust.policy import Permit, PermitEvaluator


class LocalRunnerError(RuntimeError):
    """Base error for a customer-local runner that refuses to act."""


class RunnerClosedError(LocalRunnerError):
    """Raised after a runner has discarded its one-run permit."""


class RunnerRevokedError(LocalRunnerError):
    """Raised when the local revocation source says the run must stop."""


class RunnerExecutionError(LocalRunnerError):
    """Raised when a local executor does not return a valid finding shape."""


LocalExecutor = Callable[[str, str], Mapping[str, Any] | None]
RevocationChecker = Callable[[], bool]


@dataclass(frozen=True)
class LocalExecutionReceipt:
    """A non-location receipt for one permit-authorized local action."""

    permit_id: str
    request_number: int
    remaining_requests: int
    method: str

    def to_dict(self) -> dict[str, str | int]:
        """Return the allowlisted local execution metadata."""
        return {
            "permit_id": self.permit_id,
            "request_number": self.request_number,
            "remaining_requests": self.remaining_requests,
            "method": self.method,
        }


@dataclass(frozen=True)
class LocalExecution:
    """Privacy-safe result of one local action.

    This type deliberately has no raw request, raw response, credential, or
    scanner-result field. Its receipt omits hostname and path, and its only
    finding output is the strictly allowlisted ``RedactedFindingEnvelope``.
    """

    receipt: LocalExecutionReceipt
    envelope: RedactedFindingEnvelope | None


class LocalRunner:
    """Execute customer-local actions under a verified, short-lived permit.

    ``is_revoked`` is intentionally a local dependency.  A production runner
    should back it with an authenticated, customer-controlled emergency stop
    plus a control-plane revocation feed. It is required rather than defaulted
    so callers must consciously supply a stop source. Failure to read that
    source is treated as a stop, never as permission to continue.
    """

    def __init__(
        self,
        *,
        permit: Permit,
        evaluator: PermitEvaluator,
        evidence_hmac_key: bytes | bytearray,
        is_revoked: RevocationChecker,
    ) -> None:
        if not isinstance(permit, Permit):
            raise TypeError("permit must be a Permit")
        if not isinstance(evaluator, PermitEvaluator):
            raise TypeError("evaluator must be a PermitEvaluator")
        if not isinstance(evidence_hmac_key, (bytes, bytearray)) or len(evidence_hmac_key) < 32:
            raise ValueError("evidence_hmac_key must be at least 32 customer-local bytes")
        if not callable(is_revoked):
            raise TypeError("is_revoked must be callable")
        self._permit: Permit | None = permit
        self._evaluator = evaluator
        self._evidence_hmac_key: bytes | None = bytes(evidence_hmac_key)
        self._is_revoked = is_revoked
        self._closed = False

    def execute(
        self,
        *,
        method: str,
        url: str,
        executor: LocalExecutor,
    ) -> LocalExecution:
        """Check local revocation and scope before a customer-local action.

        The executor is invoked only after the permit evaluator reserves a
        request.  It may use local credentials through a closure, but those
        values are never accepted, retained, logged, or returned by this
        runner.  A returned raw finding is immediately reduced to a redacted
        envelope.
        """
        permit = self._require_open()
        self._raise_if_revoked()
        if not callable(executor):
            raise RunnerExecutionError("executor must be callable")

        # This is deliberately immediately before local egress.  A real
        # deployment additionally routes the executor through a mandatory
        # network proxy which repeats this decision outside the process.
        decision = self._evaluator.evaluate(permit, method=method, url=url)
        receipt = LocalExecutionReceipt(
            permit_id=decision.permit_id,
            request_number=decision.request_number,
            remaining_requests=decision.remaining_requests,
            method=decision.method,
        )
        self._raise_if_revoked()
        try:
            raw_finding = executor(method, url)
        except Exception:
            # A scanner exception may contain a URL, cookie, request body, or
            # customer test data.  Do not preserve it as an exception cause
            # where an upstream logger could export it.
            raise RunnerExecutionError("local executor failed") from None

        # Revocation cannot undo an already-started executor; the mandatory
        # proxy remains necessary for that. It can, however, stop further
        # local processing or export after a stop arrives during execution.
        self._raise_if_revoked()
        if raw_finding is None:
            return LocalExecution(receipt=receipt, envelope=None)
        if not isinstance(raw_finding, Mapping):
            raise RunnerExecutionError("local executor returned an invalid finding")
        try:
            if self._evidence_hmac_key is None:
                raise RunnerExecutionError("local runner is closed")
            envelope = create_redacted_finding_envelope(
                raw_finding,
                evidence_hmac_key=self._evidence_hmac_key,
            )
        except RunnerExecutionError:
            raise
        except Exception:
            # Do not include scanner material in an exception: it may contain
            # a token, cookie, response body, or test data.
            raise RunnerExecutionError("local finding could not be safely redacted") from None
        self._raise_if_revoked()
        return LocalExecution(receipt=receipt, envelope=envelope)

    def close(self) -> None:
        """Discard execution authority after a run completes or is stopped."""
        self._permit = None
        self._evidence_hmac_key = None
        self._closed = True

    def _require_open(self) -> Permit:
        if self._closed or self._permit is None:
            raise RunnerClosedError("local runner is closed")
        return self._permit

    def _raise_if_revoked(self) -> None:
        try:
            revoked = bool(self._is_revoked())
        except Exception:
            self.close()
            raise RunnerRevokedError("unable to confirm local run authorization") from None
        if revoked:
            self.close()
            raise RunnerRevokedError("local run was revoked")
