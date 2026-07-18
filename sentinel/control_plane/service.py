"""Signed contracts and short-lived leases for safe scan automation.

This module is deliberately a small, fail-closed control plane.  It does not
turn a scan into a general-purpose network capability: the first supported
contract recipe is Tier-A, same-origin recon only.  Higher-risk engines stay
blocked until their traffic can be forced through an independently enforced
egress proxy and their rollback/fixture controls exist.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import NoReturn
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from sentinel.config import settings
from sentinel.db.models import (
    ActionLease,
    ActionLeaseStatus,
    ActionTier,
    LeaseAction,
    ScanContract,
    ScanContractStatus,
    ScanSession,
    ScanStatus,
    TargetRegistration,
)
from sentinel.security import audit_log
from sentinel.security.guardrails import normalize_host
from sentinel.zero_trust.policy import (
    Permit,
    PermitValidationError,
    public_verification_key_from_private,
)

_POLICY_VERSION = 1
_HARD_MAX_LEASE_SECONDS = 15 * 60


class ControlPlaneError(Exception):
    """Base error for authorization-control-plane enforcement."""


class ControlPlaneConfigurationError(ControlPlaneError):
    pass


class ContractPolicyError(ControlPlaneError):
    pass


class ContractIntegrityError(ControlPlaneError):
    pass


class ContractStateError(ControlPlaneError):
    pass


class LeaseStateError(ControlPlaneError):
    pass


class LeaseBudgetExceededError(ControlPlaneError):
    pass


class ReconRequestDenied(ControlPlaneError):
    """A recon URL is not inside the contract's exact HTTPS origin."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    """SQLite may round-trip timezone-aware values as naive timestamps."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _as_utc(value).isoformat(timespec="microseconds")


def _signing_key() -> bytes:
    key = settings.control_plane_signing_key
    if not key:
        raise ControlPlaneConfigurationError(
            "SENTINEL_CONTROL_PLANE_SIGNING_KEY must be configured for contract-backed runs"
        )
    return key.encode("utf-8")


def _runner_permit_private_key() -> str:
    """Return the Ed25519 issuer key without ever persisting or logging it."""
    key = settings.runner_permit_private_key
    if not key:
        raise ControlPlaneConfigurationError(
            "SENTINEL_RUNNER_PERMIT_PRIVATE_KEY must be configured to issue customer-local permits"
        )
    return key


def _customer_authorization_reference_hash(reference: str | None) -> str | None:
    """Store only a keyed digest of an out-of-band customer approval record.

    An official email or a customer ticket is a human authorization artifact.
    The control plane needs a durable binding before it issues a local-runner
    permit, but never needs the email body, recipient list, or credentials.
    HMAC also prevents a database reader from dictionary-matching a short
    ticket reference against the stored digest.
    """
    if reference is None:
        return None
    if not isinstance(reference, str):
        raise ContractPolicyError("customer authorization reference must be text")
    normalized = reference.strip()
    if (
        not normalized
        or len(normalized) > 512
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized)
    ):
        raise ContractPolicyError("customer authorization reference is invalid")
    return hmac.new(
        _signing_key(),
        b"customer-authorization-reference:\x00" + normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _coerce_tier(value: ActionTier | str) -> ActionTier:
    try:
        return value if isinstance(value, ActionTier) else ActionTier(value)
    except ValueError as exc:
        raise ContractPolicyError(f"Unknown action tier '{value}'") from exc


def _target_for_contract(db: Session, contract: ScanContract) -> TargetRegistration:
    target = db.get(TargetRegistration, contract.target_id)
    if target is None:
        raise ContractIntegrityError(f"Contract {contract.id} refers to a missing target")
    return target


def _policy_document(db: Session, contract: ScanContract) -> bytes:
    target = _target_for_contract(db, contract)
    policy = {
        "version": _POLICY_VERSION,
        "contract_id": contract.id,
        "target_registration_id": contract.target_id,
        "target_domain": normalize_host(target.domain),
        "approved_by": contract.approved_by,
        "allowed_tier": contract.allowed_tier.value,
        "not_before": _iso(contract.not_before),
        "expires_at": _iso(contract.expires_at),
        "max_scan_sessions": contract.max_scan_sessions,
        "max_requests": contract.max_requests,
    }
    # Keep the canonical representation of pre-existing signed contracts
    # unchanged. New contracts that bind a customer authorization artifact
    # include the digest, while legacy contracts without one retain their
    # original signature and simply cannot receive a customer-runner permit.
    if contract.customer_authorization_reference_hash is not None:
        policy["customer_authorization_reference_hash"] = (
            contract.customer_authorization_reference_hash
        )
    return json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_policy(document: bytes) -> str:
    return hashlib.sha256(document).hexdigest()


def _sign_policy(document: bytes) -> str:
    return hmac.new(_signing_key(), document, hashlib.sha256).hexdigest()


def _verify_contract_integrity(db: Session, contract: ScanContract) -> None:
    """Verify immutable policy fields before every issuance or action."""
    document = _policy_document(db, contract)
    expected_hash = _digest_policy(document)
    expected_signature = _sign_policy(document)
    if not hmac.compare_digest(contract.policy_hash, expected_hash) or not hmac.compare_digest(
        contract.policy_signature, expected_signature
    ):
        raise ContractIntegrityError(
            f"Scan contract {contract.id} integrity check failed; its signed policy was modified"
        )


def _validate_contract_shape(
    *,
    registration: TargetRegistration,
    allowed_tier: ActionTier,
    expires_at: datetime,
    max_scan_sessions: int,
    max_requests: int,
    not_before: datetime,
) -> None:
    if not registration.is_active or not registration.is_ownership_verified:
        raise ContractPolicyError(
            "A contract can only be issued for an active, Phase-0 ownership-verified target"
        )
    if allowed_tier != ActionTier.TIER_A:
        raise ContractPolicyError(
            "Tier B contracts are blocked until fixture, rollback, tenant-identity, and "
            "independent egress-proxy controls exist"
        )
    if _as_utc(not_before) > _as_utc(expires_at):
        raise ContractPolicyError("Contract expiry must be later than its activation time")
    if _as_utc(expires_at) <= _now():
        raise ContractPolicyError("Contract expiry must be in the future")
    if max_scan_sessions < 1:
        raise ContractPolicyError("max_scan_sessions must be at least 1")
    if max_requests < 1:
        raise ContractPolicyError("max_requests must be at least 1")


def create_scan_contract(
    db: Session,
    *,
    registration: TargetRegistration,
    approved_by: str,
    allowed_tier: ActionTier | str,
    expires_at: datetime,
    max_scan_sessions: int = 1,
    max_requests: int = 100,
    not_before: datetime | None = None,
    customer_authorization_reference: str | None = None,
) -> ScanContract:
    """Create one immutable signed Tier-A recon contract."""
    tier = _coerce_tier(allowed_tier)
    starts_at = _as_utc(not_before or _now())
    ends_at = _as_utc(expires_at)
    _validate_contract_shape(
        registration=registration,
        allowed_tier=tier,
        expires_at=ends_at,
        max_scan_sessions=max_scan_sessions,
        max_requests=max_requests,
        not_before=starts_at,
    )
    if not approved_by.strip():
        raise ContractPolicyError("approved_by is required")
    authorization_reference_hash = _customer_authorization_reference_hash(
        customer_authorization_reference
    )

    contract = ScanContract(
        target_id=registration.id,
        approved_by=approved_by.strip(),
        customer_authorization_reference_hash=authorization_reference_hash,
        allowed_tier=tier,
        not_before=starts_at,
        expires_at=ends_at,
        max_scan_sessions=max_scan_sessions,
        max_requests=max_requests,
        policy_hash="pending",
        policy_signature="pending",
    )
    db.add(contract)
    db.flush()  # Assign the contract id before it becomes part of its policy.
    document = _policy_document(db, contract)
    contract.policy_hash = _digest_policy(document)
    contract.policy_signature = _sign_policy(document)
    db.flush()
    audit_log.record(
        db,
        agent="control_plane",
        action="scan_contract_created",
        payload={
            "contract_id": contract.id,
            "target_id": registration.id,
            "allowed_tier": tier.value,
            "max_scan_sessions": max_scan_sessions,
            "max_requests": max_requests,
            "expires_at": _iso(ends_at),
            "customer_authorization_attested": authorization_reference_hash is not None,
        },
    )
    return contract


def enforce_contract_active(db: Session, contract: ScanContract) -> None:
    """Check signature, Phase 0 target state, lifecycle and validity window."""
    db.flush()
    # A long-running worker may retain an ORM object while an operator
    # revokes the contract in another session. Always read the authoritative
    # row before authorizing another action.
    db.refresh(contract)
    _verify_contract_integrity(db, contract)
    target = _target_for_contract(db, contract)
    db.refresh(target)
    if not target.is_active or not target.is_ownership_verified:
        raise ContractStateError(
            f"Scan contract {contract.id} target is no longer active and ownership verified"
        )
    current = _now()
    if contract.status == ScanContractStatus.REVOKED:
        raise ContractStateError(f"Scan contract {contract.id} has been revoked")
    if _as_utc(contract.not_before) > current:
        raise ContractStateError(f"Scan contract {contract.id} is not active yet")
    if contract.status == ScanContractStatus.EXPIRED or _as_utc(contract.expires_at) <= current:
        if contract.status != ScanContractStatus.EXPIRED:
            contract.status = ScanContractStatus.EXPIRED
            db.flush()
            audit_log.record(
                db,
                agent="control_plane",
                action="scan_contract_expired",
                payload={"contract_id": contract.id},
            )
        raise ContractStateError(f"Scan contract {contract.id} has expired")
    if contract.status != ScanContractStatus.ACTIVE:
        raise ContractStateError(f"Scan contract {contract.id} is not active")


def _lease_lifetime_seconds() -> int:
    configured = settings.control_plane_max_lease_seconds
    if configured < 1:
        raise ControlPlaneConfigurationError("control_plane_max_lease_seconds must be positive")
    return min(configured, _HARD_MAX_LEASE_SECONDS)


def issue_action_lease(
    db: Session, *, contract: ScanContract, requested_tier: ActionTier | str
) -> tuple[ActionLease, str]:
    """Reserve one contract run and return its transient, opaque lease token."""
    tier = _coerce_tier(requested_tier)
    enforce_contract_active(db, contract)
    if tier != ActionTier.TIER_A or tier != contract.allowed_tier:
        raise ContractPolicyError("This control-plane MVP permits only the contract's Tier-A recon recipe")

    # This conditional update is the session-budget concurrency boundary. A
    # second runner can never both observe and consume the last allowance.
    claimed = (
        db.query(ScanContract)
        .filter(
            ScanContract.id == contract.id,
            ScanContract.status == ScanContractStatus.ACTIVE,
            ScanContract.issued_lease_count < ScanContract.max_scan_sessions,
        )
        .update(
            {ScanContract.issued_lease_count: ScanContract.issued_lease_count + 1},
            synchronize_session=False,
        )
    )
    if claimed != 1:
        raise LeaseStateError(f"Scan contract {contract.id} has no remaining scan-session allowance")
    db.flush()
    db.refresh(contract)

    issued_at = _now()
    expires_at = min(
        _as_utc(contract.expires_at),
        issued_at + timedelta(seconds=_lease_lifetime_seconds()),
    )
    token = secrets.token_urlsafe(32)
    lease = ActionLease(
        id=str(uuid.uuid4()),
        contract_id=contract.id,
        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        requested_tier=tier,
        max_requests=contract.max_requests,
        revocation_epoch=contract.revocation_epoch,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    db.add(lease)
    db.flush()
    audit_log.record(
        db,
        agent="control_plane",
        action="action_lease_issued",
        payload={
            "lease_id": lease.id,
            "contract_id": contract.id,
            "requested_tier": tier.value,
            "expires_at": _iso(expires_at),
        },
    )
    return lease, token


def issue_customer_runner_permit(
    db: Session,
    *,
    contract: ScanContract,
    allowed_path_prefixes: tuple[str, ...] | list[str],
) -> tuple[Permit, str]:
    """Issue a short-lived, asymmetric permit for a customer-hosted runner.

    The customer receives a signed policy and a non-secret issuer-key ID—never
    either control-plane signing secret or a raw action-lease token.  The
    runner's public verification key is provisioned separately during
    onboarding and must be pinned locally.  The current vertical slice is
    intentionally Tier-A GET/HEAD only; it enables a customer-local runner
    foundation, not unattended active exploitation.  A normal ActionLease is
    still reserved so the contract's session budget cannot be bypassed by
    minting local permits.
    """
    private_key = _runner_permit_private_key()
    try:
        public_key = public_verification_key_from_private(private_key)
    except PermitValidationError:
        # Treat malformed key material as deployment configuration, not an
        # unexpected API error. Never preserve crypto/key diagnostics in an
        # exception chain that a web server may log.
        raise ControlPlaneConfigurationError(
            "SENTINEL_RUNNER_PERMIT_PRIVATE_KEY is invalid"
        ) from None
    enforce_contract_active(db, contract)
    if contract.allowed_tier != ActionTier.TIER_A:
        raise ContractPolicyError("Customer-local permits currently require a Tier-A contract")
    if not contract.customer_authorization_reference_hash:
        raise ContractPolicyError(
            "A customer authorization reference is required before issuing a customer-local permit"
        )

    target = _target_for_contract(db, contract)
    prefixes = tuple(allowed_path_prefixes)
    # Validate caller-controlled path scope before *any* verification egress
    # or contract-session consumption. The preflight object is never returned
    # or recorded.
    try:
        Permit.issue(
            permit_id=f"preflight-{contract.id}",
            allowed_hosts=[normalize_host(target.domain)],
            allowed_methods=["GET", "HEAD"],
            allowed_path_prefixes=prefixes,
            not_before=_now(),
            expires_at=min(
                _as_utc(contract.expires_at),
                _now() + timedelta(seconds=_lease_lifetime_seconds()),
            ),
            request_budget=contract.max_requests,
            private_signing_key=private_key,
        )
    except PermitValidationError as exc:
        raise ContractPolicyError("Customer-local permit path scope is invalid") from exc

    # A permit can later be carried into a customer-local process, so a
    # historical ownership proof is not enough. Re-prove domain control
    # before consuming any contract-run budget or signing its scope.
    from sentinel.phase0 import registry

    fresh_target = registry.run_ownership_verification(db, target.domain)
    if not fresh_target.is_ownership_verified:
        audit_log.record(
            db,
            agent="control_plane",
            action="customer_runner_permit_fresh_ownership_failed",
            payload={"contract_id": contract.id, "target_id": target.id},
        )
        raise ContractStateError("Fresh domain ownership verification failed")
    enforce_contract_active(db, contract)

    lease, _unused_opaque_token = issue_action_lease(
        db,
        contract=contract,
        requested_tier=ActionTier.TIER_A,
    )
    try:
        permit = Permit.issue(
            permit_id=lease.id,
            allowed_hosts=[normalize_host(target.domain)],
            allowed_methods=["GET", "HEAD"],
            allowed_path_prefixes=prefixes,
            not_before=_as_utc(lease.issued_at),
            expires_at=_as_utc(lease.expires_at),
            request_budget=lease.max_requests,
            private_signing_key=private_key,
        )
    except PermitValidationError as exc:  # Defensive: preflight above should make this unreachable.
        lease.status = ActionLeaseStatus.REVOKED
        lease.terminal_at = _now()
        lease.terminal_reason = "customer-local permit signing failed"
        db.flush()
        raise ContractPolicyError("Customer-local permit could not be signed") from exc

    audit_log.record(
        db,
        agent="control_plane",
        action="customer_runner_permit_issued",
        payload={
            "contract_id": contract.id,
            "lease_id": lease.id,
            "allowed_tier": contract.allowed_tier.value,
            "request_budget": lease.max_requests,
            "policy_hash": hashlib.sha256(permit.canonical_payload()).hexdigest(),
            "expires_at": _iso(lease.expires_at),
        },
    )
    issuer_key_id = hashlib.sha256(public_key.encode("ascii")).hexdigest()[:16]
    return permit, issuer_key_id


def activate_lease_for_scan(db: Session, *, lease_token: str, scan_session: ScanSession) -> ActionLease:
    """Bind a one-use lease to exactly one fresh Phase-0 scan session."""
    token_hash = hashlib.sha256(lease_token.encode("utf-8")).hexdigest()
    # Discover the contract first without retaining a lease-row lock. Both
    # activation and revocation then lock in the same order (contract,
    # lease), avoiding a lock-order deadlock.
    candidate = (
        db.query(ActionLease)
        .filter(ActionLease.token_hash == token_hash)
        .one_or_none()
    )
    if candidate is None:
        raise LeaseStateError("Action lease is unknown")
    contract = (
        db.query(ScanContract)
        .filter(ScanContract.id == candidate.contract_id)
        .with_for_update()
        .one_or_none()
    )
    if contract is None:
        raise LeaseStateError("Action lease refers to a missing contract")
    enforce_contract_active(db, contract)
    lease = (
        db.query(ActionLease)
        .filter(ActionLease.id == candidate.id, ActionLease.token_hash == token_hash)
        .with_for_update()
        .one_or_none()
    )
    if lease is None:
        raise LeaseStateError("Action lease is unknown")
    if lease.status != ActionLeaseStatus.ISSUED or lease.scan_session_id is not None:
        raise LeaseStateError("Action lease has already been used or is no longer issuable")
    locked_scan_session = (
        db.query(ScanSession)
        .filter(ScanSession.id == scan_session.id)
        .with_for_update()
        .one_or_none()
    )
    if locked_scan_session is None:
        raise LeaseStateError("Scan session is unknown")
    if _as_utc(lease.expires_at) <= _now():
        lease.status = ActionLeaseStatus.EXPIRED
        lease.terminal_at = _now()
        lease.terminal_reason = "expired before activation"
        db.flush()
        raise LeaseStateError("Action lease expired before activation")
    if (
        locked_scan_session.status != ScanStatus.RUNNING
        or locked_scan_session.contract_id is not None
        or locked_scan_session.target_id != contract.target_id
        or lease.requested_tier != contract.allowed_tier
        or lease.max_requests != contract.max_requests
        or lease.revocation_epoch != contract.revocation_epoch
    ):
        raise LeaseStateError("Action lease cannot be bound to this scan session")

    activated_at = _now()
    claimed = (
        db.query(ActionLease)
        .filter(
            ActionLease.id == lease.id,
            ActionLease.status == ActionLeaseStatus.ISSUED,
            ActionLease.scan_session_id.is_(None),
            ActionLease.revocation_epoch == contract.revocation_epoch,
        )
        .update(
            {
                ActionLease.scan_session_id: locked_scan_session.id,
                ActionLease.status: ActionLeaseStatus.ACTIVE,
                ActionLease.activated_at: activated_at,
            },
            synchronize_session=False,
        )
    )
    if claimed != 1:
        raise LeaseStateError("Action lease changed while it was being activated")
    locked_scan_session.contract_id = contract.id
    locked_scan_session.permitted_action_tier = contract.allowed_tier
    db.flush()
    db.refresh(lease)
    audit_log.record(
        db,
        agent="control_plane",
        action="action_lease_activated",
        payload={
            "lease_id": lease.id,
            "contract_id": contract.id,
            "scan_session_id": locked_scan_session.id,
        },
    )
    return lease


def _halt_for_lease(
    db: Session, scan_session: ScanSession, lease: ActionLease | None, reason: str
) -> NoReturn:
    """Fail closed: end the scan and make further guard checks reject it."""
    if lease is not None and lease.status in {ActionLeaseStatus.ISSUED, ActionLeaseStatus.ACTIVE}:
        lease.status = (
            ActionLeaseStatus.EXPIRED if "expired" in reason else ActionLeaseStatus.REVOKED
        )
        lease.terminal_at = _now()
        lease.terminal_reason = reason
    if scan_session.status == ScanStatus.RUNNING:
        scan_session.status = ScanStatus.HALTED
        scan_session.halted_reason = f"action lease {reason}"
        scan_session.ended_at = _now()
    db.flush()
    audit_log.record(
        db,
        agent="control_plane",
        action="contract_scan_halted",
        payload={
            "scan_session_id": scan_session.id,
            "lease_id": lease.id if lease is not None else None,
            "reason": reason,
        },
    )
    # This is terminal safety state, not an ordinary caller-owned mutation.
    # In particular, a request-reservation context is about to re-raise this
    # exception; without an explicit commit its context manager would roll
    # back the halt and permit a retry to spend the same budget.
    db.commit()
    from sentinel.security.guardrails import ScanHaltedError

    raise ScanHaltedError(
        f"Scan session {scan_session.id} action lease is no longer valid ({reason})"
    )


def enforce_lease_active_for_scan(db: Session, scan_session: ScanSession) -> None:
    """Verify a contract-backed scan still has live internal authority."""
    if scan_session.contract_id is None:
        return
    lease = (
        db.query(ActionLease)
        .filter(ActionLease.scan_session_id == scan_session.id)
        .one_or_none()
    )
    if lease is None:
        _halt_for_lease(db, scan_session, None, "is missing")
    db.refresh(lease)
    contract = db.get(ScanContract, scan_session.contract_id)
    if contract is None or lease.contract_id != scan_session.contract_id:
        _halt_for_lease(db, scan_session, lease, "does not match its contract")
    db.refresh(contract)
    try:
        enforce_contract_active(db, contract)
    except ControlPlaneError as exc:
        _halt_for_lease(db, scan_session, lease, str(exc))
    if lease.status != ActionLeaseStatus.ACTIVE:
        _halt_for_lease(db, scan_session, lease, f"has status '{lease.status.value}'")
    if _as_utc(lease.expires_at) <= _now():
        _halt_for_lease(db, scan_session, lease, "expired")
    if lease.revocation_epoch != contract.revocation_epoch:
        _halt_for_lease(db, scan_session, lease, "was revoked by a newer contract epoch")
    if lease.max_requests != contract.max_requests:
        _halt_for_lease(db, scan_session, lease, "does not match the signed request budget")
    if scan_session.permitted_action_tier != contract.allowed_tier:
        _halt_for_lease(db, scan_session, lease, "does not match the approved action tier")


def _recon_origin_allowed(registration: TargetRegistration, request_url: str) -> bool:
    try:
        parsed = urlparse(request_url)
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme.lower() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or not parsed.hostname
    ):
        return False
    try:
        return normalize_host(parsed.hostname) == normalize_host(registration.domain)
    except Exception:
        return False


def reserve_recon_request(db: Session, *, scan_session: ScanSession, request_url: str) -> None:
    """Atomically reserve a bounded contract action immediately before egress."""
    enforce_lease_active_for_scan(db, scan_session)
    lease = (
        db.query(ActionLease)
        .filter(ActionLease.scan_session_id == scan_session.id)
        .one()
    )
    registration = db.get(TargetRegistration, scan_session.target_id)
    if registration is None or not _recon_origin_allowed(registration, request_url):
        audit_log.record(
            db,
            agent="control_plane",
            action="recon_request_blocked",
            payload={
                "scan_session_id": scan_session.id,
                "lease_id": lease.id,
                "request_hash": hashlib.sha256(request_url.encode("utf-8")).hexdigest(),
                "reason": "request is outside the exact HTTPS contract origin",
            },
        )
        # This is a security decision, not ordinary caller-owned work. The
        # per-request guard raises immediately afterwards, so its context
        # manager would otherwise roll the denial audit entry back and leave
        # no durable record of the blocked egress attempt.
        db.commit()
        raise ReconRequestDenied("Recon request is outside the exact HTTPS contract origin")

    reserved = (
        db.query(ActionLease)
        .filter(
            ActionLease.id == lease.id,
            ActionLease.status == ActionLeaseStatus.ACTIVE,
            ActionLease.requests_used < ActionLease.max_requests,
        )
        .update({ActionLease.requests_used: ActionLease.requests_used + 1}, synchronize_session=False)
    )
    if reserved != 1:
        db.refresh(lease)
        if lease.requests_used >= lease.max_requests:
            _halt_for_lease(
                db,
                scan_session,
                lease,
                f"recon request budget exhausted ({lease.max_requests} requests)",
            )
        enforce_lease_active_for_scan(db, scan_session)
        raise LeaseStateError("Action lease changed while reserving a recon request")
    db.flush()
    db.refresh(lease)
    fingerprint = hashlib.sha256(
        f"{lease.id}:{lease.requests_used}:{request_url}".encode("utf-8")
    ).hexdigest()
    db.add(
        LeaseAction(
            lease_id=lease.id,
            request_fingerprint=fingerprint,
            policy_decision="allowed",
        )
    )
    db.flush()
    audit_log.record(
        db,
        agent="control_plane",
        action="recon_request_reserved",
        payload={
            "scan_session_id": scan_session.id,
            "lease_id": lease.id,
            "request_number": lease.requests_used,
            "request_hash": hashlib.sha256(request_url.encode("utf-8")).hexdigest(),
        },
    )


def revoke_contract(db: Session, *, contract: ScanContract, reason: str) -> None:
    """Revoke a policy and halt every active scan bound to it."""
    db.flush()
    db.refresh(contract)
    if contract.status == ScanContractStatus.REVOKED:
        return
    revoked_at = _now()
    # The conditional state transition acquires the contract row lock before
    # leases are enumerated. Issuance and activation also lock/check this
    # record, so a just-issued lease cannot slip past this revocation.
    transitioned = (
        db.query(ScanContract)
        .filter(
            ScanContract.id == contract.id,
            ScanContract.status != ScanContractStatus.REVOKED,
        )
        .update(
            {
                ScanContract.status: ScanContractStatus.REVOKED,
                ScanContract.revocation_epoch: ScanContract.revocation_epoch + 1,
                ScanContract.revoked_at: revoked_at,
                ScanContract.revoked_reason: reason,
            },
            synchronize_session=False,
        )
    )
    if transitioned != 1:
        db.refresh(contract)
        return
    leases = (
        db.query(ActionLease)
        .filter(
            ActionLease.contract_id == contract.id,
            ActionLease.status.in_([ActionLeaseStatus.ISSUED, ActionLeaseStatus.ACTIVE]),
        )
        .with_for_update()
        .all()
    )
    halted_session_ids: list[int] = []
    for lease in leases:
        lease.status = ActionLeaseStatus.REVOKED
        lease.terminal_at = _now()
        lease.terminal_reason = reason
        if lease.scan_session_id is not None:
            session_row = db.get(ScanSession, lease.scan_session_id)
            if session_row is not None and session_row.status == ScanStatus.RUNNING:
                session_row.status = ScanStatus.HALTED
                session_row.halted_reason = f"action lease {reason}"
                session_row.ended_at = _now()
                halted_session_ids.append(session_row.id)
    db.flush()
    db.refresh(contract)
    audit_log.record(
        db,
        agent="control_plane",
        action="scan_contract_revoked",
        payload={
            "contract_id": contract.id,
            "reason": reason,
            "halted_scan_session_ids": halted_session_ids,
        },
    )


def revoke_contracts_for_target(db: Session, *, target_id: int, reason: str) -> None:
    contracts = (
        db.query(ScanContract)
        .filter(
            ScanContract.target_id == target_id,
            ScanContract.status != ScanContractStatus.REVOKED,
        )
        .all()
    )
    for contract in contracts:
        revoke_contract(db, contract=contract, reason=reason)


def revoke_lease_for_scan(db: Session, *, scan_session: ScanSession, reason: str) -> None:
    """Keep a manual/anomaly halt from leaving a usable active lease behind."""
    if scan_session.contract_id is None:
        return
    lease = (
        db.query(ActionLease)
        .filter(
            ActionLease.scan_session_id == scan_session.id,
            ActionLease.status == ActionLeaseStatus.ACTIVE,
        )
        .one_or_none()
    )
    if lease is None:
        return
    lease.status = ActionLeaseStatus.REVOKED
    lease.terminal_at = _now()
    lease.terminal_reason = reason
    db.flush()
    audit_log.record(
        db,
        agent="control_plane",
        action="action_lease_revoked_for_halt",
        payload={"lease_id": lease.id, "scan_session_id": scan_session.id, "reason": reason},
    )


def complete_lease_for_scan(db: Session, *, scan_session: ScanSession) -> None:
    """Close a successful contract run; completed leases cannot be resumed."""
    db.refresh(scan_session, attribute_names=["status", "contract_id"])
    if scan_session.status != ScanStatus.COMPLETED:
        return
    if scan_session.contract_id is None:
        return
    lease = (
        db.query(ActionLease)
        .filter(
            ActionLease.scan_session_id == scan_session.id,
            ActionLease.status == ActionLeaseStatus.ACTIVE,
        )
        .one_or_none()
    )
    if lease is None:
        return
    lease.status = ActionLeaseStatus.COMPLETED
    lease.terminal_at = _now()
    lease.terminal_reason = "scan completed"
    db.flush()
    audit_log.record(
        db,
        agent="control_plane",
        action="action_lease_completed",
        payload={"lease_id": lease.id, "scan_session_id": scan_session.id},
    )


def fail_contract_scan(db: Session, *, scan_session: ScanSession, reason: str) -> None:
    """Terminally fail an unexpected worker crash and revoke its authority."""
    db.refresh(scan_session, attribute_names=["status", "contract_id"])
    if scan_session.status != ScanStatus.RUNNING:
        return
    scan_session.status = ScanStatus.FAILED
    scan_session.halted_reason = reason
    scan_session.ended_at = _now()
    if scan_session.contract_id is not None:
        lease = (
            db.query(ActionLease)
            .filter(
                ActionLease.scan_session_id == scan_session.id,
                ActionLease.status == ActionLeaseStatus.ACTIVE,
            )
            .one_or_none()
        )
        if lease is not None:
            lease.status = ActionLeaseStatus.REVOKED
            lease.terminal_at = _now()
            lease.terminal_reason = reason
    db.flush()
    audit_log.record(
        db,
        agent="control_plane",
        action="contract_scan_failed",
        payload={"scan_session_id": scan_session.id, "reason": reason},
    )


def start_contract_run(db: Session, *, contract_id: int) -> ScanSession:
    """Run Phase 0 freshly, then bind an internal lease before any pipeline node."""
    contract = db.get(ScanContract, contract_id)
    if contract is None:
        raise ContractStateError(f"Scan contract {contract_id} was not found")
    enforce_contract_active(db, contract)
    target = _target_for_contract(db, contract)
    scan_session: ScanSession | None = None
    try:
        # Import lazily to keep the Phase-0 package independent from this
        # control plane. This call is the fresh ownership + canary gate.
        from sentinel.phase0 import registry

        # Historical verification is not enough: a formerly-owned hostname
        # may have been transferred or repointed. Phase 0 must prove control
        # again immediately before every contract run.
        fresh_target = registry.run_ownership_verification(db, target.domain)
        if not fresh_target.is_ownership_verified:
            audit_log.record(
                db,
                agent="control_plane",
                action="contract_run_fresh_ownership_failed",
                payload={"contract_id": contract.id, "target_id": target.id},
            )
            raise ContractStateError("Fresh domain ownership verification failed")
        enforce_contract_active(db, contract)
        lease, token = issue_action_lease(db, contract=contract, requested_tier=ActionTier.TIER_A)
        scan_session = registry.start_scan_session(db, target.domain)
        activate_lease_for_scan(db, lease_token=token, scan_session=scan_session)
    except Exception as exc:
        # Lease issuance happens only after the fresh proof. Keep failure
        # handling safe for proof failures that never allocated a lease.
        if "lease" in locals() and lease.status in {ActionLeaseStatus.ISSUED, ActionLeaseStatus.ACTIVE}:
            lease.status = ActionLeaseStatus.REVOKED
            lease.terminal_at = _now()
            lease.terminal_reason = f"run start failed: {type(exc).__name__}"
        if scan_session is not None and scan_session.status == ScanStatus.RUNNING:
            # A partially-created Phase-0 session must never remain a
            # runnable, unleased scan if binding the lease fails.
            scan_session.status = ScanStatus.HALTED
            scan_session.halted_reason = "action lease could not be activated"
            scan_session.ended_at = _now()
        db.flush()
        audit_log.record(
            db,
            agent="control_plane",
            action="contract_run_start_failed",
            payload={
                "contract_id": contract.id,
                "lease_id": lease.id if "lease" in locals() else None,
                "scan_session_id": scan_session.id if scan_session is not None else None,
                "error_type": type(exc).__name__,
            },
        )
        raise
    audit_log.record(
        db,
        agent="control_plane",
        action="contract_run_started",
        payload={
            "contract_id": contract.id,
            "scan_session_id": scan_session.id,
            "lease_id": lease.id,
            "recipe": "recon.v1",
        },
    )
    return scan_session
