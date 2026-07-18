from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from sentinel.config import settings
from sentinel.control_plane import service
from sentinel.db.models import (
    ActionLease,
    ActionLeaseStatus,
    ActionTier,
    EnvironmentTier,
    ScanContractStatus,
    ScanSession,
    ScanStatus,
    TargetRegistration,
)
from sentinel.phase0 import registry
from sentinel.security import audit_log, guardrails
from sentinel.security.guardrails import ScanHaltedError
from sentinel.zero_trust.policy import generate_ed25519_keypair


def _verified_registration(db_session, domain: str = "contract-test.example") -> TargetRegistration:
    registration = TargetRegistration(
        domain=domain,
        account_owner="owner@example.com",
        verification_token="proof-token",
        canary_marker="canary",
        canary_check_url_template=f"https://{domain}/canary/{{marker}}",
        verification_passed_at=datetime.now(timezone.utc),
    )
    db_session.add(registration)
    db_session.flush()
    return registration


@pytest.fixture(autouse=True)
def _control_plane_signing_key(monkeypatch):
    monkeypatch.setattr(settings, "control_plane_signing_key", "test-contract-signing-key")
    monkeypatch.setattr(settings, "control_plane_max_lease_seconds", 900)


def _active_contract(db_session, registration):
    return service.create_scan_contract(
        db_session,
        registration=registration,
        approved_by="security.approver@example.com",
        allowed_tier=ActionTier.TIER_A,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        max_scan_sessions=1,
        max_requests=1,
    )


def test_contract_is_signed_and_binds_the_verified_target(db_session):
    registration = _verified_registration(db_session)

    contract = _active_contract(db_session, registration)

    assert contract.target_id == registration.id
    assert contract.policy_hash
    assert contract.policy_signature
    assert contract.allowed_tier == ActionTier.TIER_A
    service.enforce_contract_active(db_session, contract)


def test_legacy_contract_policy_without_an_authorization_digest_remains_valid(db_session):
    """Adding runner-attestation data must not invalidate existing contracts."""
    registration = _verified_registration(db_session)
    contract = _active_contract(db_session, registration)

    document = service._policy_document(db_session, contract)

    assert b"customer_authorization_reference_hash" not in document
    service.enforce_contract_active(db_session, contract)


def test_customer_authorization_reference_is_stored_only_as_a_signed_keyed_digest(db_session):
    registration = _verified_registration(db_session)
    reference = "official-email-thread-2026-07-18-42"

    contract = service.create_scan_contract(
        db_session,
        registration=registration,
        approved_by="security.approver@example.com",
        allowed_tier=ActionTier.TIER_A,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        customer_authorization_reference=reference,
    )

    assert contract.customer_authorization_reference_hash is not None
    assert reference not in contract.customer_authorization_reference_hash
    assert len(contract.customer_authorization_reference_hash) == 64
    service.enforce_contract_active(db_session, contract)

    contract.customer_authorization_reference_hash = "0" * 64
    db_session.flush()
    with pytest.raises(service.ContractIntegrityError):
        service.enforce_contract_active(db_session, contract)


def test_tier_b_contract_is_blocked_until_fixture_controls_exist(db_session):
    registration = _verified_registration(db_session)

    with pytest.raises(service.ContractPolicyError, match="Tier B"):
        service.create_scan_contract(
            db_session,
            registration=registration,
            approved_by="security.approver@example.com",
            allowed_tier=ActionTier.TIER_B,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            max_scan_sessions=1,
        )


def test_tampered_contract_cannot_issue_a_lease(db_session):
    registration = _verified_registration(db_session)
    contract = _active_contract(db_session, registration)
    contract.max_scan_sessions = 99
    db_session.flush()

    with pytest.raises(service.ContractIntegrityError):
        service.issue_action_lease(db_session, contract=contract, requested_tier=ActionTier.TIER_A)


def test_lease_is_opaque_short_lived_and_single_use(db_session):
    registration = _verified_registration(db_session)
    contract = _active_contract(db_session, registration)

    lease, lease_token = service.issue_action_lease(
        db_session,
        contract=contract,
        requested_tier=ActionTier.TIER_A,
    )

    assert lease_token
    assert lease_token != lease.token_hash
    assert lease.expires_at <= datetime.now(timezone.utc) + timedelta(minutes=15, seconds=1)

    scan_session = ScanSession(
        target_id=registration.id,
        status=ScanStatus.RUNNING,
        environment_tier=EnvironmentTier.VERIFIED_SAFE,
    )
    db_session.add(scan_session)
    db_session.flush()
    service.activate_lease_for_scan(db_session, lease_token=lease_token, scan_session=scan_session)

    assert scan_session.contract_id == contract.id
    assert scan_session.permitted_action_tier == ActionTier.TIER_A
    guardrails.enforce_not_halted(db_session, scan_session)

    with pytest.raises(service.LeaseStateError):
        service.activate_lease_for_scan(db_session, lease_token=lease_token, scan_session=scan_session)


def test_lease_activation_rejects_a_mutated_request_cap(db_session):
    """The mutable lease copy cannot broaden the signed contract budget."""
    registration = _verified_registration(db_session)
    contract = _active_contract(db_session, registration)
    lease, lease_token = service.issue_action_lease(
        db_session,
        contract=contract,
        requested_tier=ActionTier.TIER_A,
    )
    lease.max_requests = contract.max_requests + 1
    scan_session = ScanSession(
        target_id=registration.id,
        status=ScanStatus.RUNNING,
        environment_tier=EnvironmentTier.VERIFIED_SAFE,
    )
    db_session.add(scan_session)
    db_session.flush()

    with pytest.raises(service.LeaseStateError, match="cannot be bound"):
        service.activate_lease_for_scan(db_session, lease_token=lease_token, scan_session=scan_session)


def test_recon_request_budget_is_reserved_before_egress(db_session):
    registration = _verified_registration(db_session)
    contract = _active_contract(db_session, registration)
    _, lease_token = service.issue_action_lease(
        db_session,
        contract=contract,
        requested_tier=ActionTier.TIER_A,
    )
    scan_session = ScanSession(
        target_id=registration.id,
        status=ScanStatus.RUNNING,
        environment_tier=EnvironmentTier.VERIFIED_SAFE,
    )
    db_session.add(scan_session)
    db_session.flush()
    service.activate_lease_for_scan(db_session, lease_token=lease_token, scan_session=scan_session)

    service.reserve_recon_request(
        db_session,
        scan_session=scan_session,
        request_url="https://contract-test.example/one",
    )
    with pytest.raises(ScanHaltedError, match="budget exhausted"):
        service.reserve_recon_request(
            db_session,
            scan_session=scan_session,
            request_url="https://contract-test.example/two",
        )
    db_session.refresh(scan_session)
    assert scan_session.status == ScanStatus.HALTED


def test_recon_lease_rejects_non_https_or_wrong_origin_without_spending_budget(db_session):
    registration = _verified_registration(db_session)
    contract = _active_contract(db_session, registration)
    lease, lease_token = service.issue_action_lease(
        db_session,
        contract=contract,
        requested_tier=ActionTier.TIER_A,
    )
    scan_session = ScanSession(
        target_id=registration.id,
        status=ScanStatus.RUNNING,
        environment_tier=EnvironmentTier.VERIFIED_SAFE,
    )
    db_session.add(scan_session)
    db_session.flush()
    service.activate_lease_for_scan(db_session, lease_token=lease_token, scan_session=scan_session)

    with pytest.raises(service.ReconRequestDenied):
        service.reserve_recon_request(
            db_session,
            scan_session=scan_session,
            request_url="http://contract-test.example/not-https",
        )
    with pytest.raises(service.ReconRequestDenied):
        service.reserve_recon_request(
            db_session,
            scan_session=scan_session,
            request_url="https://other.example/not-our-origin",
        )

    db_session.refresh(lease)
    assert lease.requests_used == 0


def test_recon_request_denial_audit_survives_the_callers_rollback(db_session):
    registration = _verified_registration(db_session)
    contract = _active_contract(db_session, registration)
    _, lease_token = service.issue_action_lease(
        db_session,
        contract=contract,
        requested_tier=ActionTier.TIER_A,
    )
    scan_session = ScanSession(
        target_id=registration.id,
        status=ScanStatus.RUNNING,
        environment_tier=EnvironmentTier.VERIFIED_SAFE,
    )
    db_session.add(scan_session)
    db_session.flush()
    service.activate_lease_for_scan(db_session, lease_token=lease_token, scan_session=scan_session)

    with pytest.raises(service.ReconRequestDenied):
        service.reserve_recon_request(
            db_session,
            scan_session=scan_session,
            request_url="https://outside-contract.example/not-allowed",
        )
    # The request guard re-raises denials. A conventional session wrapper
    # rolls back on that exception, so this regression proves the security
    # event was committed before propagation.
    db_session.rollback()
    actions = [entry.action for entry in db_session.query(audit_log.AuditLogEntry).all()]
    assert "recon_request_blocked" in actions


def test_revoked_contract_halts_an_active_leased_scan(db_session):
    registration = _verified_registration(db_session)
    contract = _active_contract(db_session, registration)
    _, lease_token = service.issue_action_lease(
        db_session,
        contract=contract,
        requested_tier=ActionTier.TIER_A,
    )
    scan_session = ScanSession(
        target_id=registration.id,
        status=ScanStatus.RUNNING,
        environment_tier=EnvironmentTier.VERIFIED_SAFE,
    )
    db_session.add(scan_session)
    db_session.flush()
    service.activate_lease_for_scan(db_session, lease_token=lease_token, scan_session=scan_session)

    service.revoke_contract(db_session, contract=contract, reason="approval withdrawn")

    with pytest.raises(ScanHaltedError, match="action lease"):
        guardrails.enforce_not_halted(db_session, scan_session)
    db_session.refresh(scan_session)
    assert scan_session.status == ScanStatus.HALTED
    assert "approval withdrawn" in (scan_session.halted_reason or "")


def test_target_deactivation_revokes_active_contracts_and_stops_their_runs(db_session):
    registration = _verified_registration(db_session)
    contract = _active_contract(db_session, registration)
    lease, lease_token = service.issue_action_lease(
        db_session,
        contract=contract,
        requested_tier=ActionTier.TIER_A,
    )
    scan_session = ScanSession(
        target_id=registration.id,
        status=ScanStatus.RUNNING,
        environment_tier=EnvironmentTier.VERIFIED_SAFE,
    )
    db_session.add(scan_session)
    db_session.flush()
    service.activate_lease_for_scan(db_session, lease_token=lease_token, scan_session=scan_session)

    registry.deactivate_target(db_session, registration.domain)

    db_session.refresh(contract)
    db_session.refresh(lease)
    db_session.refresh(scan_session)
    assert contract.status.value == "revoked"
    assert lease.status == ActionLeaseStatus.REVOKED
    assert scan_session.status == ScanStatus.HALTED
    assert registration.is_active is False


def test_target_deactivation_revokes_an_expired_contract_with_a_live_lease(db_session):
    registration = _verified_registration(db_session)
    contract = _active_contract(db_session, registration)
    lease, lease_token = service.issue_action_lease(
        db_session,
        contract=contract,
        requested_tier=ActionTier.TIER_A,
    )
    scan_session = ScanSession(
        target_id=registration.id,
        status=ScanStatus.RUNNING,
        environment_tier=EnvironmentTier.VERIFIED_SAFE,
    )
    db_session.add(scan_session)
    db_session.flush()
    service.activate_lease_for_scan(db_session, lease_token=lease_token, scan_session=scan_session)
    # A background expiry path could have marked the contract expired before
    # its lease was next checked. Target deactivation must still terminalize
    # that lease/session rather than filtering the contract out.
    contract.status = ScanContractStatus.EXPIRED
    db_session.flush()

    registry.deactivate_target(db_session, registration.domain)

    db_session.refresh(contract)
    db_session.refresh(lease)
    db_session.refresh(scan_session)
    assert contract.status == ScanContractStatus.REVOKED
    assert lease.status == ActionLeaseStatus.REVOKED
    assert scan_session.status == ScanStatus.HALTED


def test_contract_run_requires_a_fresh_ownership_proof_before_issuing_a_lease(db_session):
    registration = _verified_registration(db_session)
    contract = _active_contract(db_session, registration)

    with patch(
        "sentinel.phase0.registry.run_ownership_verification",
        return_value=SimpleNamespace(is_ownership_verified=False),
    ):
        with pytest.raises(service.ContractStateError, match="Fresh domain ownership verification failed"):
            service.start_contract_run(db_session, contract_id=contract.id)

    db_session.refresh(contract)
    assert contract.issued_lease_count == 0
    assert db_session.query(ActionLease).filter(ActionLease.contract_id == contract.id).count() == 0


def test_customer_runner_permit_requires_fresh_ownership_before_consuming_a_run_budget(
    db_session,
    monkeypatch,
):
    registration = _verified_registration(db_session)
    contract = service.create_scan_contract(
        db_session,
        registration=registration,
        approved_by="security.approver@example.com",
        allowed_tier=ActionTier.TIER_A,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        customer_authorization_reference="official-approval-ticket-42",
    )
    private_key, _ = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "runner_permit_private_key", private_key)

    with patch(
        "sentinel.phase0.registry.run_ownership_verification",
        return_value=SimpleNamespace(is_ownership_verified=False),
    ):
        with pytest.raises(service.ContractStateError, match="Fresh domain ownership verification failed"):
            service.issue_customer_runner_permit(
                db_session,
                contract=contract,
                allowed_path_prefixes=["/"],
            )

    db_session.refresh(contract)
    assert contract.issued_lease_count == 0
    assert db_session.query(ActionLease).filter(ActionLease.contract_id == contract.id).count() == 0


def test_invalid_customer_runner_path_is_rejected_before_a_fresh_ownership_probe(
    db_session,
    monkeypatch,
):
    registration = _verified_registration(db_session)
    contract = service.create_scan_contract(
        db_session,
        registration=registration,
        approved_by="security.approver@example.com",
        allowed_tier=ActionTier.TIER_A,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        customer_authorization_reference="official-approval-ticket-42",
    )
    private_key, _ = generate_ed25519_keypair()
    monkeypatch.setattr(settings, "runner_permit_private_key", private_key)

    with patch("sentinel.phase0.registry.run_ownership_verification") as fresh_proof:
        with pytest.raises(service.ContractPolicyError, match="path scope"):
            service.issue_customer_runner_permit(
                db_session,
                contract=contract,
                allowed_path_prefixes=["not-a-root-path"],
            )

    fresh_proof.assert_not_called()
    db_session.refresh(contract)
    assert contract.issued_lease_count == 0
