"""The registration workflow: the only door into the registered-targets list.

register_target() creates an unverified row. Nothing can scan against it
until run_ownership_verification() passes. start_scan_session() is the single
entry point the API/agents use to begin a scan — it re-checks ownership via
sentinel.security.guardrails (not by re-implementing the check) and re-runs
the canary probe fresh every time, then stamps the resulting tier onto a new
ScanSession row and writes both decisions to the audit log.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from sentinel.db.models import EnvironmentTier, ScanSession, ScanStatus, TargetRegistration
from sentinel.phase0 import canary, verification
from sentinel.phase0.exceptions import DomainAlreadyRegisteredError, TargetNotRegisteredError
from sentinel.security import guardrails
from sentinel.security.audit_log import record as audit_record
from sentinel.security.guardrails import normalize_host as _normalize_host


def register_target(
    db: Session,
    *,
    domain: str,
    account_owner: str,
    canary_check_url_template: str,
    canary_check_method: str = "GET",
) -> TargetRegistration:
    # Phase 0 is executing here: creates the (still-unverified) registration
    # row — the token and canary marker generated below are Phase 0's two
    # gate artifacts, and nothing can scan this domain until they're proven.
    host = _normalize_host(domain)
    existing = db.query(TargetRegistration).filter(TargetRegistration.domain == host).one_or_none()
    if existing is not None and existing.is_active:
        raise DomainAlreadyRegisteredError(f"'{host}' is already registered (id={existing.id})")

    if "{marker}" not in canary_check_url_template:
        raise ValueError("canary_check_url_template must contain the literal placeholder '{marker}'")

    registration = TargetRegistration(
        domain=host,
        account_owner=account_owner,
        verification_token=verification.generate_verification_token(),
        canary_marker=canary.generate_canary_marker(),
        canary_check_url_template=canary_check_url_template,
        canary_check_method=canary_check_method.upper(),
    )
    db.add(registration)
    db.flush()

    audit_record(
        db,
        agent="phase0.registry",
        action="target_registered",
        payload={
            "domain": host,
            "account_owner": account_owner,
            "registration_id": registration.id,
        },
    )
    return registration


def run_ownership_verification(db: Session, domain: str) -> TargetRegistration:
    # Phase 0 is executing here: runs the live domain-ownership check
    # (HTTP well-known / DNS TXT) and stamps the result onto the registration.
    host = _normalize_host(domain)
    registration = db.query(TargetRegistration).filter(TargetRegistration.domain == host).one_or_none()
    if registration is None:
        raise TargetNotRegisteredError(f"'{host}' has no registration record; call register_target() first")

    method = verification.verify_domain_ownership(host, registration.verification_token)
    from datetime import datetime, timezone

    passed = method is not None
    registration.verification_method = method
    registration.verification_passed_at = datetime.now(timezone.utc) if passed else None
    db.flush()

    audit_record(
        db,
        agent="phase0.registry",
        action="ownership_verification_result",
        payload={
            "domain": host,
            "passed": passed,
            "method": method.value if method else None,
        },
    )
    return registration


def get_active_registration(db: Session, domain: str) -> TargetRegistration | None:
    # Phase 0 is executing here: reads back the current registration/
    # verification/canary state for a domain (used by the API status route).
    host = _normalize_host(domain)
    return (
        db.query(TargetRegistration)
        .filter(TargetRegistration.domain == host, TargetRegistration.is_active.is_(True))
        .one_or_none()
    )


def deactivate_target(db: Session, domain: str) -> None:
    # Phase 0 is executing here: revokes a domain's registration — after this,
    # enforce_target_authorized will reject it again until re-registered.
    host = _normalize_host(domain)
    registration = db.query(TargetRegistration).filter(TargetRegistration.domain == host).one_or_none()
    if registration is None:
        return
    registration.is_active = False
    db.flush()
    audit_record(db, agent="phase0.registry", action="target_deactivated", payload={"domain": host})


def start_scan_session(db: Session, domain: str) -> ScanSession:
    """The single entry point agents/API use to begin a scan.

    1. enforce_target_authorized — fails closed if not registered+verified.
    2. Fresh canary probe — never trusts a cached/prior-session result.
    3. Stamp the resulting tier onto a brand-new ScanSession row.
    4. Audit-log both the authorization pass and the tier decision.
    """
    # Phase 0 is executing here (step 1): re-checks domain-ownership
    # authorization every single time a scan starts — not just at registration.
    registration = guardrails.enforce_target_authorized(db, domain)

    # Phase 0 is executing here (step 2): re-runs the environment canary probe
    # live, right now, for this session — never trusts a previous session's tier.
    tier = canary.determine_environment_tier(
        registration.canary_check_url_template,
        registration.canary_marker,
        registration.canary_check_method,
    )
    from datetime import datetime, timezone

    registration.last_canary_check_at = datetime.now(timezone.utc)
    registration.last_canary_result = tier
    db.flush()

    session_row = ScanSession(target_id=registration.id, status=ScanStatus.RUNNING, environment_tier=tier)
    db.add(session_row)
    db.flush()

    audit_record(
        db,
        agent="phase0.registry",
        action="scan_session_started",
        payload={
            "domain": registration.domain,
            "scan_session_id": session_row.id,
            "environment_tier": tier.value,
        },
    )
    if tier != EnvironmentTier.VERIFIED_SAFE:
        audit_record(
            db,
            agent="phase0.canary",
            action="session_downgraded_to_tier_a",
            payload={
                "domain": registration.domain,
                "scan_session_id": session_row.id,
                "reason": "canary marker not confirmed present in target environment",
            },
        )
    return session_row
