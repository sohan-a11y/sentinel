from __future__ import annotations

import httpx
import pytest
import respx

from sentinel.config import settings
from sentinel.db.models import EnvironmentTier, ScanStatus
from sentinel.phase0 import registry
from sentinel.phase0.exceptions import DomainAlreadyRegisteredError, TargetNotRegisteredError
from sentinel.security import audit_log
from sentinel.security.guardrails import UnauthorizedTargetError

DOMAIN = "example-test.com"
CANARY_URL = "https://example-test.com/api/users/{marker}"


def _register(db_session, domain=DOMAIN, canary_url=CANARY_URL):
    return registry.register_target(
        db_session,
        domain=domain,
        account_owner="alice@corp.com",
        canary_check_url_template=canary_url,
    )


def test_register_target_creates_unverified_row(db_session):
    reg = _register(db_session)
    assert reg.domain == DOMAIN
    assert reg.is_ownership_verified is False
    assert reg.verification_token
    assert reg.canary_marker


def test_register_target_rejects_duplicate_active_domain(db_session):
    _register(db_session)
    with pytest.raises(DomainAlreadyRegisteredError):
        _register(db_session)


def test_register_target_requires_marker_placeholder(db_session):
    with pytest.raises(ValueError):
        registry.register_target(
            db_session,
            domain=DOMAIN,
            account_owner="alice@corp.com",
            canary_check_url_template="https://example-test.com/api/users/42",
        )


def test_run_ownership_verification_requires_existing_registration(db_session):
    with pytest.raises(TargetNotRegisteredError):
        registry.run_ownership_verification(db_session, "never-registered.com")


@respx.mock
def test_run_ownership_verification_passes_and_marks_verified(db_session):
    reg = _register(db_session)
    respx.get(f"https://{DOMAIN}{settings.well_known_path}").mock(
        return_value=httpx.Response(200, text=reg.verification_token)
    )
    updated = registry.run_ownership_verification(db_session, DOMAIN)
    assert updated.is_ownership_verified is True


@respx.mock
def test_run_ownership_verification_fails_when_token_absent(db_session):
    _register(db_session)
    respx.get(f"https://{DOMAIN}{settings.well_known_path}").mock(return_value=httpx.Response(404))
    import dns.resolver as dr
    from unittest.mock import patch

    with patch("dns.resolver.Resolver.resolve", side_effect=dr.NXDOMAIN()):
        updated = registry.run_ownership_verification(db_session, DOMAIN)
    assert updated.is_ownership_verified is False


def test_start_scan_session_rejects_unregistered_domain(db_session):
    with pytest.raises(UnauthorizedTargetError):
        registry.start_scan_session(db_session, "never-registered.com")


@respx.mock
def test_start_scan_session_rejects_unverified_ownership_even_if_canary_would_pass(db_session):
    reg = _register(db_session)
    respx.get(f"https://{DOMAIN}/api/users/{reg.canary_marker}").mock(
        return_value=httpx.Response(200, text=reg.canary_marker)
    )
    with pytest.raises(UnauthorizedTargetError):
        registry.start_scan_session(db_session, DOMAIN)


@respx.mock
def test_start_scan_session_stamps_verified_safe_when_canary_passes(db_session):
    reg = _register(db_session)
    respx.get(f"https://{DOMAIN}{settings.well_known_path}").mock(
        return_value=httpx.Response(200, text=reg.verification_token)
    )
    registry.run_ownership_verification(db_session, DOMAIN)

    respx.get(f"https://{DOMAIN}/api/users/{reg.canary_marker}").mock(
        return_value=httpx.Response(200, text=reg.canary_marker)
    )
    session_row = registry.start_scan_session(db_session, DOMAIN)
    assert session_row.environment_tier == EnvironmentTier.VERIFIED_SAFE
    assert session_row.status == ScanStatus.RUNNING


@respx.mock
def test_start_scan_session_downgrades_to_unverified_when_canary_absent_regardless_of_claim(db_session):
    """Core Phase 0 requirement: marker absent -> forced downgrade, logged, no override."""
    reg = _register(db_session)
    respx.get(f"https://{DOMAIN}{settings.well_known_path}").mock(
        return_value=httpx.Response(200, text=reg.verification_token)
    )
    registry.run_ownership_verification(db_session, DOMAIN)

    respx.get(f"https://{DOMAIN}/api/users/{reg.canary_marker}").mock(return_value=httpx.Response(404))
    session_row = registry.start_scan_session(db_session, DOMAIN)
    assert session_row.environment_tier == EnvironmentTier.UNVERIFIED

    ok, reason = audit_log.verify_chain(db_session)
    assert ok, reason
    downgrade_entries = [
        e
        for e in db_session.query(audit_log.AuditLogEntry).all()
        if e.action == "session_downgraded_to_tier_a"
    ]
    assert len(downgrade_entries) == 1


def test_deactivate_target_removes_from_active_registry(db_session):
    _register(db_session)
    registry.deactivate_target(db_session, DOMAIN)
    assert registry.get_active_registration(db_session, DOMAIN) is None


@respx.mock
def test_full_audit_chain_verifies_after_multiple_operations(db_session):
    reg = _register(db_session)
    respx.get(f"https://{DOMAIN}{settings.well_known_path}").mock(
        return_value=httpx.Response(200, text=reg.verification_token)
    )
    registry.run_ownership_verification(db_session, DOMAIN)
    respx.get(f"https://{DOMAIN}/api/users/{reg.canary_marker}").mock(
        return_value=httpx.Response(200, text=reg.canary_marker)
    )
    registry.start_scan_session(db_session, DOMAIN)
    registry.deactivate_target(db_session, DOMAIN)

    ok, reason = audit_log.verify_chain(db_session)
    assert ok, reason
