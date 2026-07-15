from __future__ import annotations

from datetime import datetime, timezone

import pytest

from sentinel.db.models import (
    ActionTier,
    EnvironmentTier,
    ScanSession,
    ScanStatus,
    TargetRegistration,
)
from sentinel.security import guardrails
from sentinel.security.guardrails import (
    DemonstrationBudgetExceededError,
    PivotViolationError,
    ScanHaltedError,
    TierViolationError,
    UnauthorizedTargetError,
    normalize_host,
)


def _verified_registration(db_session, domain="example-test.com") -> TargetRegistration:
    reg = TargetRegistration(
        domain=domain,
        account_owner="alice@corp.com",
        verification_token="tok",
        canary_marker="marker",
        canary_check_url_template="https://x/{marker}",
        verification_passed_at=datetime.now(timezone.utc),
    )
    db_session.add(reg)
    db_session.flush()
    return reg


class TestNormalizeHost:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("example.com", "example.com"),
            ("Example.COM", "example.com"),
            ("https://example.com/path", "example.com"),
            ("https://example.com:8443/path", "example.com"),
            ("example.com.", "example.com"),
        ],
    )
    def test_normalizes_variants_to_bare_host(self, raw, expected):
        assert normalize_host(raw) == expected

    @pytest.mark.parametrize(
        "dangerous_url",
        [
            "file://example.com/etc/passwd",
            "ftp://example.com/x",
            "javascript://example.com/%0aalert(1)",
        ],
    )
    def test_rejects_non_http_schemes_on_explicit_urls(self, dangerous_url):
        """Regression: a same-looking hostname behind a non-http(s) scheme
        used to normalize cleanly and pass enforce_no_pivot, relying only on
        httpx's own scheme rejection (an implementation detail elsewhere) to
        stop it actually being fetched."""
        with pytest.raises(PivotViolationError):
            normalize_host(dangerous_url)

    def test_bare_hostnames_without_scheme_are_unaffected(self):
        # No "://" at all — never treated as a scheme violation, even if it
        # happens to contain a colon-like substring.
        assert normalize_host("example.com") == "example.com"


class TestEnforceTargetAuthorized:
    def test_raises_for_unregistered_domain(self, db_session):
        with pytest.raises(UnauthorizedTargetError):
            guardrails.enforce_target_authorized(db_session, "never-registered.com")

    def test_raises_for_registered_but_unverified_domain(self, db_session):
        reg = TargetRegistration(
            domain="unverified-test.com",
            account_owner="alice@corp.com",
            verification_token="tok",
            canary_marker="marker",
            canary_check_url_template="https://x/{marker}",
        )
        db_session.add(reg)
        db_session.flush()
        with pytest.raises(UnauthorizedTargetError):
            guardrails.enforce_target_authorized(db_session, "unverified-test.com")

    def test_raises_for_deactivated_domain(self, db_session):
        reg = _verified_registration(db_session)
        reg.is_active = False
        db_session.flush()
        with pytest.raises(UnauthorizedTargetError):
            guardrails.enforce_target_authorized(db_session, "example-test.com")

    def test_passes_for_active_verified_domain(self, db_session):
        _verified_registration(db_session)
        result = guardrails.enforce_target_authorized(db_session, "example-test.com")
        assert result.domain == "example-test.com"

    def test_no_scan_flag_or_config_can_bypass_this(self, db_session):
        """No enforce_* function accepts a force/override/skip parameter, and
        none of them branch on an environment variable — the only way to
        change this behavior is to edit this source file."""
        import inspect

        enforce_functions = [
            guardrails.enforce_target_authorized,
            guardrails.enforce_no_pivot,
            guardrails.enforce_tier,
            guardrails.enforce_not_halted,
            guardrails.enforce_demonstration_budget,
        ]
        for fn in enforce_functions:
            for param_name in inspect.signature(fn).parameters:
                lowered = param_name.lower()
                assert "force" not in lowered
                assert "override" not in lowered
                assert "skip" not in lowered

        source = inspect.getsource(guardrails)
        assert "os.environ" not in source
        assert "getenv" not in source


class TestEnforceNoPivot:
    def test_allows_exact_registered_host(self, db_session):
        reg = _verified_registration(db_session)
        guardrails.enforce_no_pivot(reg, "example-test.com")  # should not raise

    def test_blocks_discovered_third_party_host(self, db_session):
        reg = _verified_registration(db_session)
        with pytest.raises(PivotViolationError):
            guardrails.enforce_no_pivot(reg, "some-other-site.com")

    def test_blocks_even_subdomains_by_default(self, db_session):
        reg = _verified_registration(db_session)
        with pytest.raises(PivotViolationError):
            guardrails.enforce_no_pivot(reg, "cdn.example-test.com")


class TestEnforceTier:
    def test_tier_a_always_allowed(self):
        guardrails.enforce_tier(ActionTier.TIER_A, EnvironmentTier.UNVERIFIED)
        guardrails.enforce_tier(ActionTier.TIER_A, EnvironmentTier.VERIFIED_SAFE)

    def test_tier_b_blocked_without_canary_pass(self):
        with pytest.raises(TierViolationError):
            guardrails.enforce_tier(ActionTier.TIER_B, EnvironmentTier.UNVERIFIED)

    def test_tier_b_allowed_with_canary_pass(self):
        guardrails.enforce_tier(ActionTier.TIER_B, EnvironmentTier.VERIFIED_SAFE)


class TestEnforceNotHalted:
    def test_passes_when_running(self, db_session):
        reg = _verified_registration(db_session)
        session_row = ScanSession(target_id=reg.id, status=ScanStatus.RUNNING)
        db_session.add(session_row)
        db_session.flush()
        guardrails.enforce_not_halted(db_session, session_row)

    def test_raises_when_halted(self, db_session):
        reg = _verified_registration(db_session)
        session_row = ScanSession(target_id=reg.id, status=ScanStatus.HALTED, halted_reason="anomaly detected")
        db_session.add(session_row)
        db_session.flush()
        with pytest.raises(ScanHaltedError):
            guardrails.enforce_not_halted(db_session, session_row)

    def test_picks_up_a_halt_committed_by_a_different_session(self, db_session):
        """The actual CRITICAL fix this covers: a manual halt arrives via a
        different DB session (e.g. a separate API request thread) than the
        one a long-running dispatch loop is holding. enforce_not_halted must
        refresh from the DB, not trust a stale in-memory attribute."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        from sentinel.db.models import Base

        engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
        )
        Base.metadata.create_all(bind=engine)
        SessionFactory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

        session_a = SessionFactory()
        session_b = SessionFactory()

        reg = TargetRegistration(
            domain="cross-session-test.com",
            account_owner="alice@corp.com",
            verification_token="tok",
            canary_marker="marker",
            canary_check_url_template="https://x/{marker}",
            verification_passed_at=datetime.now(timezone.utc),
        )
        session_a.add(reg)
        session_a.commit()

        scan_session = ScanSession(target_id=reg.id, status=ScanStatus.RUNNING)
        session_a.add(scan_session)
        session_a.commit()
        scan_session_id = scan_session.id

        # session_b loads its OWN object for the same row — simulating a
        # long-running dispatch loop that loaded scan_session minutes ago.
        scan_session_in_b = session_b.get(ScanSession, scan_session_id)
        guardrails.enforce_not_halted(session_b, scan_session_in_b)  # passes: still running

        # A completely different session halts it (e.g. a manual API halt).
        scan_session_in_a = session_a.get(ScanSession, scan_session_id)
        scan_session_in_a.status = ScanStatus.HALTED
        scan_session_in_a.halted_reason = "operator halt from another session"
        session_a.commit()

        # session_b's object must see it on the very next check.
        with pytest.raises(ScanHaltedError):
            guardrails.enforce_not_halted(session_b, scan_session_in_b)

        session_a.close()
        session_b.close()


class TestEnforceDemonstrationBudget:
    def test_allows_single_account_creation(self, db_session):
        reg = _verified_registration(db_session)
        guardrails.enforce_demonstration_budget(db_session, reg, "account_creation", 1)

    def test_blocks_mass_account_creation_in_one_call(self, db_session):
        reg = _verified_registration(db_session)
        with pytest.raises(DemonstrationBudgetExceededError):
            guardrails.enforce_demonstration_budget(db_session, reg, "account_creation", 50)

    def test_blocks_mass_deletion(self, db_session):
        reg = _verified_registration(db_session)
        with pytest.raises(DemonstrationBudgetExceededError):
            guardrails.enforce_demonstration_budget(db_session, reg, "account_deletion", 10)

    def test_allows_unrelated_action_types_through(self, db_session):
        reg = _verified_registration(db_session)
        guardrails.enforce_demonstration_budget(db_session, reg, "read_only_probe", 10_000)

    def test_budget_is_persistent_across_calls_not_reset_per_call(self, db_session):
        """The actual HIGH-severity fix: a caller can't get a fresh
        allowance by asking for "1" again in a new call — the lifetime
        counter on the registration is what's checked, not the argument."""
        reg = _verified_registration(db_session)
        guardrails.enforce_demonstration_budget(db_session, reg, "account_creation", 1)
        guardrails.record_demonstration_action(db_session, reg, "account_creation", 1)

        with pytest.raises(DemonstrationBudgetExceededError):
            guardrails.enforce_demonstration_budget(db_session, reg, "account_creation", 1)

    def test_budget_persists_even_via_a_fresh_registration_object(self, db_session):
        """Simulates a new scan session loading its own TargetRegistration
        instance — the counter must still be visible, not per-object state."""
        reg = _verified_registration(db_session)
        guardrails.enforce_demonstration_budget(db_session, reg, "account_creation", 1)
        guardrails.record_demonstration_action(db_session, reg, "account_creation", 1)
        db_session.flush()

        reloaded = db_session.get(TargetRegistration, reg.id)
        with pytest.raises(DemonstrationBudgetExceededError):
            guardrails.enforce_demonstration_budget(db_session, reloaded, "account_creation", 1)
