"""Hard architectural boundaries.

Every function here is a plain Python assertion against database state. There
is no LLM in this file, no prompt telling an agent to "please behave" — every
dispatch call in sentinel/agents/dispatch/*.py imports these functions and
calls them as its FIRST line, before a single byte goes over the network.
Bypassing these requires editing this source file; no runtime flag, config
key, or user-supplied instruction does it.

    from sentinel.security.guardrails import enforce_target_authorized, enforce_tier
    reg = enforce_target_authorized(db, domain)          # raises if not registered+verified
    enforce_tier(ActionTier.TIER_B, session_tier)         # raises if canary never passed
    enforce_no_pivot(reg, discovered_host)                # raises if host != registered domain
    enforce_not_halted(db, scan_session)                  # raises if kill switch tripped (DB-fresh check)
"""
from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy.orm import Session

from sentinel.db.models import ActionTier, EnvironmentTier, ScanSession, ScanStatus, TargetRegistration

# Hard ceilings — not configurable, not env-var overridable. Raising these
# numbers requires an in-repo code change, i.e. a reviewed commit.
MAX_DEMONSTRATION_ACCOUNTS = 1
MAX_DEMONSTRATION_DELETIONS = 1


class SentinelGuardrailError(Exception):
    """Base class for every hard-boundary violation. Never caught-and-ignored."""


class UnauthorizedTargetError(SentinelGuardrailError):
    pass


class TierViolationError(SentinelGuardrailError):
    pass


class PivotViolationError(SentinelGuardrailError):
    pass


class DemonstrationBudgetExceededError(SentinelGuardrailError):
    pass


class ScanHaltedError(SentinelGuardrailError):
    pass


_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})


def normalize_host(value: str) -> str:
    """Extracts a bare hostname for comparison.

    Rejects a non-http(s) scheme explicitly (file://, ftp://, javascript:,
    etc.) rather than silently extracting a same-looking hostname from it —
    without this, `file://example.com/etc/passwd` would normalize to the
    same host as the registered target and pass enforce_no_pivot, with only
    httpx's own scheme rejection (an implementation detail, not a boundary
    this code owns) standing between that URL and being "same host, proceed."
    Bare hostnames (no "://" at all) are unaffected — this only fires for a
    URL that actually declared a scheme.
    """
    value = value.strip().lower()
    has_explicit_scheme = "://" in value
    if not has_explicit_scheme:
        value = f"//{value}"
    parsed = urlparse(value)
    if has_explicit_scheme and parsed.scheme not in _ALLOWED_URL_SCHEMES:
        raise PivotViolationError(
            f"Refusing to process non-HTTP(S) URL scheme '{parsed.scheme}' in '{value}' — "
            "only http/https are permitted"
        )
    host = parsed.hostname or value
    return host.rstrip(".")


def enforce_target_authorized(db: Session, domain: str) -> TargetRegistration:
    """The single gate every scan action must pass. Fails closed.

    Ad hoc domains typed at scan time that are not an active, ownership
    verified row in target_registrations are rejected here — full stop.
    """
    host = normalize_host(domain)
    registration = (
        db.query(TargetRegistration)
        .filter(TargetRegistration.domain == host, TargetRegistration.is_active.is_(True))
        .one_or_none()
    )
    if registration is None:
        raise UnauthorizedTargetError(
            f"'{domain}' is not a registered target. Registration (Phase 0) must complete "
            "before any scan action — no override exists."
        )
    if not registration.is_ownership_verified:
        raise UnauthorizedTargetError(
            f"'{domain}' has not passed domain ownership verification. No scan action is possible."
        )
    return registration


def enforce_no_pivot(registration: TargetRegistration, discovered_host: str) -> None:
    """Recon may find links to other hosts. This stops the agent from ever
    dispatching a test against them, no matter how it justifies it."""
    target_host = normalize_host(registration.domain)
    found_host = normalize_host(discovered_host)
    if found_host != target_host:
        raise PivotViolationError(
            f"Refusing to pivot from registered target '{target_host}' to discovered host "
            f"'{found_host}'. Only the exact registered, verified domain may be tested."
        )


def enforce_tier(requested_tier: ActionTier, environment_tier: EnvironmentTier) -> None:
    """Tier B (destructive/exploitative) actions require a canary check that
    passed THIS session. environment_tier is stamped fresh per ScanSession by
    sentinel.phase0.canary — it is never inherited from a prior session."""
    if requested_tier == ActionTier.TIER_B and environment_tier != EnvironmentTier.VERIFIED_SAFE:
        raise TierViolationError(
            "Tier B (destructive/exploitative) action blocked: environment canary has not "
            "passed for this session. Session is restricted to Tier A (read-only) regardless "
            "of any user instruction to the contrary."
        )


def enforce_not_halted(db: Session, scan_session: ScanSession) -> None:
    """Refreshes status/halted_reason from the DB before checking.

    A halt can be recorded by a completely different thread/session — a
    manual operator halt arrives via its own FastAPI request session, while a
    long-running dispatch loop holds a scan_session object loaded minutes
    earlier in its own session. Checking the in-memory attribute without
    refreshing would let that halt go unnoticed for as long as the current
    engine keeps running. db.refresh() forces a fresh read so an external
    commit becomes visible on the next check, not just the next graph node.

    (Deployed against SQLite specifically, cross-connection visibility here
    depends on SQLite's own transaction semantics — reliable in this
    codebase's default single-engine setup, but for multi-process deployment
    prefer Postgres, where READ COMMITTED guarantees a fresh SELECT always
    sees prior commits.)
    """
    db.refresh(scan_session, attribute_names=["status", "halted_reason"])
    if scan_session.status == ScanStatus.HALTED:
        raise ScanHaltedError(
            f"Scan session {scan_session.id} was halted"
            + (f" ({scan_session.halted_reason})" if scan_session.halted_reason else "")
            + " — no further dispatch calls are permitted for this session."
        )


def enforce_demonstration_budget(
    db: Session, registration: TargetRegistration, action_type: str, requested_count: int
) -> None:
    """Caps mass account creation/deletion to the minimum needed to
    demonstrate one specific finding (e.g. one throwaway IDOR test account).

    For account_creation this is a persistent, cross-session LIFETIME cap on
    `registration` — read fresh from the DB via refresh(), not just this
    call's argument. A caller cannot get a fresh allowance by starting a new
    scan session and asking for "1" again; `record_demonstration_action`
    below is what makes prior creations visible here.
    """
    if action_type == "account_creation":
        db.refresh(registration, attribute_names=["demo_accounts_created"])
        if registration.demo_accounts_created + requested_count > MAX_DEMONSTRATION_ACCOUNTS:
            raise DemonstrationBudgetExceededError(
                f"Refusing to create {requested_count} more account(s) for '{registration.domain}': "
                f"{registration.demo_accounts_created} already created over this target's lifetime, "
                f"cap is {MAX_DEMONSTRATION_ACCOUNTS}."
            )
    elif action_type == "account_deletion" and requested_count > MAX_DEMONSTRATION_DELETIONS:
        raise DemonstrationBudgetExceededError(
            f"Refusing to delete {requested_count} accounts; cap is {MAX_DEMONSTRATION_DELETIONS} "
            "per finding demonstration."
        )


def record_demonstration_action(
    db: Session, registration: TargetRegistration, action_type: str, count: int = 1
) -> None:
    """Call ONLY after the action actually succeeded. This persists the
    lifetime counter enforce_demonstration_budget checks — skip this call and
    the budget silently resets to zero for every new scan session."""
    if action_type == "account_creation":
        registration.demo_accounts_created += count
        db.flush()
