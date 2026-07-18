"""SQLAlchemy models — the persistent record of everything Sentinel does.

Every table here is additive/append-only in spirit: registrations are
deactivated rather than deleted, findings are never dropped (only marked
unconfirmed), and AuditLogEntry rows are never updated once written (enforced
in sentinel.security.audit_log, not here).
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class VerificationMethod(str, enum.Enum):
    WELL_KNOWN_HTTP = "well_known_http"
    DNS_TXT = "dns_txt"


class EnvironmentTier(str, enum.Enum):
    """Tier the *environment* has earned via the canary check this session.

    UNVERIFIED is the default/fail-closed state. VERIFIED_SAFE is only ever
    set by sentinel.phase0.canary after a live probe succeeds, and it is only
    trusted for the scan session it was checked in for — see
    ScanSession.environment_tier which is stamped independently every run.
    """

    VERIFIED_SAFE = "verified_safe"
    UNVERIFIED = "unverified"


class ActionTier(str, enum.Enum):
    TIER_A = "tier_a"  # read-only / non-destructive
    TIER_B = "tier_b"  # destructive / exploitative


class ScanContractStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ActionLeaseStatus(str, enum.Enum):
    ISSUED = "issued"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    COMPLETED = "completed"


class FindingStatus(str, enum.Enum):
    CONFIRMED = "confirmed"
    UNCONFIRMED = "unconfirmed"  # failed re-verification — needs human review
    PENDING_VERIFICATION = "pending_verification"


class ScanStatus(str, enum.Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    HALTED = "halted"  # kill switch fired
    FAILED = "failed"


class TargetRegistration(Base):
    """The one and only source of truth for 'is this domain in scope'.

    A domain typed at scan time that isn't an active row in this table is
    rejected by sentinel.security.guardrails.enforce_target_authorized —
    that check imports this table directly, it does not ask an LLM.
    """

    __tablename__ = "target_registrations"
    __table_args__ = (UniqueConstraint("domain", name="uq_target_domain"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    account_owner: Mapped[str] = mapped_column(String(255), nullable=False)

    # Phase 0 step 1: ownership verification
    verification_token: Mapped[str] = mapped_column(String(128), nullable=False)
    verification_method: Mapped[VerificationMethod | None] = mapped_column(
        Enum(VerificationMethod), nullable=True
    )
    verification_passed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Phase 0 step 2: environment canary
    canary_marker: Mapped[str] = mapped_column(String(128), nullable=False)
    canary_check_url_template: Mapped[str] = mapped_column(
        Text, nullable=False, doc="URL containing literal '{marker}' placeholder"
    )
    canary_check_method: Mapped[str] = mapped_column(String(8), default="GET")
    last_canary_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_canary_result: Mapped[EnvironmentTier | None] = mapped_column(Enum(EnvironmentTier), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Lifetime, cross-session counter — guardrails.enforce_demonstration_budget
    # checks THIS, not a caller-supplied count, so a fresh scan session can't
    # reset the budget just by starting over.
    demo_accounts_created: Mapped[int] = mapped_column(Integer, default=0)

    scan_sessions: Mapped[list["ScanSession"]] = relationship(back_populates="target")

    @property
    def is_ownership_verified(self) -> bool:
        # Phase 0 is executing here: this is the exact flag
        # guardrails.enforce_target_authorized reads to decide whether
        # Phase 0 step 1 (domain ownership) has ever passed for this row.
        return self.verification_passed_at is not None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": self.domain,
            "account_owner": self.account_owner,
            "verification_method": self.verification_method.value if self.verification_method else None,
            "verification_passed_at": self.verification_passed_at.isoformat()
            if self.verification_passed_at
            else None,
            "last_canary_check_at": self.last_canary_check_at.isoformat()
            if self.last_canary_check_at
            else None,
            "last_canary_result": self.last_canary_result.value if self.last_canary_result else None,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
        }


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("target_registrations.id"), nullable=False)
    # Contract-backed runs carry an immutable policy binding. Legacy historical
    # sessions may remain null so existing reports stay readable.
    contract_id: Mapped[int | None] = mapped_column(ForeignKey("scan_contracts.id"), nullable=True, index=True)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.RUNNING)

    # Stamped fresh every session by phase0.canary — never inherited/cached
    environment_tier: Mapped[EnvironmentTier] = mapped_column(Enum(EnvironmentTier), default=EnvironmentTier.UNVERIFIED)
    # Stamped from the approved contract at run creation. A null value means
    # a pre-contract historical/internal session, not "Tier B allowed".
    permitted_action_tier: Mapped[ActionTier | None] = mapped_column(Enum(ActionTier), nullable=True)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    halted_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    applicable_cwe_count: Mapped[int] = mapped_column(Integer, default=0)
    not_applicable_cwe_count: Mapped[int] = mapped_column(Integer, default=0)
    tested_cwe_count: Mapped[int] = mapped_column(Integer, default=0)

    target: Mapped["TargetRegistration"] = relationship(back_populates="scan_sessions")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_session")
    cwe_applicability: Mapped[list["CweApplicability"]] = relationship(back_populates="scan_session")


class ScanContract(Base):
    """Immutable, signed Tier-A policy for a verified target.

    The signed fields are deliberately narrow in this first vertical slice:
    one target, one maximum action tier, a request budget, a scan-session
    budget, and a validity window. Higher-risk scope features belong in a
    later versioned manifest rather than silently broadening this record.
    """

    __tablename__ = "scan_contracts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("target_registrations.id"), nullable=False, index=True)
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    # A keyed digest of the customer's out-of-band authorization reference
    # (for example, an official-email ticket ID).  The email/body/reference
    # itself is intentionally never stored in this service.
    customer_authorization_reference_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    allowed_tier: Mapped[ActionTier] = mapped_column(Enum(ActionTier), nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    max_scan_sessions: Mapped[int] = mapped_column(Integer, nullable=False)
    issued_lease_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_requests: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[ScanContractStatus] = mapped_column(
        Enum(ScanContractStatus), default=ScanContractStatus.ACTIVE, nullable=False
    )
    revocation_epoch: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_signature: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class ActionLease(Base):
    """Short-lived internal execution authority for exactly one scan session.

    Only a SHA-256 digest of the high-entropy opaque token is stored. The raw
    token is transient control-plane data and must never be audited or sent to
    the public API.
    """

    __tablename__ = "action_leases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    contract_id: Mapped[int] = mapped_column(ForeignKey("scan_contracts.id"), nullable=False, index=True)
    scan_session_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_sessions.id"), nullable=True, unique=True, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    requested_tier: Mapped[ActionTier] = mapped_column(Enum(ActionTier), nullable=False)
    max_requests: Mapped[int] = mapped_column(Integer, nullable=False)
    requests_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    revocation_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[ActionLeaseStatus] = mapped_column(
        Enum(ActionLeaseStatus), default=ActionLeaseStatus.ISSUED, nullable=False
    )
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    terminal_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class LeaseAction(Base):
    """Auditable reservation made immediately before a contract-run request."""

    __tablename__ = "lease_actions"
    __table_args__ = (UniqueConstraint("lease_id", "request_fingerprint", name="uq_lease_request_fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    lease_id: Mapped[str] = mapped_column(ForeignKey("action_leases.id"), nullable=False, index=True)
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class CweApplicability(Base):
    __tablename__ = "cwe_applicability"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"), nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(16), nullable=False)
    cwe_name: Mapped[str] = mapped_column(String(255), nullable=False)
    applicable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    tested: Mapped[bool] = mapped_column(Boolean, default=False)
    detection_method: Mapped[str | None] = mapped_column(String(32), nullable=True)  # nuclei|zap|custom

    scan_session: Mapped["ScanSession"] = relationship(back_populates="cwe_applicability")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_session_id: Mapped[int] = mapped_column(ForeignKey("scan_sessions.id"), nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(16), nullable=False)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)
    tier: Mapped[ActionTier] = mapped_column(Enum(ActionTier), nullable=False)
    detection_method: Mapped[str] = mapped_column(String(32), nullable=False)  # nuclei|zap|custom
    poc_evidence: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0-1.0
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.PENDING_VERIFICATION)
    verification_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan_session: Mapped["ScanSession"] = relationship(back_populates="findings")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cwe_id": self.cwe_id,
            "endpoint": self.endpoint,
            "tier": self.tier.value,
            "detection_method": self.detection_method,
            "poc_evidence": self.poc_evidence,
            "confidence": self.confidence,
            "status": self.status.value,
            "verification_method": self.verification_method,
            "verification_note": self.verification_note,
            "created_at": self.created_at.isoformat(),
        }


class AuditLogEntry(Base):
    """Append-only, hash-chained. Writes go through sentinel.security.audit_log
    ONLY — no other module should import this model directly for writes."""

    __tablename__ = "audit_log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Stored as a plain ISO-8601 string, not DateTime: SQLite's DateTime
    # round-trip silently drops tzinfo on re-query within the same session,
    # which would make entry_hash unrecomputable from a re-fetched row. The
    # hash is computed over this exact string — it must never be reparsed.
    timestamp: Mapped[str] = mapped_column(String(40), nullable=False)
    agent: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
