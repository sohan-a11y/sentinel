"""Contract-backed scan lifecycle.

Public callers create a narrow, signed approval and then start a run by
contract ID. They never receive a lease token and never supply a target
domain at run time.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from sentinel.agents.graph import run_scan_pipeline
from sentinel.api.deps import get_db, require_configured_api_key
from sentinel.config import settings
from sentinel.control_plane import service
from sentinel.db.models import ActionTier, ScanContract
from sentinel.phase0 import registry
from sentinel.security.guardrails import PivotViolationError

router = APIRouter(
    prefix="/api/contracts",
    tags=["contracts"],
    dependencies=[Depends(require_configured_api_key)],
)


class CreateContractRequest(BaseModel):
    domain: str = Field(..., description="Previously registered, ownership-verified target domain")
    approved_by: str = Field(..., min_length=1, max_length=255)
    # Reference only, never the email body or any customer credential. The
    # service persists a keyed digest so it can bind a local-runner permit to
    # the out-of-band approval without retaining the underlying record.
    customer_authorization_reference: str | None = Field(default=None, max_length=512)
    allowed_tier: ActionTier = ActionTier.TIER_A
    expires_at: datetime
    max_scan_sessions: int = Field(default=1, ge=1, le=100)
    max_requests: int = Field(default=100, ge=1, le=10_000)


class RevokeContractRequest(BaseModel):
    reason: str = Field(default="approval withdrawn", min_length=1, max_length=1_000)


class IssueCustomerRunnerPermitRequest(BaseModel):
    """Narrower-than-contract paths for a customer-local, read-only runner.

    Methods are deliberately not caller-configurable in this first slice:
    only GET and HEAD are signed into the permit.  Active recipes require a
    separate sandbox contract and independent proxy/fixture controls.
    """

    allowed_path_prefixes: list[str] = Field(default_factory=lambda: ["/"], min_length=1, max_length=32)


def _configuration_error(exc: service.ControlPlaneConfigurationError) -> HTTPException:
    # Never expose signing-key values or diagnostics to an API caller.
    return HTTPException(status_code=503, detail="Authorization control plane is not configured")


@router.post("", status_code=201)
def create_contract(payload: CreateContractRequest, db: Session = Depends(get_db)) -> dict:
    try:
        target = registry.get_active_registration(db, payload.domain)
    except PivotViolationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if target is None:
        raise HTTPException(status_code=404, detail="Target is not an active registration")
    try:
        contract = service.create_scan_contract(
            db,
            registration=target,
            approved_by=payload.approved_by,
            allowed_tier=payload.allowed_tier,
            expires_at=payload.expires_at,
            max_scan_sessions=payload.max_scan_sessions,
            max_requests=payload.max_requests,
            customer_authorization_reference=payload.customer_authorization_reference,
        )
    except service.ControlPlaneConfigurationError as exc:
        raise _configuration_error(exc) from exc
    except service.ContractPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "contract_id": contract.id,
        "target_id": contract.target_id,
        "allowed_tier": contract.allowed_tier.value,
        "status": contract.status.value,
        "expires_at": contract.expires_at.isoformat(),
        "max_scan_sessions": contract.max_scan_sessions,
        "max_requests": contract.max_requests,
    }


@router.post("/{contract_id}/runner-permits", status_code=201)
def issue_customer_runner_permit(
    contract_id: int,
    payload: IssueCustomerRunnerPermitRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Mint a public-key-verifiable permit for a customer-hosted runner.

    This endpoint returns no customer credentials and no control-plane secret.
    It is intentionally restricted to the current Tier-A GET/HEAD recipe
    boundary; an external customer runner must still provide its own local
    revocation source and network egress boundary.
    """
    if (
        settings.deployment_mode != "development"
        or not settings.enable_development_runner_permit_issuance
    ):
        raise HTTPException(
            status_code=503,
            detail="Customer-local permit issuance is disabled",
        )
    contract = db.get(ScanContract, contract_id)
    if contract is None:
        raise HTTPException(status_code=404, detail="Scan contract was not found")
    try:
        permit, issuer_key_id = service.issue_customer_runner_permit(
            db,
            contract=contract,
            allowed_path_prefixes=payload.allowed_path_prefixes,
        )
    except service.ControlPlaneConfigurationError as exc:
        raise _configuration_error(exc) from exc
    except service.ContractIntegrityError:
        raise HTTPException(status_code=409, detail="Scan contract integrity check failed")
    except service.ContractPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (service.ContractStateError, service.LeaseStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return {
        "contract_id": contract.id,
        # The runner's public key must be pinned out-of-band during
        # enrollment. Returning it with a permit would make key substitution
        # possible for a compromised operator/API channel.
        "issuer_key_id": issuer_key_id,
        "permit": permit.to_dict(),
    }


@router.post("/{contract_id}/runs", status_code=202)
def start_contract_run(
    contract_id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)
) -> dict:
    try:
        scan_session = service.start_contract_run(db, contract_id=contract_id)
    except service.ControlPlaneConfigurationError as exc:
        raise _configuration_error(exc) from exc
    except service.ContractIntegrityError:
        # An altered approval is not a recoverable user input error. Do not
        # reveal signed policy internals through this route.
        raise HTTPException(status_code=409, detail="Scan contract integrity check failed")
    except service.ContractStateError as exc:
        if "not found" in str(exc):
            raise HTTPException(status_code=404, detail="Scan contract was not found") from exc
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (service.ContractPolicyError, service.LeaseStateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    # The worker receives its own database session. Commit the complete
    # Phase-0 + lease binding before it is ever scheduled, rather than
    # relying on framework ordering between dependency cleanup and
    # BackgroundTasks.
    db.commit()
    db.refresh(scan_session)
    # The worker derives its target and tier from this committed session. Do
    # not pass request-controlled or separately reloaded authority to the
    # background task, which would create an avoidable post-commit race.
    background_tasks.add_task(run_scan_pipeline, scan_session.id)
    return {
        "contract_id": scan_session.contract_id,
        "scan_session_id": scan_session.id,
        "status": scan_session.status.value,
        "environment_tier": scan_session.environment_tier.value,
        "recipe": "recon.v1",
    }


@router.post("/{contract_id}/revoke")
def revoke_contract(
    contract_id: int,
    payload: RevokeContractRequest,
    db: Session = Depends(get_db),
) -> dict:
    contract = db.get(ScanContract, contract_id)
    if contract is None:
        raise HTTPException(status_code=404, detail="Scan contract was not found")
    service.revoke_contract(db, contract=contract, reason=payload.reason)
    return {
        "contract_id": contract.id,
        "status": contract.status.value,
        "revocation_epoch": contract.revocation_epoch,
    }
