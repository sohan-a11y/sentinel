"""Phase 0 HTTP surface: register a domain, verify ownership, check status.

This is the only way a domain enters sentinel — there is no scan endpoint
that accepts an ad hoc domain string; sentinel.security.guardrails rejects
anything not registered+verified here.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from sentinel.api.deps import get_db, require_api_key
from sentinel.phase0 import registry
from sentinel.phase0.exceptions import DomainAlreadyRegisteredError, TargetNotRegisteredError
from sentinel.security.guardrails import PivotViolationError

router = APIRouter(prefix="/api/targets", tags=["targets"], dependencies=[Depends(require_api_key)])


class RegisterTargetRequest(BaseModel):
    domain: str = Field(..., description="Bare hostname, e.g. app.example.com")
    account_owner: str = Field(..., description="Email or identifier of the requester")
    canary_check_url_template: str = Field(
        ..., description="URL containing the literal placeholder '{marker}', e.g. https://app.example.com/api/users/{marker}"
    )
    canary_check_method: str = "GET"


class RegisterTargetResponse(BaseModel):
    domain: str
    verification_token: str
    well_known_instructions: str
    dns_txt_instructions: str
    canary_marker: str
    canary_instructions: str


@router.post("/register", response_model=RegisterTargetResponse, status_code=201)
def register_target(payload: RegisterTargetRequest, db: Session = Depends(get_db)) -> RegisterTargetResponse:
    try:
        reg = registry.register_target(
            db,
            domain=payload.domain,
            account_owner=payload.account_owner,
            canary_check_url_template=payload.canary_check_url_template,
            canary_check_method=payload.canary_check_method,
        )
    except DomainAlreadyRegisteredError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (ValueError, PivotViolationError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return RegisterTargetResponse(
        domain=reg.domain,
        verification_token=reg.verification_token,
        well_known_instructions=(
            f"Place a file at https://{reg.domain}/.well-known/sentinel-auth.txt containing exactly: "
            f"{reg.verification_token}"
        ),
        dns_txt_instructions=(
            f"OR create a DNS TXT record at _sentinel-verify.{reg.domain} containing: {reg.verification_token}"
        ),
        canary_marker=reg.canary_marker,
        canary_instructions=(
            "Seed this exact value into your target's own database (e.g. a seeded test-user id) so it can be "
            f"read back through your canary_check_url_template. No Tier B (destructive) test will ever run "
            "unless this value is echoed back by a live probe at scan time."
        ),
    )


@router.post("/{domain}/verify")
def verify_target(domain: str, db: Session = Depends(get_db)) -> dict:
    try:
        reg = registry.run_ownership_verification(db, domain)
    except TargetNotRegisteredError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PivotViolationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "domain": reg.domain,
        "verified": reg.is_ownership_verified,
        "method": reg.verification_method.value if reg.verification_method else None,
    }


@router.get("/{domain}")
def get_target(domain: str, db: Session = Depends(get_db)) -> dict:
    try:
        reg = registry.get_active_registration(db, domain)
    except PivotViolationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if reg is None:
        raise HTTPException(status_code=404, detail=f"'{domain}' is not a registered active target")
    return reg.to_dict()


@router.delete("/{domain}", status_code=204, response_class=Response)
def deactivate_target(domain: str, db: Session = Depends(get_db)) -> Response:
    try:
        registry.deactivate_target(db, domain)
    except PivotViolationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return Response(status_code=204)
