"""Authenticated API for read-only AWS assessment and approved fixes."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException

from ..deps import get_container, require_auth
from ..schemas.security_agent import (
    SecurityRemediationRequest,
    SecurityRemediationResponse,
    SecurityScanResponse,
)
from ..services import Container

router = APIRouter(
    prefix="/security-agent",
    tags=["AWS Security Agent"],
    dependencies=[Depends(require_auth)],
)


@router.post("/scan", response_model=SecurityScanResponse, summary="Scan configured AWS resources")
async def scan_aws_security(container: Container = Depends(get_container)) -> SecurityScanResponse:
    """Run the baseline assessment. This endpoint never changes AWS state."""

    return await asyncio.to_thread(container.security_agent.scan)


@router.get("/latest", response_model=SecurityScanResponse, summary="Return the latest security scan")
def latest_aws_security_scan(container: Container = Depends(get_container)) -> SecurityScanResponse:
    result = container.security_agent.latest_scan()
    if not result:
        raise HTTPException(status_code=404, detail="No AWS security scan is available yet.")
    return result


@router.post(
    "/remediate",
    response_model=SecurityRemediationResponse,
    summary="Apply explicitly confirmed AWS baseline remediations",
)
async def remediate_aws_security(
    body: SecurityRemediationRequest,
    container: Container = Depends(get_container),
) -> SecurityRemediationResponse:
    try:
        return await asyncio.to_thread(
            container.security_agent.remediate,
            body.scan_id,
            body.finding_ids,
            body.confirm,
            body.acknowledgement,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
