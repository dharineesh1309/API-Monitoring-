"""Authenticated API for read-only AWS assessment and approved fixes."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..deps import get_container, require_auth
from ..schemas.security_agent import (
    SecurityRemediationRequest,
    SecurityRemediationResponse,
    SecurityScanResponse,
)
from ..services import Container
from ..services.api_astf import DeepTestBusy, deep_test
from ..services.api_inventory import crawl

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


@router.get("/api-inventory", summary="List every API the AWS account exposes, in all enabled regions")
async def api_inventory(probe: bool = False, container: Container = Depends(get_container)) -> dict:
    """Read-only crawl of API Gateway, Lambda URLs, AppSync, CloudFront, load balancers and public EC2.

    ``probe=true`` also sends one unauthenticated GET per readable route and one TLS handshake per host.
    """

    result = await asyncio.to_thread(crawl, container.session, container.settings, probe)
    return container.api_watch.record(result, {"type": "manual", "probe": probe})


@router.get("/api-inventory/latest", summary="The latest API exposure scan (manual, startup or CloudTrail-triggered)")
def latest_api_inventory(container: Container = Depends(get_container)) -> dict:
    if not container.api_watch.latest:
        raise HTTPException(status_code=404, detail="No API exposure scan has run yet.")
    return container.api_watch.latest


class ApiDeepTestRequest(BaseModel):
    api_ids: list[str] | None = None  # None = every public API matching API_SCAN_ALLOWLIST


@router.post("/api-astf", summary="Run OWASP ASTF against allow-listed APIs using their real routes")
async def api_deep_test(
    body: ApiDeepTestRequest | None = None, container: Container = Depends(get_container)
) -> dict:
    """Sends attack traffic (bursts, state-changing calls, injection payloads) to allow-listed APIs only."""

    try:
        return await asyncio.to_thread(
            deep_test, container.session, container.settings, body.api_ids if body else None
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except DeepTestBusy as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


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
