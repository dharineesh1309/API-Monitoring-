"""Failure-simulation endpoints — exist ONLY to demonstrate observability."""

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, Request
import httpx

from ..deps import get_container, require_auth
from ..services import Container

# Protected like every business router: these endpoints exist ONLY to exercise
# the observability pipeline, so they require a valid bearer token.
router = APIRouter(prefix="/simulate", tags=["simulate"], dependencies=[Depends(require_auth)])


async def _notify_alertmanager(
    alertname: str,
    summary: str,
    description: str,
    severity: str = "critical",
    extra_labels: dict | None = None,
) -> None:
    """Post an active alert directly to Alertmanager for instant visibility."""
    now = datetime.now(timezone.utc)
    end = now + timedelta(minutes=15)
    labels = {
        "alertname": alertname,
        "service_name": "centralwatch-demo-app",
        "severity": severity,
    }
    if extra_labels:
        labels.update(extra_labels)
    payload = [
        {
            "labels": labels,
            "annotations": {
                "summary": summary,
                "description": description,
            },
            "startsAt": now.isoformat(),
            "endsAt": end.isoformat(),
        }
    ]
    alertmanager_urls = [
        "http://alertmanager:9093/api/v2/alerts",
        "http://127.0.0.1:9093/api/v2/alerts",
    ]
    for url in alertmanager_urls:
        try:
            async with httpx.AsyncClient(timeout=1.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code in {200, 202}:
                    break
        except Exception:
            continue


class SimulatedFailure(Exception):
    """Deliberate 500 error for observability demos."""

    status_code = 500


class SimulatedAWSError(Exception):
    """Deliberate upstream AWS failure (502) for observability demos."""

    status_code = 502


class SimulatedBruteForceBlocked(Exception):
    """Deliberate 403 error for brute-force IP blocking demo."""

    status_code = 403


@router.get("/error", summary="Return HTTP 500 (deliberate error)")
async def simulate_error():
    await _notify_alertmanager(
        alertname="ApplicationErrorDetected",
        summary="Application error (HTTP 500) detected",
        description="Deliberate internal server error triggered on centralwatch-demo-app via /simulate/error.",
        severity="critical",
        extra_labels={"http_status_code": "500"},
    )
    raise SimulatedFailure("Simulated internal server error for observability demo")


@router.get("/timeout", summary="Sleep for several seconds (slow request)")
async def simulate_timeout(container: Container = Depends(get_container)):
    seconds = container.settings.simulate_timeout_seconds
    await asyncio.sleep(seconds)
    return {"status": "ok", "slept_for_seconds": seconds}


@router.get("/s3-error", summary="Attempt an S3 call against an invalid bucket")
async def simulate_s3_error(container: Container = Depends(get_container)):
    bad_bucket = f"centralwatch-invalid-bucket-{uuid4().hex[:8]}"
    try:
        container.s3.client.put_object(Bucket=bad_bucket, Key="demo.txt", Body=b"demo")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        await _notify_alertmanager(
            alertname="AWSS3FailureDetected",
            summary="AWS S3 integration failure (HTTP 502) detected",
            description=f"S3 put_object to invalid bucket '{bad_bucket}' failed with {code}.",
            severity="critical",
            extra_labels={"http_status_code": "502", "error_code": code},
        )
        raise SimulatedAWSError(f"S3 put_object to invalid bucket '{bad_bucket}' failed: {code}") from exc
    raise SimulatedFailure("unreachable: S3 call unexpectedly succeeded")


@router.get("/retry", summary="Retry an AWS SDK call before succeeding (retry demo)")
def simulate_retry(container: Container = Depends(get_container)):
    return container.s3.list_buckets_with_retries()


@router.get("/brute-force", summary="Simulate brute-force attack from untrusted IP")
async def simulate_brute_force(request: Request, container: Container = Depends(get_container)):
    attacker_ip = "198.51.100.42"
    port = request.app.state.settings.port
    proxy_url = f"http://127.0.0.1:{port}/centralwatch/proxy/gemini_api/models/gemini-3.1-flash-lite:generateContent"
    # Execute 5 rapid unauthorized requests from untrusted IP to trigger brute-force block
    for _ in range(5):
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(
                    proxy_url,
                    headers={
                        "X-Forwarded-For": attacker_ip,
                        "X-CentralWatch-Proxy-Token": "unauthorized-brute-force-token",
                        "Content-Type": "application/json",
                    },
                    json={"contents": [{"parts": [{"text": "admin:password"}]}]},
                )
        except Exception:
            pass

    proxy_store = getattr(request.app.state, "centralwatch_proxy_store", None)
    if proxy_store:
        try:
            await proxy_store.quarantine_ip(
                attacker_ip,
                reason="Brute-force attack simulation (repeated unauthorized requests)",
                blocked_by="firewall_auto_defense",
                attempts=5,
            )
        except Exception:
            pass

    await _notify_alertmanager(
        alertname="IPBruteForceBlocked",
        summary="Brute-force attack detected & IP temporarily blocked",
        description=f"Untrusted external IP {attacker_ip} attempted rapid unauthorized requests and was dynamically blocked by CentralWatch firewall.",
        severity="critical",
        extra_labels={"http_status_code": "403", "attacker_ip": attacker_ip},
    )

    raise SimulatedBruteForceBlocked(
        f"Brute-force attack detected from untrusted IP {attacker_ip} (5 rapid requests). "
        f"CentralWatch Security Firewall temporarily blocked the IP with HTTP 403 and logged security violations."
    )


