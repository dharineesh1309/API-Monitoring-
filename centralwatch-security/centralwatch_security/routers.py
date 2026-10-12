"""On-Demand OWASP ASTF security scanner router for FastAPI.

The router is a factory (``create_security_router``) so the plugin never has to
reach into the host application's internals. The host passes a small
``get_token_user(bearer_token)`` callable that resolves a bearer token into a
user object (any object; ``None``/falsy or an exception means "invalid").

A module-level ``security_router`` instance is kept for backwards compatibility
with the original public API. On hosts that do not pass an explicit resolver it
falls back to ``app.state.container.auth`` (the CentralWatch demo app layout)
and raises a clear 501 if that structure is absent.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import socket
import struct
import subprocess
from asyncio import to_thread
from typing import Any, Callable, Optional

from fastapi import APIRouter, Header, HTTPException, Request

logger = logging.getLogger("centralwatch_security")


def create_security_router(
    get_token_user: Optional[Callable[[str], Optional[Any]]] = None,
    script_path: Optional[str] = None,
    report_path: Optional[str] = None,
    scan_timeout_seconds: Optional[int] = None,
) -> APIRouter:
    """Build the OWASP ASTF security scanner router.

    Exposes a single ``POST /security-scan?target_url=...`` endpoint that runs
    the background ASTF scan in a thread pool and streams the report status back
    to the caller. The endpoint stays protected by the host's own
    ``SecurityEnforcementMiddleware`` (IP/CIDR + revocation) as well as the
    ``get_token_user`` resolver below.

    Args:
        get_token_user: callable resolving a raw bearer token to a user object.
            Raises or returns None/falsy for invalid tokens.
        script_path: absolute path to ``security_scan.sh``. Defaults to the
            ``ASTF_SCRIPT_PATH`` env var, then ``/scripts/security_scan.sh``.
        report_path: report path ASTF must write. Defaults to the
            ``ASTF_REPORT_PATH`` env var, then ``/app/reports/security-report.html``.
        scan_timeout_seconds: subprocess timeout. Defaults to the
            ``ASTF_SCAN_TIMEOUT_SECONDS`` env var (1800s).
    """
    router = APIRouter(tags=["Security"])

    @router.post("/security-scan")
    async def trigger_security_scan(
        target_url: str,
        request: Request,
        authorization: str = Header(default=""),
    ) -> dict:
        """Trigger an OWASP ASTF security scan against ``target_url``.

        The caller's validated bearer token is forwarded to ASTF so the scan can
        perform authenticated checks against the target.
        """
        token = _extract_token(authorization)
        _validate_token(token, get_token_user, request)

        resolved_script = script_path or os.environ.get("ASTF_SCRIPT_PATH", "/scripts/security_scan.sh")
        if not os.path.exists(resolved_script):
            raise HTTPException(status_code=500, detail="Security scan script not configured on the server.")

        resolved_report = report_path or os.environ.get("ASTF_REPORT_PATH", "/app/reports/security-report.html")
        timeout = (
            scan_timeout_seconds
            if scan_timeout_seconds is not None
            else int(os.environ.get("ASTF_SCAN_TIMEOUT_SECONDS", "1800"))
        )

        logger.info("Security scan started: target_url=%s script=%s", target_url, resolved_script)
        try:
            result = await to_thread(
                subprocess.run,
                [resolved_script, target_url, token, resolved_report],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.exception("Security scan timed out: target_url=%s", target_url)
            raise HTTPException(status_code=504, detail="Security scan timed out.") from None
        except OSError as exc:
            logger.exception("Security scan could not be executed: target_url=%s", target_url)
            raise HTTPException(status_code=500, detail=f"Failed to execute security scan: {exc}") from exc

        output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
        if output:
            logger.info("ASTF scan output:\n%s", output)
        if result.returncode not in (0, 1):
            logger.error("Security scan failed: target_url=%s exit_code=%d", target_url, result.returncode)
            raise HTTPException(
                status_code=502,
                detail=f"ASTF security scan failed with exit code {result.returncode}.",
            )
        if result.returncode == 1:
            logger.warning("ASTF scan completed with findings: target_url=%s", target_url)

        try:
            report_size = os.path.getsize(resolved_report)
        except OSError as exc:
            logger.error("Security scan did not produce report: path=%s error=%s", resolved_report, exc)
            raise HTTPException(status_code=502, detail="ASTF scan completed without generating a report.") from exc
        if report_size == 0:
            logger.error("Security scan produced an empty report: path=%s", resolved_report)
            raise HTTPException(status_code=502, detail="ASTF scan generated an empty report.")

        logger.info(
            "Security scan complete: target_url=%s report=%s bytes=%d", target_url, resolved_report, report_size
        )
        return {
            "status": "Scan complete",
            "target": target_url,
            "report": resolved_report,
            "report_bytes": report_size,
            "findings_detected": result.returncode == 1,
        }

    return router


def _extract_token(authorization: str) -> str:
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return token


def _validate_token(token: str, get_token_user: Optional[Callable[[str], Optional[Any]]], request: Request) -> None:
    try:
        if get_token_user is not None:
            user = get_token_user(token)
        else:
            user = _default_token_resolver(token, request)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired bearer token") from exc
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired bearer token")


def _default_token_resolver(token: str, request: Request) -> Optional[Any]:
    """Backwards-compatible resolver for hosts that expose ``app.state.container``."""
    container = getattr(request.app.state, "container", None)
    auth = getattr(container, "auth", None) if container is not None else None
    if auth is None:
        raise HTTPException(
            status_code=501,
            detail=(
                "Security scan endpoint has no token resolver configured. "
                "Use create_security_router(get_token_user=...) in the host application."
            ),
        )
    return auth.get_profile(token)


security_router = create_security_router()
