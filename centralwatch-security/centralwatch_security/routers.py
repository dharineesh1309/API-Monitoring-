import os
import subprocess
from asyncio import to_thread
import httpx
from fastapi import APIRouter, Header, HTTPException, Request, Response
import logging

security_router = APIRouter(tags=["Security"])
logger = logging.getLogger("centralwatch_security")

from pydantic import BaseModel
from typing import List

class ServiceConfig(BaseModel):
    service_name: str
    base_url: str
    api_key: str
    allowed_ips: List[str]

# Mock Database mapping a service name to its required API key, base URL, and allowed IPs.
# In a real scenario, this would be stored in a secure encrypted database.
EXTERNAL_SERVICES_DB = {
    "weather_api": {
        "base_url": "https://api.open-meteo.com/v1",
        "api_key": "mock_secret_key_123",
        "allowed_ips": ["127.0.0.1", "::1"]
    },
    "mock_service": {
        "base_url": "https://jsonplaceholder.typicode.com",
        "api_key": "mock_secret_key_456",
        "allowed_ips": ["127.0.0.1", "::1"]
    }
}

@security_router.get("/proxy/keys")
async def list_keys():
    """List all managed services and their configurations (excluding secrets)."""
    return [
        {
            "service_name": name,
            "base_url": config["base_url"],
            "allowed_ips": config["allowed_ips"],
            # Masking API key for security
            "api_key": "***" + config["api_key"][-4:] if len(config["api_key"]) > 4 else "***"
        }
        for name, config in EXTERNAL_SERVICES_DB.items()
    ]

@security_router.post("/proxy/keys")
async def add_key(config: ServiceConfig):
    """Add or update a managed service configuration."""
    EXTERNAL_SERVICES_DB[config.service_name] = {
        "base_url": config.base_url,
        "api_key": config.api_key,
        "allowed_ips": config.allowed_ips
    }
    return {"status": "success", "message": f"Service {config.service_name} configured successfully."}

@security_router.api_route("/proxy/{service_name}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def api_proxy(service_name: str, path: str, request: Request):
    """
    Secure API Proxy Endpoint.
    Instead of clients managing third-party API keys, they send requests here.
    We verify their IP (and optionally their role/token), inject the API key,
    and forward the request to the real service.
    """
    # 1. Look up the requested service
    service_config = EXTERNAL_SERVICES_DB.get(service_name)
    if not service_config:
        raise HTTPException(status_code=404, detail="Service not found in CentralWatch registry.")
    
    # 2. Verify IP (Access Control)
    client_ip = request.client.host if request.client else "127.0.0.1"
    if client_ip not in service_config["allowed_ips"]:
        logger.warning(f"Unauthorized proxy access attempt from {client_ip} for service {service_name}")
        raise HTTPException(status_code=403, detail="Your IP is not authorized to use this service.")
        
    # 3. Prepare the forwarded request
    target_url = f"{service_config['base_url']}/{path}"
    if request.query_params:
        target_url += f"?{request.query_params}"
        
    # We can inject the API key in headers or query params depending on the service.
    # Here we inject it as a Bearer token in the Authorization header.
    headers = dict(request.headers)
    headers.pop("host", None) # Remove original host header
    headers["Authorization"] = f"Bearer {service_config['api_key']}"
    
    body = await request.body()
    
    # 4. Forward the request
    logger.info(f"Proxying request for {service_name} to {target_url}")
    async with httpx.AsyncClient() as client:
        try:
            proxy_response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                timeout=10.0
            )
        except httpx.RequestError as e:
            logger.error(f"Error proxying to {service_name}: {str(e)}")
            raise HTTPException(status_code=502, detail="Error communicating with the external service.")
            
    # 5. Return the response to the client
    return Response(
        content=proxy_response.content,
        status_code=proxy_response.status_code,
        headers=dict(proxy_response.headers)
    )

@security_router.post("/security-scan")
async def trigger_security_scan(target_url: str, authorization: str = Header(default="")):
    """
    Trigger an OWASP ASTF security scan on the specified target.
    The caller's validated bearer token is forwarded to ASTF for authenticated checks.
    """
    script_path = os.environ.get("ASTF_SCRIPT_PATH", "/scripts/security_scan.sh")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=500, detail="Security scan script not configured on the server.")

    token = authorization.removeprefix("Bearer ").strip()
    logger.info("Security scan started: target_url=%s script=%s", target_url, script_path)
    try:
        cmd = [script_path, target_url, token]
        result = await to_thread(
            subprocess.run,
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("ASTF_SCAN_TIMEOUT_SECONDS", "1800")),
        )
    except subprocess.TimeoutExpired:
        logger.exception("Security scan timed out: target_url=%s", target_url)
        raise HTTPException(status_code=504, detail="Security scan timed out.")
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

    report_path = os.environ.get("ASTF_REPORT_PATH", "/app/reports/security-report.html")
    try:
        report_size = os.path.getsize(report_path)
    except OSError as exc:
        logger.error("Security scan did not produce report: path=%s error=%s", report_path, exc)
        raise HTTPException(status_code=502, detail="ASTF scan completed without generating a report.") from exc
    if report_size == 0:
        logger.error("Security scan produced an empty report: path=%s", report_path)
        raise HTTPException(status_code=502, detail="ASTF scan generated an empty report.")

    logger.info("Security scan complete: target_url=%s report=%s bytes=%d", target_url, report_path, report_size)
    return {
        "status": "Scan complete",
        "target": target_url,
        "report": report_path,
        "report_bytes": report_size,
        "findings_detected": result.returncode == 1,
    }
