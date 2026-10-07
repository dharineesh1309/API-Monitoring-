"""HTTP routes supplied by the CentralWatch security plugin."""

from __future__ import annotations

import ipaddress
import hashlib
import hmac
import logging
import math
import os
import re
import secrets
import socket
import struct
import subprocess
from asyncio import to_thread
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from threading import RLock
from time import perf_counter
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import httpx
from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from opentelemetry import metrics
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

from .proxy_store import PostgresProxyStore

logger = logging.getLogger("centralwatch_security")

security_router = APIRouter(tags=["Security"])

_meter = metrics.get_meter("centralwatch_security.proxy")
_proxy_request_counter = _meter.create_counter(
    "proxy.requests_total",
    description="Managed API proxy requests",
)
_proxy_duration_histogram = _meter.create_histogram(
    "proxy.request_duration",
    description="Managed API proxy request duration",
    unit="ms",
)
_SUPPORTED_PROXY_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
_GEMINI_PLACEHOLDER_KEY = "replace_with_gemini_api_key"

_FORWARDED_REQUEST_HEADERS = {
    "accept",
    "accept-language",
    "content-type",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-unmodified-since",
    "range",
    "user-agent",
}
_HOP_BY_HOP_RESPONSE_HEADERS = {
    "connection",
    "content-encoding",  # httpx has already decoded response.content
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class ServiceConfig(BaseModel):
    """Validated configuration for one managed upstream API."""

    service_name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$",
    )
    base_url: str = Field(min_length=1, max_length=2048)
    api_key: str = Field(min_length=1, max_length=4096)
    allowed_ips: list[str] = Field(min_length=1, max_length=100)
    role_name: str = Field(
        default="proxy_reader",
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$",
    )
    auth_type: Literal["bearer", "x-goog-api-key"] = "bearer"
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0)

    @field_validator("service_name", "base_url", "role_name", mode="before")
    @classmethod
    def strip_text_fields(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("base_url must be an absolute HTTP or HTTPS URL")
        if parsed.username or parsed.password:
            raise ValueError("base_url must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain a query string or fragment")
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError("api_key must not contain newlines")
        if not value.strip():
            raise ValueError("api_key must not be blank")
        return value

    @field_validator("allowed_ips")
    @classmethod
    def validate_allowed_ips(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw_value in values:
            value = raw_value.strip()
            if not value:
                raise ValueError("allowed_ips cannot contain an empty value")
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address or CIDR: {value}") from exc
            if value not in normalized:
                normalized.append(value)
        return normalized


class ProxyRoleConfig(BaseModel):
    """Permissions assigned to one or more managed proxy services."""

    role_name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$",
    )
    allowed_services: list[str] = Field(min_length=1, max_length=100)
    allowed_methods: list[str] = Field(min_length=1, max_length=7)

    @field_validator("role_name", mode="before")
    @classmethod
    def strip_role_name(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("allowed_services")
    @classmethod
    def validate_allowed_services(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw_value in values:
            value = raw_value.strip()
            if value != "*" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", value):
                raise ValueError(f"Invalid service ID: {value}")
            if value and value not in normalized:
                normalized.append(value)
        if not normalized:
            raise ValueError("At least one allowed service is required")
        return normalized

    @field_validator("allowed_methods")
    @classmethod
    def validate_allowed_methods(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(value.strip().upper() for value in values))
        invalid = [value for value in normalized if value not in _SUPPORTED_PROXY_METHODS]
        if invalid:
            raise ValueError(f"Unsupported HTTP methods: {', '.join(invalid)}")
        return normalized


# Defaults are inserted only when a service/role does not already exist. The
# runtime source of truth is PostgreSQL; these values make a new local install
# immediately testable without overwriting user configuration on restart.
_DEFAULT_EXTERNAL_SERVICES: dict[str, dict[str, Any]] = {
    "weather_api": {
        "base_url": "https://api.open-meteo.com/v1",
        "api_key": "mock_secret_key_123",
        "allowed_ips": ["127.0.0.1", "::1"],
        "role_name": "proxy_reader",
        "token_hash": hashlib.sha256(b"cw_proxy_demo_weather").hexdigest(),
        "token_hint": "...weather",
        "auth_type": "bearer",
        "timeout_seconds": 10.0,
    },
    "mock_service": {
        "base_url": "https://jsonplaceholder.typicode.com",
        "api_key": "mock_secret_key_456",
        "allowed_ips": ["127.0.0.1", "::1"],
        "role_name": "proxy_reader",
        "token_hash": hashlib.sha256(b"cw_proxy_demo_mock").hexdigest(),
        "token_hint": "...o_mock",
        "auth_type": "bearer",
        "timeout_seconds": 10.0,
    },
    "gemini_api": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "api_key": _GEMINI_PLACEHOLDER_KEY,
        "allowed_ips": ["127.0.0.1", "::1"],
        "role_name": "gemini_chat",
        # No usable raw token exists for the placeholder registration. Saving
        # the real key through the dashboard issues a fresh one-time token.
        "token_hash": hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        "token_hint": "not issued",
        "auth_type": "x-goog-api-key",
        "timeout_seconds": 60.0,
    },
}

_DEFAULT_PROXY_ROLES: dict[str, dict[str, Any]] = {
    "proxy_reader": {
        "allowed_services": ["*"],
        "allowed_methods": ["GET", "HEAD", "OPTIONS"],
    },
    "gemini_chat": {
        "allowed_services": ["gemini_api"],
        "allowed_methods": ["POST"],
    },
}
PROXY_USAGE_HISTORY: list[dict[str, Any]] = []
_PROXY_HISTORY_LIMIT = 1000
_proxy_state_lock = RLock()
_proxy_started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
_PROXY_HTTP_LIMITS = httpx.Limits(
    max_connections=100,
    max_keepalive_connections=20,
    keepalive_expiry=30.0,
)


@asynccontextmanager
async def _proxy_lifespan(app):
    """Start the proxy database and its shared upstream connection pool."""

    store = getattr(app.state, "centralwatch_proxy_store", None)
    owns_store = store is None
    if owns_store:
        store = PostgresProxyStore.from_environment()
        app.state.centralwatch_proxy_store = store

    http_client = getattr(app.state, "centralwatch_proxy_http_client", None)
    owns_http_client = http_client is None
    try:
        await store.start(_DEFAULT_EXTERNAL_SERVICES, _DEFAULT_PROXY_ROLES)
        logger.info("CentralWatch proxy configuration store is ready")
        if owns_http_client:
            http_client = httpx.AsyncClient(
                follow_redirects=False,
                limits=_PROXY_HTTP_LIMITS,
            )
            app.state.centralwatch_proxy_http_client = http_client
        logger.info("CentralWatch proxy upstream connection pool is ready")
        yield
    finally:
        if owns_http_client and http_client is not None:
            await http_client.aclose()
        if owns_store:
            await store.close()
        logger.info("CentralWatch proxy resources stopped")


proxy_router = APIRouter(prefix="/proxy", tags=["API Proxy"], lifespan=_proxy_lifespan)


def _proxy_store(request: Request):
    store = getattr(request.app.state, "centralwatch_proxy_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Proxy configuration database is unavailable.")
    return store


def _proxy_http_client(request: Request):
    client = getattr(request.app.state, "centralwatch_proxy_http_client", None)
    if client is None:
        raise HTTPException(status_code=503, detail="Proxy upstream client is unavailable.")
    return client


async def _database_call(operation, action: str):
    """Translate unavailable/corrupt proxy storage into a safe API response."""

    try:
        return await operation
    except Exception as exc:
        logger.exception("Proxy database operation failed: %s", action)
        raise HTTPException(
            status_code=503,
            detail="Proxy configuration database is unavailable.",
        ) from exc


def _mask_api_key(api_key: str) -> str:
    return f"***{api_key[-4:]}" if len(api_key) > 4 else "***"


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _role_allows(role: dict[str, Any], service_name: str, method: str) -> bool:
    services = role.get("allowed_services", [])
    methods = role.get("allowed_methods", [])
    return ("*" in services or service_name in services) and method.upper() in methods


def _record_proxy_usage(
    *,
    service_name: str,
    method: str,
    path: str,
    client_ip: str,
    status_code: int,
    outcome: str,
    duration_ms: float,
    bytes_in: int = 0,
    bytes_out: int = 0,
    token_hint: str | None = None,
    role_name: str | None = None,
) -> None:
    record = {
        "request_id": f"proxy_{uuid4().hex}",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "service_name": service_name,
        "method": method.upper(),
        "path": f"/{path.lstrip('/')}" if path else "/",
        "client_ip": client_ip,
        "token_hint": token_hint,
        "role_name": role_name,
        "status_code": status_code,
        "outcome": outcome,
        "duration_ms": round(duration_ms, 2),
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
    }
    with _proxy_state_lock:
        PROXY_USAGE_HISTORY.append(record)
        if len(PROXY_USAGE_HISTORY) > _PROXY_HISTORY_LIMIT:
            del PROXY_USAGE_HISTORY[: len(PROXY_USAGE_HISTORY) - _PROXY_HISTORY_LIMIT]

    attributes = {
        "service": service_name,
        "method": method.upper(),
        "status_code": str(status_code),
        "outcome": outcome,
        "role": role_name or "none",
    }
    _proxy_request_counter.add(1, attributes)
    _proxy_duration_histogram.record(duration_ms, attributes)


def _client_ip(request: Request) -> str:
    """Return the direct peer IP used for proxy access control.

    X-Forwarded-For is deliberately not trusted here. Uvicorn may replace
    ``request.client`` when it is configured with a trusted reverse proxy,
    which is the safe layer at which to make that decision.
    """

    client_ip = request.client.host if request.client else "127.0.0.1"
    if (
        os.environ.get("PROXY_DOCKER_HOST_AS_LOOPBACK", "").lower() in {"1", "true", "yes"}
        and client_ip == _docker_default_gateway()
    ):
        # Docker Desktop NAT represents requests to a published localhost port
        # as the bridge gateway. This opt-in exists only for the local demo so
        # the documented 127.0.0.1 allowlist behaves as users expect.
        return "127.0.0.1"
    return client_ip


@lru_cache(maxsize=1)
def _docker_default_gateway() -> str | None:
    """Read the Linux container's default gateway from /proc/net/route."""

    try:
        with open("/proc/net/route", encoding="ascii") as routes:
            next(routes, None)
            for line in routes:
                fields = line.split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    packed = struct.pack("<L", int(fields[2], 16))
                    return socket.inet_ntoa(packed)
    except (OSError, ValueError, struct.error):
        logger.warning("Could not determine the Docker default gateway")
    return None


def _is_ip_allowed(client_ip: str, allowed_ips: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    for allowed in allowed_ips:
        try:
            if address in ipaddress.ip_network(allowed, strict=False):
                return True
        except ValueError:
            logger.error("Ignoring invalid stored proxy CIDR: %s", allowed)
    return False


def _target_url(base_url: str, path: str) -> str:
    safe_path = path.lstrip("/\\")
    return f"{base_url.rstrip('/')}/{safe_path}" if safe_path else base_url.rstrip("/") + "/"


@proxy_router.get("/keys")
async def list_keys(request: Request):
    """List managed services without exposing their secret API keys."""

    services = await _database_call(
        _proxy_store(request).list_services(),
        "list services",
    )
    return [
        {
            "service_name": config["service_name"],
            "base_url": config["base_url"],
            "allowed_ips": config["allowed_ips"],
            "api_key": _mask_api_key(config["api_key"]),
            "role_name": config.get("role_name", "proxy_reader"),
            "token_hint": config.get("token_hint", "unavailable"),
            "auth_type": config.get("auth_type", "bearer"),
            "timeout_seconds": config.get("timeout_seconds", 10.0),
            "secret_configured": config["api_key"] != _GEMINI_PLACEHOLDER_KEY,
        }
        for config in services
    ]


@proxy_router.post("/keys", status_code=201)
async def add_key(config: ServiceConfig, request: Request):
    """Add or replace a managed service configuration."""

    store = _proxy_store(request)
    role = await _database_call(store.get_role(config.role_name), "get role")
    if role is None:
        raise HTTPException(status_code=404, detail="Proxy role not found.")
    access_token = f"cw_proxy_{secrets.token_urlsafe(32)}"
    service = {
        "service_name": config.service_name,
        "base_url": config.base_url,
        "api_key": config.api_key,
        "allowed_ips": config.allowed_ips,
        "role_name": config.role_name,
        "auth_type": config.auth_type,
        "timeout_seconds": config.timeout_seconds,
        "token_hash": _token_digest(access_token),
        "token_hint": f"...{access_token[-6:]}",
    }
    await _database_call(store.upsert_service(service), "upsert service")
    logger.info(
        "Proxy service configured: service=%s base_url=%s allowed_ips=%s",
        config.service_name,
        config.base_url,
        config.allowed_ips,
    )
    return {
        "status": "success",
        "message": f"Service {config.service_name} configured successfully.",
        "service_name": config.service_name,
        "role_name": config.role_name,
        "access_token": access_token,
        "token_hint": f"...{access_token[-6:]}",
        "token_message": "Copy this proxy token now. CentralWatch stores only its SHA-256 hash.",
    }


@proxy_router.post("/keys/{service_name}/rotate-token")
async def rotate_proxy_token(service_name: str, request: Request):
    """Rotate a service's proxy token and return the new value once."""

    store = _proxy_store(request)
    service = await _database_call(store.get_service(service_name), "get service")
    if not service:
        raise HTTPException(status_code=404, detail="Service not found in CentralWatch registry.")
    access_token = f"cw_proxy_{secrets.token_urlsafe(32)}"
    token_hint = f"...{access_token[-6:]}"
    updated = await _database_call(
        store.update_service_token(service_name, _token_digest(access_token), token_hint),
        "rotate token",
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Service not found in CentralWatch registry.")
    role_name = service.get("role_name", "proxy_reader")
    logger.warning("Proxy access token rotated: service=%s role=%s", service_name, role_name)
    return {
        "status": "success",
        "service_name": service_name,
        "role_name": role_name,
        "access_token": access_token,
        "token_hint": f"...{access_token[-6:]}",
        "token_message": "Copy this proxy token now. The previous token is no longer valid.",
    }


@proxy_router.get("/roles")
async def list_proxy_roles(request: Request):
    """List role definitions used for machine-to-machine proxy access."""

    store = _proxy_store(request)
    roles = await _database_call(store.list_roles(), "list roles")
    services = await _database_call(store.list_services(), "list services for roles")
    return [
        {
            "role_name": role["role_name"],
            "allowed_services": role["allowed_services"],
            "allowed_methods": role["allowed_methods"],
            "assigned_services": sum(
                service.get("role_name", "proxy_reader") == role["role_name"]
                for service in services
            ),
        }
        for role in roles
    ]


@proxy_router.post("/roles", status_code=201)
async def create_proxy_role(config: ProxyRoleConfig, request: Request):
    """Create or replace a proxy access role."""

    role = {
        "role_name": config.role_name,
        "allowed_services": config.allowed_services,
        "allowed_methods": config.allowed_methods,
    }
    await _database_call(_proxy_store(request).upsert_role(role), "upsert role")
    logger.info(
        "Proxy role configured: role=%s services=%s methods=%s",
        config.role_name,
        config.allowed_services,
        config.allowed_methods,
    )
    return {"status": "success", "message": f"Role {config.role_name} configured."}


@proxy_router.get("/history")
async def proxy_usage_history(
    limit: int = Query(default=100, ge=1, le=500),
    service_name: str | None = None,
    outcome: str | None = None,
):
    """Return recent proxy requests without bodies, secrets, or query values."""

    with _proxy_state_lock:
        records = list(reversed(PROXY_USAGE_HISTORY))
    if service_name:
        records = [item for item in records if item["service_name"] == service_name]
    if outcome:
        records = [item for item in records if item["outcome"] == outcome]
    return records[:limit]


@proxy_router.get("/metrics")
async def proxy_usage_metrics():
    """Aggregate the in-memory proxy request history for the control plane."""

    with _proxy_state_lock:
        records = list(PROXY_USAGE_HISTORY)

    total = len(records)
    successful = sum(item["status_code"] < 400 for item in records)
    blocked = sum(item["outcome"].startswith("blocked") for item in records)
    errors = sum(item["status_code"] >= 500 for item in records)
    five_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
    recent_requests = sum(
        datetime.fromisoformat(item["timestamp"]) >= five_minutes_ago for item in records
    )
    durations = sorted(item["duration_ms"] for item in records)
    average = round(sum(durations) / total, 2) if total else 0.0
    p95_index = max(0, math.ceil(len(durations) * 0.95) - 1) if durations else 0
    p95 = durations[p95_index] if durations else 0.0

    by_service: dict[str, dict[str, Any]] = {}
    by_method: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for item in records:
        method = item["method"]
        status = str(item["status_code"])
        by_method[method] = by_method.get(method, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
        service = by_service.setdefault(
            item["service_name"],
            {"requests": 0, "successful": 0, "blocked": 0, "errors": 0, "duration_total_ms": 0.0},
        )
        service["requests"] += 1
        service["successful"] += item["status_code"] < 400
        service["blocked"] += item["outcome"].startswith("blocked")
        service["errors"] += item["status_code"] >= 500
        service["duration_total_ms"] += item["duration_ms"]

    services = []
    for service_name, values in sorted(by_service.items()):
        count = values.pop("requests")
        duration_total = values.pop("duration_total_ms")
        services.append(
            {
                "service_name": service_name,
                "requests": count,
                **values,
                "average_latency_ms": round(duration_total / count, 2) if count else 0.0,
            }
        )

    return {
        "since": _proxy_started_at,
        "total_requests": total,
        "successful_requests": successful,
        "blocked_requests": blocked,
        "error_requests": errors,
        "success_rate": round(successful / total * 100, 2) if total else 0.0,
        "error_rate": round(errors / total * 100, 2) if total else 0.0,
        "requests_per_minute": round(recent_requests / 5, 2),
        "average_latency_ms": average,
        "p95_latency_ms": p95,
        "bytes_in": sum(item["bytes_in"] for item in records),
        "bytes_out": sum(item["bytes_out"] for item in records),
        "unique_client_ips": len({item["client_ip"] for item in records}),
        "authenticated_proxy_tokens": len(
            {item["token_hint"] for item in records if item["token_hint"]}
        ),
        "by_method": dict(sorted(by_method.items())),
        "by_status": dict(sorted(by_status.items())),
        "by_service": services,
    }


@proxy_router.api_route(
    "/{service_name}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    include_in_schema=False,
)
@proxy_router.api_route(
    "/{service_name}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def api_proxy(
    service_name: str,
    request: Request,
    path: str = "",
    proxy_token: str = Header(default="", alias="X-CentralWatch-Proxy-Token"),
):
    """Authorize, inject the managed key, and forward an API request."""

    started = perf_counter()
    client_ip = _client_ip(request)
    role_name: str | None = None
    token_hint: str | None = None
    store = _proxy_store(request)
    service_config = await _database_call(store.get_service(service_name), "get service for proxy")
    if not service_config:
        _record_proxy_usage(
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=404,
            outcome="service_not_found",
            duration_ms=(perf_counter() - started) * 1000,
        )
        raise HTTPException(status_code=404, detail="Service not found in CentralWatch registry.")

    role_name = service_config.get("role_name", "proxy_reader")
    configured_token_hint = service_config.get("token_hint")

    if not _is_ip_allowed(client_ip, service_config["allowed_ips"]):
        logger.warning(
            "Unauthorized proxy access attempt: client_ip=%s service=%s",
            client_ip,
            service_name,
        )
        _record_proxy_usage(
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=403,
            outcome="blocked_ip",
            duration_ms=(perf_counter() - started) * 1000,
            role_name=role_name,
        )
        raise HTTPException(status_code=403, detail="Your IP is not authorized to use this service.")

    stored_token_hash = service_config.get("token_hash", "")
    supplied_token_hash = _token_digest(proxy_token) if proxy_token else ""
    if not stored_token_hash or not hmac.compare_digest(stored_token_hash, supplied_token_hash):
        _record_proxy_usage(
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=403,
            outcome="blocked_token",
            duration_ms=(perf_counter() - started) * 1000,
            role_name=role_name,
        )
        raise HTTPException(
            status_code=403,
            detail="A valid CentralWatch proxy token is required for this service.",
        )

    token_hint = configured_token_hint

    role = await _database_call(store.get_role(role_name), "get role for proxy")
    if not role or not _role_allows(role, service_name, request.method):
        _record_proxy_usage(
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=403,
            outcome="blocked_role",
            duration_ms=(perf_counter() - started) * 1000,
            token_hint=token_hint,
            role_name=role_name,
        )
        raise HTTPException(
            status_code=403,
            detail="The assigned proxy role does not permit this service or HTTP method.",
        )

    if service_config["api_key"] == _GEMINI_PLACEHOLDER_KEY:
        _record_proxy_usage(
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=503,
            outcome="secret_not_configured",
            duration_ms=(perf_counter() - started) * 1000,
            token_hint=token_hint,
            role_name=role_name,
        )
        raise HTTPException(
            status_code=503,
            detail="The Gemini API key placeholder must be replaced in CentralWatch before use.",
        )

    target_url = _target_url(service_config["base_url"], path)
    headers = {
        name: value
        for name, value in request.headers.items()
        if name.lower() in _FORWARDED_REQUEST_HEADERS
    }
    if service_config.get("auth_type", "bearer") == "x-goog-api-key":
        headers["x-goog-api-key"] = service_config["api_key"]
    else:
        headers["authorization"] = f"Bearer {service_config['api_key']}"
    body = await request.body()

    logger.info(
        "Proxying request: service=%s method=%s target=%s client_ip=%s",
        service_name,
        request.method,
        target_url,
        client_ip,
    )
    client = _proxy_http_client(request)
    try:
        proxy_response = await client.request(
            method=request.method,
            url=target_url,
            params=list(request.query_params.multi_items()),
            headers=headers,
            content=body,
            timeout=float(service_config.get("timeout_seconds", 10.0)),
        )
    except httpx.TimeoutException as exc:
        logger.warning("Proxy upstream timed out: service=%s", service_name)
        _record_proxy_usage(
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=504,
            outcome="upstream_timeout",
            duration_ms=(perf_counter() - started) * 1000,
            bytes_in=len(body),
            token_hint=token_hint,
            role_name=role_name,
        )
        raise HTTPException(status_code=504, detail="The external service timed out.") from exc
    except httpx.RequestError as exc:
        logger.error("Proxy upstream error: service=%s error=%s", service_name, exc)
        _record_proxy_usage(
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=502,
            outcome="upstream_error",
            duration_ms=(perf_counter() - started) * 1000,
            bytes_in=len(body),
            token_hint=token_hint,
            role_name=role_name,
        )
        raise HTTPException(
            status_code=502,
            detail="Error communicating with the external service.",
        ) from exc

    _record_proxy_usage(
        service_name=service_name,
        method=request.method,
        path=path,
        client_ip=client_ip,
        status_code=proxy_response.status_code,
        outcome="success" if proxy_response.status_code < 400 else "upstream_response_error",
        duration_ms=(perf_counter() - started) * 1000,
        bytes_in=len(body),
        bytes_out=len(proxy_response.content),
        token_hint=token_hint,
        role_name=role_name,
    )

    response_headers = {
        name: value
        for name, value in proxy_response.headers.items()
        if name.lower() not in _HOP_BY_HOP_RESPONSE_HEADERS
    }
    return Response(
        content=proxy_response.content,
        status_code=proxy_response.status_code,
        headers=response_headers,
    )


@security_router.post("/security-scan")
async def trigger_security_scan(target_url: str, authorization: str = Header(default="")):
    """Trigger an OWASP ASTF scan and verify that it produced a report."""

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


@security_router.get("/security-scan/report")
async def get_security_scan_report():
    """Return the latest ASTF HTML report to an authenticated operator."""

    report_path = os.environ.get("ASTF_REPORT_PATH", "/app/reports/security-report.html")
    try:
        report_size = os.path.getsize(report_path)
    except OSError as exc:
        raise HTTPException(status_code=404, detail="No security scan report is available yet.") from exc
    if report_size == 0:
        raise HTTPException(status_code=404, detail="The latest security scan report is empty.")

    return FileResponse(
        report_path,
        media_type="text/html",
        filename="centralwatch-security-report.html",
        content_disposition_type="inline",
    )
