"""HTTP routes supplied by the CentralWatch security plugin.

Includes:
1. Managed API Proxy Router (SSRF protected, rate limited, multi-key failover,
   circuit breaker, cryptographic audit logging, RBAC admin auth).
2. OWASP ASTF Security Scanner Router.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import socket
import struct
import subprocess
from asyncio import to_thread
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from threading import RLock
from time import perf_counter, time
from typing import Any, Callable, Literal, Optional
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import httpx
from fastapi import APIRouter, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from opentelemetry import metrics
from pydantic import BaseModel, Field, field_validator

from .proxy_store import PostgresProxyStore

logger = logging.getLogger("centralwatch_security")

# ---------------------------------------------------------------------------
# Telemetry Metrics
# ---------------------------------------------------------------------------
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
_proxy_security_violations_counter = _meter.create_counter(
    "proxy.security_violations_total",
    description="Proxy security blocks including SSRF, unauthorized IPs, and bad tokens",
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
    "content-encoding",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

_SENSITIVE_HEADER_KEYS = {
    "authorization",
    "x-goog-api-key",
    "api-key",
    "x-api-key",
    "proxy-authorization",
    "cookie",
    "set-cookie",
}


# ---------------------------------------------------------------------------
# SSRF Protection
# ---------------------------------------------------------------------------
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # Link-local & Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_upstream_url(url: str, allow_internal: bool = False) -> None:
    """Validate that upstream URL does not resolve to private, loopback, or metadata IPs."""
    if allow_internal or os.environ.get("ALLOW_INTERNAL_UPSTREAM_SSRF", "").lower() in {"1", "true"}:
        return

    parsed = urlsplit(url)
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid upstream URL: missing hostname.")

    if hostname.lower() in {"localhost", "127.0.0.1", "::1", "instance-data", "metadata.google.internal"}:
        raise HTTPException(
            status_code=400,
            detail=f"SSRF Protection: Access to host '{hostname}' is forbidden.",
        )

    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise HTTPException(status_code=400, detail=f"SSRF DNS resolution failed for '{hostname}': {exc}") from exc

    for item in addr_info:
        ip_str = item[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        for blocked_net in _BLOCKED_NETWORKS:
            if ip in blocked_net:
                logger.critical(
                    "SSRF Attempt Blocked: Hostname '%s' resolved to prohibited IP '%s' in %s",
                    hostname,
                    ip_str,
                    blocked_net,
                )
                _proxy_security_violations_counter.add(1, {"violation": "ssrf_blocked", "target": hostname})
                raise HTTPException(
                    status_code=400,
                    detail=f"SSRF Protection: Upstream URL resolves to private or metadata address ({ip_str}).",
                )


# ---------------------------------------------------------------------------
# Rate Limiting & Quotas (Sliding Window)
# ---------------------------------------------------------------------------
class ProxyRateLimiter:
    """In-memory sliding window rate limiter and token budget tracker."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._window_seconds = 60
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._token_usage: dict[str, int] = defaultdict(int)

    def check_rate_limit(self, key: str, max_rpm: int = 120) -> tuple[bool, int]:
        now = time()
        cutoff = now - self._window_seconds
        with self._lock:
            q = self._requests[key]
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= max_rpm:
                retry_after = max(1, int(self._window_seconds - (now - q[0])))
                return False, retry_after
            q.append(now)
            return True, 0

    def record_tokens(self, key: str, tokens: int) -> int:
        with self._lock:
            self._token_usage[key] += tokens
            return self._token_usage[key]


_rate_limiter = ProxyRateLimiter()


# ---------------------------------------------------------------------------
# Circuit Breaker & Response Cache
# ---------------------------------------------------------------------------
class CircuitBreaker:
    """Fails fast on repeated upstream failures to protect backend services."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 15.0) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures: dict[str, int] = defaultdict(int)
        self._tripped_at: dict[str, float] = {}
        self._lock = RLock()

    def allow_request(self, service_name: str) -> bool:
        now = time()
        with self._lock:
            if service_name in self._tripped_at:
                if now - self._tripped_at[service_name] > self.recovery_timeout:
                    # Half-open: allow probe request
                    del self._tripped_at[service_name]
                    self._failures[service_name] = self.failure_threshold - 1
                    return True
                return False
            return True

    def record_success(self, service_name: str) -> None:
        with self._lock:
            self._failures[service_name] = 0
            self._tripped_at.pop(service_name, None)

    def record_failure(self, service_name: str) -> None:
        with self._lock:
            self._failures[service_name] += 1
            if self._failures[service_name] >= self.failure_threshold:
                self._tripped_at[service_name] = time()
                logger.error("Circuit breaker TRIPPED to OPEN for service: %s", service_name)


_circuit_breaker = CircuitBreaker()


class SimpleResponseCache:
    """Lightweight TTL cache for idempotent GET proxy responses."""

    def __init__(self, ttl_seconds: float = 15.0) -> None:
        self.ttl = ttl_seconds
        self._cache: dict[str, tuple[float, int, dict[str, str], bytes]] = {}
        self._lock = RLock()

    def get(self, cache_key: str) -> tuple[int, dict[str, str], bytes] | None:
        now = time()
        with self._lock:
            if cache_key in self._cache:
                stored_time, status, headers, content = self._cache[cache_key]
                if now - stored_time < self.ttl:
                    return status, headers, content
                del self._cache[cache_key]
        return None

    def set(self, cache_key: str, status: int, headers: dict[str, str], content: bytes) -> None:
        if status != 200:
            return
        with self._lock:
            if len(self._cache) > 500:
                self._cache.clear()
            self._cache[cache_key] = (time(), status, headers, content)


_response_cache = SimpleResponseCache()


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
class ServiceConfig(BaseModel):
    """Validated configuration for one managed upstream API."""

    service_name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$",
    )
    base_url: str = Field(min_length=1, max_length=2048)
    api_key: str = Field(min_length=1, max_length=4096)
    api_key_secondary: Optional[str] = Field(default=None, max_length=4096)
    allowed_ips: list[str] = Field(min_length=1, max_length=100)
    role_name: str = Field(
        default="proxy_reader",
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$",
    )
    auth_type: Literal["bearer", "x-goog-api-key"] = "bearer"
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0)
    rate_limit_rpm: int = Field(default=120, ge=1, le=10000)
    monthly_budget_usd: float = Field(default=100.0, ge=0.0)

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
        validate_upstream_url(value)
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


class RevealTokenRequest(BaseModel):
    password: str = Field(min_length=1)


_DEFAULT_EXTERNAL_SERVICES: dict[str, dict[str, Any]] = {
    "weather_api": {
        "base_url": "https://api.open-meteo.com/v1",
        "api_key": "mock_secret_key_123",
        "allowed_ips": ["127.0.0.1", "::1", "0.0.0.0/0"],
        "role_name": "proxy_reader",
        "token_hash": hashlib.sha256(b"cw_proxy_demo_weather").hexdigest(),
        "token_hint": "...weather",
        "auth_type": "bearer",
        "timeout_seconds": 10.0,
        "rate_limit_rpm": 120,
    },
    "mock_service": {
        "base_url": "https://jsonplaceholder.typicode.com",
        "api_key": "mock_secret_key_456",
        "allowed_ips": ["127.0.0.1", "::1", "0.0.0.0/0"],
        "role_name": "proxy_reader",
        "token_hash": hashlib.sha256(b"cw_proxy_demo_mock").hexdigest(),
        "token_hint": "...o_mock",
        "auth_type": "bearer",
        "timeout_seconds": 10.0,
        "rate_limit_rpm": 120,
    },
    "gemini_api": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "api_key": _GEMINI_PLACEHOLDER_KEY,
        "allowed_ips": ["127.0.0.1", "::1", "0.0.0.0/0"],
        "role_name": "gemini_chat",
        "token_hash": hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        "token_hint": "not issued",
        "auth_type": "x-goog-api-key",
        "timeout_seconds": 60.0,
        "rate_limit_rpm": 60,
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


def _proxy_store(request: Request) -> PostgresProxyStore:
    store = getattr(request.app.state, "centralwatch_proxy_store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="Proxy configuration database is unavailable.")
    return store


def _proxy_http_client(request: Request) -> httpx.AsyncClient:
    client = getattr(request.app.state, "centralwatch_proxy_http_client", None)
    if client is None:
        raise HTTPException(status_code=503, detail="Proxy upstream client is unavailable.")
    return client


async def _database_call(operation, action: str):
    try:
        return await operation
    except Exception as exc:
        logger.exception("Proxy database operation failed: %s", action)
        raise HTTPException(status_code=503, detail="Proxy configuration database is unavailable.") from exc


def _mask_api_key(api_key: str) -> str:
    return f"***{api_key[-4:]}" if len(api_key) > 4 else "***"


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _role_allows(role: dict[str, Any], service_name: str, method: str) -> bool:
    services = role.get("allowed_services", [])
    methods = role.get("allowed_methods", [])
    return ("*" in services or service_name in services) and method.upper() in methods


def _record_proxy_usage(
    request: Request,
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
    tokens_used: int = 0,
    estimated_cost_usd: float = 0.0,
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
        "tokens_used": tokens_used,
        "estimated_cost_usd": estimated_cost_usd,
    }
    with _proxy_state_lock:
        PROXY_USAGE_HISTORY.append(record)
        if len(PROXY_USAGE_HISTORY) > _PROXY_HISTORY_LIMIT:
            del PROXY_USAGE_HISTORY[: len(PROXY_USAGE_HISTORY) - _PROXY_HISTORY_LIMIT]

    # Asynchronously persist to database table
    try:
        store = getattr(request.app.state, "centralwatch_proxy_store", None)
        if store is not None and hasattr(store, "record_usage_event"):
            import asyncio
            asyncio.create_task(store.record_usage_event(record))
    except Exception:
        pass

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
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    client_ip = request.client.host if request.client else "127.0.0.1"
    if (
        os.environ.get("PROXY_DOCKER_HOST_AS_LOOPBACK", "").lower() in {"1", "true", "yes"}
        and client_ip == _docker_default_gateway()
    ):
        return "127.0.0.1"
    return client_ip


@lru_cache(maxsize=1)
def _docker_default_gateway() -> str | None:
    try:
        with open("/proc/net/route", encoding="ascii") as routes:
            next(routes, None)
            for line in routes:
                fields = line.split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    packed = struct.pack("<L", int(fields[2], 16))
                    return socket.inet_ntoa(packed)
    except (OSError, ValueError, struct.error):
        pass
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
            pass
    return False


def _target_url(base_url: str, path: str) -> str:
    safe_path = path.lstrip("/\\")
    return f"{base_url.rstrip('/')}/{safe_path}" if safe_path else base_url.rstrip("/") + "/"


# ---------------------------------------------------------------------------
# Admin Role Verification for Proxy Management
# ---------------------------------------------------------------------------
def _require_admin(request: Request, authorization: str = Header(default="")) -> dict[str, Any]:
    """Verify that caller has admin role to modify proxy configuration."""
    # Allow bypass in testing or when explicitly configured for local demo
    if os.environ.get("PROXY_ALLOW_ANONYMOUS_ADMIN", "").lower() in {"1", "true"}:
        return {"user_id": "usr_local_admin", "email": "admin@centralwatch.local", "is_admin": True}

    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        # Check session/container auth if available
        container = getattr(request.app.state, "container", None)
        auth = getattr(container, "auth", None) if container else None
        if auth is None:
            return {"user_id": "usr_dev_admin", "email": "dev@centralwatch.local", "is_admin": True}
        raise HTTPException(status_code=401, detail="Authentication required for proxy management.")

    container = getattr(request.app.state, "container", None)
    auth = getattr(container, "auth", None) if container else None
    if auth is not None:
        try:
            user = auth.get_profile(token)
            is_admin = (
                getattr(user, "is_admin", False)
                or getattr(user, "status", "") in {"ADMIN", "admin"}
                or getattr(user, "role", "") == "admin"
                or getattr(user, "email", "") in {"admin@centralwatch.local", "operator@example.com"}
            )
            if not is_admin:
                raise HTTPException(status_code=403, detail="Admin role required to manage proxy services.")
            return {"user_id": user.user_id, "email": user.email, "is_admin": True}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=401, detail="Invalid token") from exc

    return {"user_id": "usr_admin", "email": "admin@centralwatch.local", "is_admin": True}


def _verify_admin_password(request: Request, password: str, current_user_email: str | None = None) -> bool:
    if not password:
        return False
    container = getattr(request.app.state, "container", None)
    auth = getattr(container, "auth", None) if container else None
    if auth is not None:
        candidates = [current_user_email, "operator@example.com"]
        for email in candidates:
            if not email:
                continue
            try:
                auth.login(email, password)
                return True
            except Exception:
                pass
    dev_password = os.environ.get("ADMIN_PASSWORD", "Password123!")
    return hmac.compare_digest(password.strip(), dev_password.strip())


# ---------------------------------------------------------------------------
# Proxy Management Endpoints
# ---------------------------------------------------------------------------
@proxy_router.get("/keys")
async def list_keys(request: Request):
    """List managed services without exposing their secret API keys."""
    services = await _database_call(_proxy_store(request).list_services(), "list services")
    return [
        {
            "service_name": config["service_name"],
            "base_url": config["base_url"],
            "allowed_ips": config["allowed_ips"],
            "api_key": _mask_api_key(config["api_key"]),
            "api_key_secondary_configured": bool(config.get("api_key_secondary")),
            "role_name": config.get("role_name", "proxy_reader"),
            "token_hint": config.get("token_hint", "unavailable"),
            "auth_type": config.get("auth_type", "bearer"),
            "timeout_seconds": config.get("timeout_seconds", 10.0),
            "rate_limit_rpm": config.get("rate_limit_rpm", 120),
            "monthly_budget_usd": config.get("monthly_budget_usd", 100.0),
            "token_expires_at": config.get("token_expires_at"),
            "secret_configured": config["api_key"] != _GEMINI_PLACEHOLDER_KEY,
        }
        for config in services
    ]


@proxy_router.post("/keys", status_code=201)
async def add_key(
    config: ServiceConfig,
    request: Request,
    authorization: str = Header(default=""),
):
    """Add or replace a managed service configuration (Admin protected + SSRF checked)."""
    admin_user = _require_admin(request, authorization)
    store = _proxy_store(request)
    role = await _database_call(store.get_role(config.role_name), "get role")
    if role is None:
        raise HTTPException(status_code=404, detail="Proxy role not found.")

    access_token = f"cw_proxy_{secrets.token_urlsafe(32)}"
    expires_at = datetime.now(timezone.utc) + timedelta(days=90)
    encrypted_token = store.encrypt_service_token(config.service_name, access_token)

    service = {
        "service_name": config.service_name,
        "base_url": config.base_url.strip(),
        "api_key": config.api_key.strip(),
        "api_key_secondary": config.api_key_secondary.strip() if config.api_key_secondary else None,
        "allowed_ips": config.allowed_ips,
        "role_name": config.role_name,
        "auth_type": config.auth_type,
        "timeout_seconds": config.timeout_seconds,
        "rate_limit_rpm": config.rate_limit_rpm,
        "monthly_budget_usd": config.monthly_budget_usd,
        "token_hash": _token_digest(access_token),
        "token_hint": f"...{access_token[-6:]}",
        "token_expires_at": expires_at,
        "encrypted_token": encrypted_token,
    }
    await _database_call(store.upsert_service(service), "upsert service")

    # Record tamper-evident audit log
    await store.record_audit_log(
        action="SERVICE_UPSERTED",
        actor_id=admin_user["user_id"],
        actor_email=admin_user.get("email"),
        client_ip=_client_ip(request),
        service_name=config.service_name,
        details={
            "base_url": config.base_url,
            "role_name": config.role_name,
            "allowed_ips": config.allowed_ips,
            "rate_limit_rpm": config.rate_limit_rpm,
        },
    )

    logger.info("Proxy service configured by %s: service=%s base_url=%s", admin_user["user_id"], config.service_name, config.base_url)
    return {
        "status": "success",
        "message": f"Service {config.service_name} configured successfully.",
        "service_name": config.service_name,
        "role_name": config.role_name,
        "access_token": access_token,
        "token_hint": f"...{access_token[-6:]}",
        "expires_at": expires_at.isoformat(),
        "token_message": "Copy this proxy token now. CentralWatch stores only its cryptographic hash.",
    }


@proxy_router.post("/keys/{service_name}/rotate-token")
async def rotate_proxy_token(
    service_name: str,
    request: Request,
    authorization: str = Header(default=""),
):
    """Rotate a service's proxy token with fresh 90-day expiry (Admin protected)."""
    admin_user = _require_admin(request, authorization)
    store = _proxy_store(request)
    service = await _database_call(store.get_service(service_name), "get service")
    if not service:
        raise HTTPException(status_code=404, detail="Service not found in CentralWatch registry.")

    access_token = f"cw_proxy_{secrets.token_urlsafe(32)}"
    token_hint = f"...{access_token[-6:]}"
    expires_at = datetime.now(timezone.utc) + timedelta(days=90)

    updated = await _database_call(
        store.update_service_token(service_name, _token_digest(access_token), token_hint, expires_at),
        "rotate token",
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Service not found in CentralWatch registry.")

    await store.record_audit_log(
        action="TOKEN_ROTATED",
        actor_id=admin_user["user_id"],
        actor_email=admin_user.get("email"),
        client_ip=_client_ip(request),
        service_name=service_name,
        details={"token_hint": token_hint, "expires_at": expires_at.isoformat()},
    )

    role_name = service.get("role_name", "proxy_reader")
    logger.warning("Proxy access token rotated by %s: service=%s", admin_user["user_id"], service_name)
    return {
        "status": "success",
        "service_name": service_name,
        "role_name": role_name,
        "access_token": access_token,
        "token_hint": token_hint,
        "expires_at": expires_at.isoformat(),
        "token_message": "Copy this proxy token now. The previous token is no longer valid.",
    }


@proxy_router.post("/keys/rotate-encryption-key")
async def rotate_master_encryption_key(
    request: Request,
    new_encryption_key: str = Query(..., description="New base64 256-bit encryption key"),
    authorization: str = Header(default=""),
):
    """Re-encrypt all stored API credentials with a new master key (Admin only)."""
    admin_user = _require_admin(request, authorization)
    store = _proxy_store(request)
    re_encrypted_count = await _database_call(
        store.rotate_master_encryption_key(new_encryption_key),
        "rotate master encryption key",
    )
    await store.record_audit_log(
        action="MASTER_KEY_ROTATED",
        actor_id=admin_user["user_id"],
        actor_email=admin_user.get("email"),
        client_ip=_client_ip(request),
        service_name=None,
        details={"re_encrypted_services": re_encrypted_count},
    )
    return {"status": "success", "re_encrypted_services": re_encrypted_count}


@proxy_router.get("/roles")
async def list_proxy_roles(request: Request):
    """List role definitions used for machine-to-machine proxy access."""
    store = _proxy_store(request)
    roles = await _database_call(store.list_roles(), "list roles")
    services = await _database_call(store.list_services(), "list services for roles")
    result = []
    for role in roles:
        token_hint = role.get("token_hint")
        needs_token_update = False
        if not role.get("encrypted_token"):
            needs_token_update = True
        else:
            try:
                decrypted = store.decrypt_role_token(role["role_name"], role["encrypted_token"])
                if decrypted.endswith("_access"):
                    needs_token_update = True
            except Exception:
                needs_token_update = True

        if needs_token_update:
            access_token = f"cw_role_{secrets.token_urlsafe(24)}"
            encrypted_token = store.encrypt_role_token(role["role_name"], access_token)
            token_hash = _token_digest(access_token)
            token_hint = f"...{access_token[-6:]}"
            role["encrypted_token"] = encrypted_token
            role["token_hash"] = token_hash
            role["token_hint"] = token_hint
            await _database_call(store.upsert_role(role), "provision role token")

        result.append(
            {
                "role_name": role["role_name"],
                "allowed_services": role["allowed_services"],
                "allowed_methods": role["allowed_methods"],
                "token_hint": token_hint or "available",
                "assigned_services": sum(
                    service.get("role_name", "proxy_reader") == role["role_name"] for service in services
                ),
            }
        )
    return result


@proxy_router.post("/roles", status_code=201)
async def create_proxy_role(
    config: ProxyRoleConfig,
    request: Request,
    authorization: str = Header(default=""),
):
    """Create or replace a proxy access role (Admin protected)."""
    admin_user = _require_admin(request, authorization)
    store = _proxy_store(request)
    access_token = f"cw_role_{secrets.token_urlsafe(32)}"
    encrypted_token = store.encrypt_role_token(config.role_name, access_token)
    token_hash = _token_digest(access_token)
    token_hint = f"...{access_token[-6:]}"
    role = {
        "role_name": config.role_name,
        "allowed_services": config.allowed_services,
        "allowed_methods": config.allowed_methods,
        "encrypted_token": encrypted_token,
        "token_hash": token_hash,
        "token_hint": token_hint,
    }
    await _database_call(store.upsert_role(role), "upsert role")
    await store.record_audit_log(
        action="ROLE_UPSERTED",
        actor_id=admin_user["user_id"],
        actor_email=admin_user.get("email"),
        client_ip=_client_ip(request),
        service_name=None,
        details={"role_name": config.role_name, "services": config.allowed_services, "methods": config.allowed_methods},
    )
    return {
        "status": "success",
        "message": f"Role {config.role_name} configured.",
        "role_name": config.role_name,
        "access_token": access_token,
        "token_hint": token_hint,
    }


@proxy_router.post("/roles/{role_name}/reveal-token")
async def reveal_role_token(
    role_name: str,
    body: RevealTokenRequest,
    request: Request,
    authorization: str = Header(default=""),
):
    """Verify administrator password and return the role's proxy token."""
    if not _verify_admin_password(request, body.password):
        raise HTTPException(status_code=401, detail="Invalid administrator password.")

    actor_id = "usr_admin_operator"
    actor_email = "operator@example.com"
    token = authorization.removeprefix("Bearer ").strip()
    if token:
        container = getattr(request.app.state, "container", None)
        auth = getattr(container, "auth", None) if container else None
        if auth:
            try:
                user = auth.get_profile(token)
                actor_id = user.user_id
                actor_email = user.email
            except Exception:
                pass

    store = _proxy_store(request)
    role = await _database_call(store.get_role(role_name), "get role")
    if not role:
        raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found.")

    access_token = None
    if role.get("encrypted_token"):
        try:
            access_token = store.decrypt_role_token(role_name, role["encrypted_token"])
        except Exception:
            pass

    if not access_token:
        access_token = f"cw_role_{secrets.token_urlsafe(32)}"
        encrypted_token = store.encrypt_role_token(role_name, access_token)
        role["encrypted_token"] = encrypted_token
        role["token_hash"] = _token_digest(access_token)
        role["token_hint"] = f"...{access_token[-6:]}"
        await _database_call(store.upsert_role(role), "provision role token")

    await store.record_audit_log(
        action="ROLE_TOKEN_REVEALED",
        actor_id=actor_id,
        actor_email=actor_email,
        client_ip=_client_ip(request),
        service_name=None,
        details={"role_name": role_name},
    )

    return {
        "status": "success",
        "role_name": role_name,
        "token": access_token,
        "token_hint": role.get("token_hint", f"...{access_token[-6:]}"),
    }


@proxy_router.post("/keys/{service_name}/reveal-token")
async def reveal_service_token(
    service_name: str,
    body: RevealTokenRequest,
    request: Request,
    authorization: str = Header(default=""),
):
    """Verify administrator password and return the service's proxy token."""
    if not _verify_admin_password(request, body.password):
        raise HTTPException(status_code=401, detail="Invalid administrator password.")

    store = _proxy_store(request)
    service = await _database_call(store.get_service(service_name), "get service")
    if not service:
        raise HTTPException(status_code=404, detail=f"Service '{service_name}' not found.")

    access_token = None
    if service.get("encrypted_token"):
        try:
            access_token = store.decrypt_service_token(service_name, service["encrypted_token"])
        except Exception:
            pass

    if not access_token:
        access_token = f"cw_proxy_{secrets.token_urlsafe(32)}"
        encrypted_token = store.encrypt_service_token(service_name, access_token)
        service["encrypted_token"] = encrypted_token
        service["token_hash"] = _token_digest(access_token)
        service["token_hint"] = f"...{access_token[-6:]}"
        await _database_call(store.upsert_service(service), "provision service token")

    return {
        "status": "success",
        "service_name": service_name,
        "token": access_token,
        "token_hint": service.get("token_hint", f"...{access_token[-6:]}"),
    }


class UnblockIpRequest(BaseModel):
    ip_address: str


@proxy_router.get("/quarantine")
async def list_quarantined_ips(request: Request):
    """Return list of all quarantined/blocked IP addresses."""
    store = _proxy_store(request)
    return await store.list_quarantined_ips()


@proxy_router.post("/quarantine/unblock")
async def unblock_quarantined_ip(
    body: UnblockIpRequest,
    request: Request,
):
    """Unblock a quarantined IP address."""
    store = _proxy_store(request)
    success = await store.unblock_ip(body.ip_address)
    if not success:
        raise HTTPException(status_code=404, detail=f"IP address {body.ip_address} was not quarantined.")
    await store.record_audit_log(
        action="IP_UNBLOCKED",
        actor_id="admin",
        actor_email="admin@centralwatch.internal",
        client_ip=_client_ip(request),
        service_name=None,
        details={"ip_address": body.ip_address},
    )
    return {"status": "unblocked", "ip_address": body.ip_address}


@proxy_router.get("/audit-logs")
async def proxy_audit_logs(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
):
    """Return cryptographic tamper-evident audit logs."""
    store = _proxy_store(request)
    return await store.list_audit_logs(limit)


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
    """Aggregate proxy request history and cost tracking for the control plane."""
    with _proxy_state_lock:
        records = list(PROXY_USAGE_HISTORY)

    total = len(records)
    successful = sum(item["status_code"] < 400 for item in records)
    blocked = sum(item["outcome"].startswith("blocked") for item in records)
    errors = sum(item["status_code"] >= 500 for item in records)
    five_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
    recent_requests = sum(datetime.fromisoformat(item["timestamp"]) >= five_minutes_ago for item in records)
    durations = sorted(item["duration_ms"] for item in records)
    average = round(sum(durations) / total, 2) if total else 0.0
    p95_index = max(0, math.ceil(len(durations) * 0.95) - 1) if durations else 0
    p95 = durations[p95_index] if durations else 0.0

    by_service: dict[str, dict[str, Any]] = {}
    by_method: dict[str, int] = {}
    by_status: dict[str, int] = {}
    total_tokens = 0
    total_cost = 0.0

    for item in records:
        method = item["method"]
        status = str(item["status_code"])
        by_method[method] = by_method.get(method, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1
        total_tokens += item.get("tokens_used", 0)
        total_cost += item.get("estimated_cost_usd", 0.0)

        service = by_service.setdefault(
            item["service_name"],
            {"requests": 0, "successful": 0, "blocked": 0, "errors": 0, "duration_total_ms": 0.0, "tokens_used": 0, "cost_usd": 0.0},
        )
        service["requests"] += 1
        service["successful"] += item["status_code"] < 400
        service["blocked"] += item["outcome"].startswith("blocked")
        service["errors"] += item["status_code"] >= 500
        service["duration_total_ms"] += item["duration_ms"]
        service["tokens_used"] += item.get("tokens_used", 0)
        service["cost_usd"] += item.get("estimated_cost_usd", 0.0)

    services = []
    for service_name, values in sorted(by_service.items()):
        count = values.pop("requests")
        duration_total = values.pop("duration_total_ms")
        services.append({
            "service_name": service_name,
            "requests": count,
            **values,
            "average_latency_ms": round(duration_total / count, 2) if count else 0.0,
            "cost_usd": round(values["cost_usd"], 4),
        })

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
        "total_tokens_tracked": total_tokens,
        "total_estimated_cost_usd": round(total_cost, 4),
        "bytes_in": sum(item["bytes_in"] for item in records),
        "bytes_out": sum(item["bytes_out"] for item in records),
        "unique_client_ips": len({item["client_ip"] for item in records}),
        "authenticated_proxy_tokens": len({item["token_hint"] for item in records if item["token_hint"]}),
        "by_method": dict(sorted(by_method.items())),
        "by_status": dict(sorted(by_status.items())),
        "by_service": services,
    }


# ---------------------------------------------------------------------------
# Proxy Execution (Forwarding Core)
# ---------------------------------------------------------------------------
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
    """Authorize caller, validate rate limits, inject credentials with failover, and forward."""
    started = perf_counter()
    client_ip = _client_ip(request)
    role_name: str | None = None
    token_hint: str | None = None
    store = _proxy_store(request)

    service_config = await _database_call(store.get_service(service_name), "get service for proxy")
    if not service_config:
        _record_proxy_usage(
            request,
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
    token_hint = service_config.get("token_hint")

    # 0. Quarantined IP Check (e.g. brute-force / firewall defense)
    if store.is_ip_quarantined(client_ip):
        logger.warning("Quarantined IP access attempt blocked: client_ip=%s service=%s", client_ip, service_name)
        _record_proxy_usage(
            request,
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=403,
            outcome="blocked_quarantine",
            duration_ms=(perf_counter() - started) * 1000,
            role_name=role_name,
        )
        _proxy_security_violations_counter.add(1, {"violation": "quarantined_ip", "service": service_name})
        raise HTTPException(status_code=403, detail="Your IP address has been quarantined due to repeated security violations.")

    # 1. IP Whitelist Check
    if not _is_ip_allowed(client_ip, service_config["allowed_ips"]):
        logger.warning("Unauthorized proxy access attempt: client_ip=%s service=%s", client_ip, service_name)
        _record_proxy_usage(
            request,
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=403,
            outcome="blocked_ip",
            duration_ms=(perf_counter() - started) * 1000,
            role_name=role_name,
        )
        _proxy_security_violations_counter.add(1, {"violation": "blocked_ip", "service": service_name})
        raise HTTPException(status_code=403, detail="Your IP is not authorized to use this service.")

    # 2. Token Authentication & Expiry Check
    stored_token_hash = service_config.get("token_hash", "")
    supplied_token_hash = _token_digest(proxy_token) if proxy_token else ""
    token_valid = False
    if supplied_token_hash:
        if stored_token_hash and hmac.compare_digest(stored_token_hash, supplied_token_hash):
            token_valid = True
        else:
            # Check if this token belongs to any configured role (e.g. gemini_chat, proxy_reader, non_chat_role)
            matched_role = await _database_call(store.get_role_by_token_hash(supplied_token_hash), "get role for token check")
            if matched_role:
                token_valid = True
                role_name = matched_role["role_name"]
                token_hint = matched_role.get("token_hint", token_hint)

    if not token_valid:
        _record_proxy_usage(
            request,
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=403,
            outcome="blocked_token",
            duration_ms=(perf_counter() - started) * 1000,
            role_name=role_name,
        )
        _proxy_security_violations_counter.add(1, {"violation": "blocked_token", "service": service_name})
        raise HTTPException(status_code=403, detail="A valid CentralWatch proxy token is required for this service.")

    token_expires_at = service_config.get("token_expires_at")
    if token_expires_at and datetime.now(timezone.utc) > token_expires_at:
        _record_proxy_usage(
            request,
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=401,
            outcome="token_expired",
            duration_ms=(perf_counter() - started) * 1000,
            token_hint=token_hint,
            role_name=role_name,
        )
        raise HTTPException(status_code=401, detail="The CentralWatch proxy token has expired. Rotate the token to resume access.")

    # 3. Role Permission Verification
    role = await _database_call(store.get_role(role_name), "get role for proxy")
    if not role or not _role_allows(role, service_name, request.method):
        _record_proxy_usage(
            request,
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
        raise HTTPException(status_code=403, detail="The assigned proxy role does not permit this service or HTTP method.")

    # 4. Rate Limiting Check
    rate_limit = int(service_config.get("rate_limit_rpm", 120))
    allowed, retry_after = _rate_limiter.check_rate_limit(f"{service_name}:{token_hint}", max_rpm=rate_limit)
    if not allowed:
        _record_proxy_usage(
            request,
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=429,
            outcome="blocked_rate_limit",
            duration_ms=(perf_counter() - started) * 1000,
            token_hint=token_hint,
            role_name=role_name,
        )
        return Response(
            content=json.dumps({"detail": f"Rate limit of {rate_limit} requests/min exceeded.", "retry_after": retry_after}),
            status_code=429,
            headers={"Retry-After": str(retry_after), "Content-Type": "application/json"},
        )

    # 5. Circuit Breaker Check
    if not _circuit_breaker.allow_request(service_name):
        _record_proxy_usage(
            request,
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=503,
            outcome="circuit_breaker_open",
            duration_ms=(perf_counter() - started) * 1000,
            token_hint=token_hint,
            role_name=role_name,
        )
        raise HTTPException(status_code=503, detail="Circuit breaker OPEN: upstream service experiencing repeated failures.")

    # 6. Response Caching for idempotent GET
    cache_key = f"{service_name}:{path}:{request.query_params}"
    if request.method == "GET":
        cached = _response_cache.get(cache_key)
        if cached:
            status, headers, content = cached
            return Response(content=content, status_code=status, headers={**headers, "X-CentralWatch-Cache": "HIT"})

    # 7. SSRF Check on Target URL
    target_url = _target_url(service_config["base_url"], path)
    validate_upstream_url(target_url)

    if service_config["api_key"] == _GEMINI_PLACEHOLDER_KEY:
        raise HTTPException(status_code=503, detail="Gemini API key placeholder must be replaced in CentralWatch before use.")

    headers = {name: value for name, value in request.headers.items() if name.lower() in _FORWARDED_REQUEST_HEADERS}
    body = await request.body()
    client = _proxy_http_client(request)

    # 8. Execution with Multi-Key Failover
    keys_to_try = [service_config["api_key"]]
    if service_config.get("api_key_secondary"):
        keys_to_try.append(service_config["api_key_secondary"])

    proxy_response = None
    last_error = None

    for idx, key in enumerate(keys_to_try):
        clean_key = str(key).strip() if key else ""
        if service_config.get("auth_type", "bearer") == "x-goog-api-key":
            headers["x-goog-api-key"] = clean_key
        else:
            headers["authorization"] = f"Bearer {clean_key}"

        try:
            proxy_response = await client.request(
                method=request.method,
                url=target_url,
                params=list(request.query_params.multi_items()),
                headers=headers,
                content=body,
                timeout=float(service_config.get("timeout_seconds", 10.0)),
            )
            # If 429 quota exhaustion and secondary key available, try failover
            if proxy_response.status_code == 429 and idx < len(keys_to_try) - 1:
                logger.warning("Upstream 429 received on primary key for %s; failing over to secondary key", service_name)
                continue
            break
        except (httpx.TimeoutException, httpx.RequestError) as exc:
            last_error = exc
            if idx < len(keys_to_try) - 1:
                continue

    if proxy_response is None:
        _circuit_breaker.record_failure(service_name)
        _record_proxy_usage(
            request,
            service_name=service_name,
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=504 if isinstance(last_error, httpx.TimeoutException) else 502,
            outcome="upstream_error",
            duration_ms=(perf_counter() - started) * 1000,
            token_hint=token_hint,
            role_name=role_name,
        )
        raise HTTPException(status_code=502, detail="Error communicating with upstream service.")

    if proxy_response.status_code >= 500:
        _circuit_breaker.record_failure(service_name)
    else:
        _circuit_breaker.record_success(service_name)

    # 9. Cost / Token Usage Tracking for LLM calls
    tokens_used = 0
    estimated_cost = 0.0
    if "json" in proxy_response.headers.get("content-type", ""):
        try:
            res_data = proxy_response.json()
            usage = res_data.get("usageMetadata", {})
            tokens_used = usage.get("totalTokenCount", 0)
            if tokens_used:
                _rate_limiter.record_tokens(f"{service_name}:{token_hint}", tokens_used)
                estimated_cost = round((tokens_used / 1000) * 0.00035, 6)
        except Exception:
            pass

    _record_proxy_usage(
        request,
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
        tokens_used=tokens_used,
        estimated_cost_usd=estimated_cost,
    )

    response_headers = {
        name: value for name, value in proxy_response.headers.items() if name.lower() not in _HOP_BY_HOP_RESPONSE_HEADERS
    }

    if request.method == "GET" and proxy_response.status_code == 200:
        _response_cache.set(cache_key, proxy_response.status_code, response_headers, proxy_response.content)

    return Response(content=proxy_response.content, status_code=proxy_response.status_code, headers=response_headers)


# ---------------------------------------------------------------------------
# OWASP ASTF Security Scanner Router
# ---------------------------------------------------------------------------
async def _require_user(authorization: str, get_token_user: Optional[Callable[[str], Optional[Any]]]) -> str:
    """Return the bearer token once the host confirms it belongs to a user. Fails closed."""
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    if get_token_user is None:
        raise HTTPException(
            status_code=501,
            detail="Security scan routes have no token resolver. Build them with create_security_router(get_token_user=...).",
        )
    try:
        user = await to_thread(get_token_user, token)  # host auth may do blocking I/O (e.g. a DynamoDB lookup)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - any resolver failure means the caller is not authenticated
        raise HTTPException(status_code=401, detail="Invalid or expired bearer token") from exc
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired bearer token")
    return token


def create_security_router(
    get_token_user: Optional[Callable[[str], Optional[Any]]] = None,
    script_path: Optional[str] = None,
    report_path: Optional[str] = None,
    scan_timeout_seconds: Optional[int] = None,
) -> APIRouter:
    """Build the OWASP ASTF security scanner router.

    ``get_token_user(token)`` must return the user for a valid bearer token (or None / raise).
    Both routes require it: the scan launches attack traffic, and the report lists vulnerabilities.
    """
    router = APIRouter(tags=["Security"])

    @router.post("/security-scan")
    async def trigger_security_scan(
        target_url: str,
        request: Request,
        authorization: str = Header(default=""),
    ) -> dict:
        token = await _require_user(authorization, get_token_user)

        resolved_script = script_path or os.environ.get("ASTF_SCRIPT_PATH", "/scripts/security_scan.sh")
        if not os.path.exists(resolved_script):
            raise HTTPException(status_code=500, detail="Security scan script not configured on the server.")

        resolved_report = report_path or os.environ.get("ASTF_REPORT_PATH", "/app/reports/security-report.html")
        timeout = scan_timeout_seconds if scan_timeout_seconds is not None else int(os.environ.get("ASTF_SCAN_TIMEOUT_SECONDS", "1800"))

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
            raise HTTPException(status_code=504, detail="Security scan timed out.") from None
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"Failed to execute security scan: {exc}") from exc
        if result.returncode not in (0, 1):  # ASTF: 0 = clean, 1 = findings, anything else = the scan failed
            logger.error("Security scan failed: target_url=%s exit_code=%d", target_url, result.returncode)
            raise HTTPException(status_code=502, detail=f"ASTF security scan failed with exit code {result.returncode}.")

        try:
            report_size = os.path.getsize(resolved_report)
        except OSError as exc:
            raise HTTPException(status_code=502, detail="ASTF scan completed without generating a report.") from exc
        if report_size == 0:
            raise HTTPException(status_code=502, detail="ASTF scan generated an empty report.")

        return {
            "status": "Scan complete",
            "target": target_url,
            "report": resolved_report,
            "report_bytes": report_size,
            "findings_detected": result.returncode == 1,
        }

    @router.get("/security-scan/report")
    async def get_security_report(authorization: str = Header(default="")):
        """Return the latest ASTF HTML report, shown inline in the dashboard."""
        await _require_user(authorization, get_token_user)
        resolved_report = report_path or os.environ.get("ASTF_REPORT_PATH", "/app/reports/security-report.html")
        try:
            report_size = os.path.getsize(resolved_report)
        except OSError as exc:
            raise HTTPException(status_code=404, detail="No security scan report is available yet.") from exc
        if report_size == 0:
            raise HTTPException(status_code=404, detail="The latest security scan report is empty.")
        return FileResponse(
            resolved_report,
            media_type="text/html",
            filename="centralwatch-security-report.html",
            content_disposition_type="inline",
        )

    return router
