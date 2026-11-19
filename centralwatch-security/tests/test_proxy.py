"""Contract tests for CentralWatch's managed API proxy."""

import base64
import socket
from copy import deepcopy
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from centralwatch_security import routers
from centralwatch_security.routers import (
    PROXY_USAGE_HISTORY,
    proxy_router,
)


class InMemoryProxyStore:
    """Async test double matching the PostgreSQL proxy repository contract."""

    def __init__(self):
        self.services = {}
        self.roles = {}
        self.closed = False
        self.quarantined = {}
        self.audit_logs = []
        self.usage_events = []

    async def start(self, default_services, default_roles):
        for name, service in deepcopy(default_services).items():
            self.services.setdefault(name, {"service_name": name, **service})
        for name, role in deepcopy(default_roles).items():
            self.roles.setdefault(name, {"role_name": name, **role})

    async def close(self):
        self.closed = True

    async def ping(self):
        return None

    async def list_services(self):
        return [deepcopy(self.services[name]) for name in sorted(self.services)]

    async def get_service(self, service_name):
        service = self.services.get(service_name)
        return deepcopy(service) if service else None

    async def upsert_service(self, service):
        self.services[service["service_name"]] = deepcopy(service)

    async def update_service_token(self, service_name, token_hash, token_hint, expires_at=None):
        service = self.services.get(service_name)
        if not service:
            return False
        service["token_hash"] = token_hash
        service["token_hint"] = token_hint
        service["token_expires_at"] = expires_at
        return True

    async def list_roles(self):
        return [deepcopy(self.roles[name]) for name in sorted(self.roles)]

    async def get_role(self, role_name):
        role = self.roles.get(role_name)
        return deepcopy(role) if role else None

    async def upsert_role(self, role):
        self.roles[role["role_name"]] = deepcopy(role)

    async def get_role_by_token_hash(self, token_hash):
        return next((deepcopy(role) for role in self.roles.values() if role.get("token_hash") == token_hash), None)

    # The real store encrypts with AES-GCM; these tests only need an opaque, reversible round trip.
    def encrypt_role_token(self, name, token):
        return base64.b64encode(f"{name}:{token}".encode()[::-1])

    def decrypt_role_token(self, name, envelope):
        return base64.b64decode(envelope)[::-1].decode().removeprefix(f"{name}:")

    encrypt_service_token = encrypt_role_token
    decrypt_service_token = decrypt_role_token

    async def rotate_master_encryption_key(self, new_encoded_key):
        return len(self.services) + len(self.roles)

    def is_ip_quarantined(self, ip_address):
        return ip_address in self.quarantined

    async def unblock_ip(self, ip_address):
        return self.quarantined.pop(ip_address, None) is not None

    async def list_quarantined_ips(self):
        return [deepcopy(entry) for entry in self.quarantined.values()]

    async def record_audit_log(self, action, actor_id, actor_email, client_ip, service_name, details):
        entry = {"action": action, "actor_id": actor_id, "actor_email": actor_email,
                 "client_ip": client_ip, "service_name": service_name, "details": deepcopy(details)}
        self.audit_logs.append(entry)
        return deepcopy(entry)

    async def list_audit_logs(self, limit=100):
        return deepcopy(self.audit_logs[::-1][:limit])

    async def record_usage_event(self, record):
        self.usage_events.append(deepcopy(record))


@pytest.fixture(autouse=True)
def restore_service_registry(monkeypatch):
    # The response cache, rate limiter and circuit breaker are module-level; give every test fresh ones
    # so one test's cached upstream reply cannot answer the next test's request.
    monkeypatch.setattr(routers, "_response_cache", routers.SimpleResponseCache())
    monkeypatch.setattr(routers, "_rate_limiter", routers.ProxyRateLimiter())
    monkeypatch.setattr(routers, "_circuit_breaker", routers.CircuitBreaker())
    original_history = deepcopy(PROXY_USAGE_HISTORY)
    yield
    PROXY_USAGE_HISTORY.clear()
    PROXY_USAGE_HISTORY.extend(original_history)


PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """The SSRF check resolves upstream hosts; answer with a public IP so tests need no network."""
    answers = {}

    def getaddrinfo(host, *_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answers.get(host, PUBLIC_IP), 0))]

    monkeypatch.setattr(routers.socket, "getaddrinfo", getaddrinfo)
    return answers


@pytest.fixture
def proxy_store():
    return InMemoryProxyStore()


@pytest.fixture
def client(proxy_store, monkeypatch):
    monkeypatch.setattr(routers, "_client_ip", lambda _request: "127.0.0.1")
    app = FastAPI()
    app.state.centralwatch_proxy_store = proxy_store
    app.include_router(proxy_router, prefix="/centralwatch")
    with TestClient(app) as test_client:
        yield test_client


def test_list_keys_masks_every_secret(client):
    response = client.get("/centralwatch/proxy/keys")

    assert response.status_code == 200
    services = {service["service_name"]: service for service in response.json()}
    assert services["mock_service"]["api_key"] == "***_456"
    assert "mock_secret_key_456" not in response.text
    assert services["gemini_api"]["auth_type"] == "x-goog-api-key"
    assert services["gemini_api"]["secret_configured"] is False


def test_proxy_reuses_one_upstream_client_and_closes_it(monkeypatch):
    instances = []

    class FakeAsyncClient:
        def __init__(self, **options):
            self.options = options
            self.requests = []
            self.closed = False
            instances.append(self)

        async def request(self, **kwargs):
            self.requests.append(kwargs)
            return httpx.Response(
                200,
                json={"pooled": True},
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

        async def aclose(self):
            self.closed = True

    monkeypatch.setattr(routers, "_client_ip", lambda _request: "127.0.0.1")
    monkeypatch.setattr(routers.httpx, "AsyncClient", FakeAsyncClient)
    app = FastAPI()
    app.state.centralwatch_proxy_store = InMemoryProxyStore()
    app.include_router(proxy_router, prefix="/centralwatch")

    with TestClient(app) as test_client:
        headers = {"X-CentralWatch-Proxy-Token": "cw_proxy_demo_mock"}
        first = test_client.get("/centralwatch/proxy/mock_service/users/1", headers=headers)
        second = test_client.get("/centralwatch/proxy/mock_service/users/2", headers=headers)
        assert first.status_code == 200
        assert second.status_code == 200
        assert len(instances) == 1
        assert len(instances[0].requests) == 2
        assert instances[0].options["follow_redirects"] is False
        assert instances[0].options["limits"] is routers._PROXY_HTTP_LIMITS
        assert all(call["timeout"] == 10.0 for call in instances[0].requests)

    assert instances[0].closed is True


def test_add_key_accepts_cidrs_and_normalizes_values(client):
    response = client.post(
        "/centralwatch/proxy/keys",
        json={
            "service_name": "test_service",
            "base_url": "https://example.com/api/",
            "api_key": "top-secret",
            "allowed_ips": [" 127.0.0.1 ", "10.0.0.0/8", "10.0.0.0/8"],
        },
    )

    assert response.status_code == 201
    result = response.json()
    stored = client.app.state.centralwatch_proxy_store.services["test_service"]
    assert stored["base_url"] == "https://example.com/api"
    assert stored["api_key"] == "top-secret"
    assert stored["allowed_ips"] == ["127.0.0.1", "10.0.0.0/8"]
    assert stored["role_name"] == "proxy_reader"
    assert result["access_token"].startswith("cw_proxy_")
    assert stored["token_hash"] == routers._token_digest(result["access_token"])
    assert result["access_token"] not in str(stored)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("service_name", "bad service"),
        ("base_url", "file:///etc/passwd"),
        ("base_url", "https://user:password@example.com"),
        ("allowed_ips", ["not-an-ip"]),
    ],
)
def test_add_key_rejects_invalid_configuration(client, field, value):
    payload = {
        "service_name": "valid_service",
        "base_url": "https://example.com",
        "api_key": "secret",
        "allowed_ips": ["127.0.0.1"],
    }
    payload[field] = value

    response = client.post("/centralwatch/proxy/keys", json=payload)

    assert response.status_code == 422


def test_proxy_forwards_method_query_body_and_injected_key(client, monkeypatch):
    access_token = "cw_proxy_forwarding_test"
    store = client.app.state.centralwatch_proxy_store
    store.roles["proxy_writer"] = {
        "role_name": "proxy_writer",
        "allowed_services": ["test_service"],
        "allowed_methods": ["POST"],
    }
    store.services["test_service"] = {
        "service_name": "test_service",
        "base_url": "https://upstream.example/v1",
        "api_key": "managed-secret",
        "allowed_ips": ["127.0.0.0/24"],
        "role_name": "proxy_writer",
        "token_hash": routers._token_digest(access_token),
        "token_hint": "...g_test",
    }
    captured = {}

    class FakeAsyncClient:
        async def request(self, **kwargs):
            captured["request"] = kwargs
            request = httpx.Request(kwargs["method"], kwargs["url"])
            return httpx.Response(
                202,
                json={"proxied": True},
                headers={"content-type": "application/json", "connection": "close"},
                request=request,
            )

    client.app.state.centralwatch_proxy_http_client = FakeAsyncClient()

    response = client.post(
        "/centralwatch/proxy/test_service/widgets?tag=a&tag=b",
        json={"name": "relay"},
        headers={
            "Authorization": "Bearer caller-secret",
            "X-CentralWatch-Proxy-Token": access_token,
            "X-Unsafe-Header": "drop-me",
        },
    )

    assert response.status_code == 202
    assert response.json() == {"proxied": True}
    assert captured["request"]["url"] == "https://upstream.example/v1/widgets"
    assert captured["request"]["params"] == [("tag", "a"), ("tag", "b")]
    assert captured["request"]["headers"]["authorization"] == "Bearer managed-secret"
    assert "x-unsafe-header" not in captured["request"]["headers"]
    assert response.headers.get("connection") is None


def test_proxy_injects_gemini_key_header(client, monkeypatch):
    access_token = "cw_proxy_gemini_test"
    store = client.app.state.centralwatch_proxy_store
    store.roles["gemini_test"] = {
        "role_name": "gemini_test",
        "allowed_services": ["gemini_test_service"],
        "allowed_methods": ["POST"],
    }
    store.services["gemini_test_service"] = {
        "service_name": "gemini_test_service",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "api_key": "real-gemini-key",
        "allowed_ips": ["127.0.0.1"],
        "role_name": "gemini_test",
        "auth_type": "x-goog-api-key",
        "timeout_seconds": 60.0,
        "token_hash": routers._token_digest(access_token),
        "token_hint": "...i_test",
    }
    captured = {}

    class FakeAsyncClient:
        async def request(self, **kwargs):
            captured.update(kwargs)
            return httpx.Response(
                200,
                json={"candidates": []},
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

    client.app.state.centralwatch_proxy_http_client = FakeAsyncClient()
    response = client.post(
        "/centralwatch/proxy/gemini_test_service/models/gemini-test:generateContent",
        json={"contents": []},
        headers={"X-CentralWatch-Proxy-Token": access_token},
    )

    assert response.status_code == 200
    assert captured["headers"]["x-goog-api-key"] == "real-gemini-key"
    assert "authorization" not in captured["headers"]
    assert captured["timeout"] == 60.0


def test_gemini_placeholder_is_not_sent_upstream(client, monkeypatch):
    access_token = "cw_proxy_placeholder_test"
    store = client.app.state.centralwatch_proxy_store
    store.services["gemini_api"] = {
        **store.services["gemini_api"],
        "token_hash": routers._token_digest(access_token),
        "token_hint": "...r_test",
    }
    called = False

    class ShouldNotBeCalled:
        async def request(self, **_):
            nonlocal called
            called = True

    client.app.state.centralwatch_proxy_http_client = ShouldNotBeCalled()
    response = client.post(
        "/centralwatch/proxy/gemini_api/models/gemini-test:generateContent",
        json={"contents": []},
        headers={"X-CentralWatch-Proxy-Token": access_token},
    )

    assert response.status_code == 503
    assert "placeholder" in response.json()["detail"]
    assert called is False


def test_proxy_denies_ip_outside_allowlist_before_upstream_call(monkeypatch):
    monkeypatch.setattr(routers, "_client_ip", lambda _request: "203.0.113.8")
    app = FastAPI()
    app.state.centralwatch_proxy_store = InMemoryProxyStore()
    app.include_router(proxy_router, prefix="/centralwatch")
    called = False

    class ShouldNotBeCalled:
        async def request(self, **_):
            nonlocal called
            called = True

    app.state.centralwatch_proxy_http_client = ShouldNotBeCalled()

    with TestClient(app) as test_client:
        app.state.centralwatch_proxy_store.services["mock_service"]["allowed_ips"] = ["127.0.0.1", "::1"]
        response = test_client.get(
            "/centralwatch/proxy/mock_service/users/1",
            headers={"X-CentralWatch-Proxy-Token": "cw_proxy_demo_mock"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "Your IP is not authorized to use this service."
    assert called is False


def test_forwarded_for_cannot_spoof_an_allowlisted_ip(monkeypatch):
    monkeypatch.setattr(routers, "_client_ip", lambda _request: "203.0.113.8")
    app = FastAPI()
    app.state.centralwatch_proxy_store = InMemoryProxyStore()
    app.include_router(proxy_router, prefix="/centralwatch")
    with TestClient(app) as test_client:
        app.state.centralwatch_proxy_store.services["mock_service"]["allowed_ips"] = ["127.0.0.1", "::1"]
        response = test_client.get(
            "/centralwatch/proxy/mock_service/users/1",
            headers={"X-Forwarded-For": "127.0.0.1", "X-CentralWatch-Proxy-Token": "cw_proxy_demo_mock"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "Your IP is not authorized to use this service."


def test_proxy_blocks_upstreams_that_resolve_to_internal_addresses(client, fake_dns):
    fake_dns["metadata.attacker.example"] = "169.254.169.254"  # cloud instance-metadata address
    store = client.app.state.centralwatch_proxy_store
    store.services["mock_service"]["base_url"] = "https://metadata.attacker.example"

    response = client.get("/centralwatch/proxy/mock_service/latest", headers={"X-CentralWatch-Proxy-Token": "cw_proxy_demo_mock"})

    assert response.status_code == 400
    assert "SSRF" in response.json()["detail"]


def test_opt_in_docker_gateway_maps_to_loopback(monkeypatch):
    monkeypatch.setenv("PROXY_DOCKER_HOST_AS_LOOPBACK", "true")
    monkeypatch.setattr(routers, "_docker_default_gateway", lambda: "172.18.0.1")
    monkeypatch.setattr(routers, "_client_ip", lambda _request: "127.0.0.1")
    app = FastAPI()
    app.state.centralwatch_proxy_store = InMemoryProxyStore()
    app.include_router(proxy_router, prefix="/centralwatch")

    class FakeAsyncClient:
        async def request(self, **kwargs):
            return httpx.Response(
                200,
                json={"allowed": True},
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

    app.state.centralwatch_proxy_http_client = FakeAsyncClient()

    with TestClient(app) as test_client:
        response = test_client.get(
            "/centralwatch/proxy/mock_service/users/1",
            headers={"X-CentralWatch-Proxy-Token": "cw_proxy_demo_mock"},
        )

    assert response.status_code == 200
    assert response.json() == {"allowed": True}


def test_configured_service_token_and_role_are_both_enforced(client, monkeypatch):
    class FakeAsyncClient:
        async def request(self, **kwargs):
            return httpx.Response(
                200,
                json={"allowed": True},
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

    client.app.state.centralwatch_proxy_http_client = FakeAsyncClient()

    role = client.post(
        "/centralwatch/proxy/roles",
        json={
            "role_name": "protected_reader",
            "allowed_services": ["protected_service"],
            "allowed_methods": ["GET"],
        },
    )
    assert role.status_code == 201
    configured = client.post(
        "/centralwatch/proxy/keys",
        json={
            "service_name": "protected_service",
            "base_url": "https://upstream.example",
            "api_key": "managed-secret",
            "allowed_ips": ["127.0.0.1"],
            "role_name": "protected_reader",
        },
    )
    token = configured.json()["access_token"]
    assert token.startswith("cw_proxy_")
    assert token not in str(client.app.state.centralwatch_proxy_store.services)

    missing = client.get("/centralwatch/proxy/protected_service/data")
    assert missing.status_code == 403

    allowed = client.get(
        "/centralwatch/proxy/protected_service/data",
        headers={"X-CentralWatch-Proxy-Token": token},
    )
    denied_method = client.post(
        "/centralwatch/proxy/protected_service/data",
        headers={"X-CentralWatch-Proxy-Token": token},
    )
    assert allowed.status_code == 200
    assert denied_method.status_code == 403

    rotated = client.post("/centralwatch/proxy/keys/protected_service/rotate-token").json()
    assert rotated["access_token"] != token
    assert client.get(
        "/centralwatch/proxy/protected_service/data",
        headers={"X-CentralWatch-Proxy-Token": token},
    ).status_code == 403
    assert client.get(
        "/centralwatch/proxy/protected_service/data",
        headers={"X-CentralWatch-Proxy-Token": rotated["access_token"]},
    ).status_code == 200


def test_proxy_history_and_metrics_capture_success_and_blocks(client, monkeypatch):
    access_token = "cw_proxy_metrics_test"
    store = client.app.state.centralwatch_proxy_store
    store.roles["metrics_writer"] = {
        "role_name": "metrics_writer",
        "allowed_services": ["metrics_service"],
        "allowed_methods": ["POST"],
    }
    store.services["metrics_service"] = {
        "service_name": "metrics_service",
        "base_url": "https://upstream.example",
        "api_key": "managed-secret",
        "allowed_ips": ["127.0.0.1"],
        "role_name": "metrics_writer",
        "token_hash": routers._token_digest(access_token),
        "token_hint": "...s_test",
    }

    class FakeAsyncClient:
        async def request(self, **kwargs):
            return httpx.Response(
                201,
                content=b"created",
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

    client.app.state.centralwatch_proxy_http_client = FakeAsyncClient()
    assert client.post(
        "/centralwatch/proxy/metrics_service/items",
        content=b"payload",
        headers={"X-CentralWatch-Proxy-Token": access_token},
    ).status_code == 201
    assert client.get("/centralwatch/proxy/unknown/items").status_code == 404

    history = client.get("/centralwatch/proxy/history").json()
    metrics = client.get("/centralwatch/proxy/metrics").json()

    assert len(history) == 2
    assert history[0]["outcome"] == "service_not_found"
    assert history[1]["bytes_in"] == len(b"payload")
    assert "managed-secret" not in str(history)
    assert metrics["total_requests"] == 2
    assert metrics["successful_requests"] == 1
    assert metrics["authenticated_proxy_tokens"] == 1
    assert metrics["by_status"] == {"201": 1, "404": 1}


def _usage(request_id, minute):
    return {
        "request_id": request_id, "timestamp": f"2026-11-19T08:{minute:02d}:00+00:00", "service_name": "gemini_api",
        "method": "POST", "path": "/models/x:generateContent", "client_ip": "127.0.0.1", "token_hint": "...abc123",
        "role_name": "gemini_chat", "status_code": 200, "outcome": "success", "duration_ms": 10.0,
        "bytes_in": 10, "bytes_out": 20, "tokens_used": 50, "estimated_cost_usd": 0.0000175,
    }


def test_usage_history_and_metrics_survive_a_restart(monkeypatch):
    """The database keeps every call; a fresh process must show them again, not an empty page."""
    PROXY_USAGE_HISTORY.clear()  # a new process starts with nothing in memory

    class StoreWithHistory(InMemoryProxyStore):
        async def list_usage_history(self, limit=100, service_name=None, outcome=None):
            return [_usage("proxy_newer", 58), _usage("proxy_older", 57)][:limit]  # newest first, like the database

    app = FastAPI()
    app.state.centralwatch_proxy_store = StoreWithHistory()
    app.include_router(proxy_router, prefix="/centralwatch")
    with TestClient(app) as client:
        history = client.get("/centralwatch/proxy/history").json()
        metrics = client.get("/centralwatch/proxy/metrics").json()

    assert [item["request_id"] for item in history] == ["proxy_newer", "proxy_older"]
    assert metrics["total_requests"] == 2
    assert metrics["total_tokens_tracked"] == 100


class FakeHostAuth:
    """The host application's auth: one administrator and one ordinary user."""

    users = {
        "admin-token": SimpleNamespace(user_id="usr_admin1", email="admin@example.com", is_admin=True, status="ACTIVE", role="admin"),
        "user-token": SimpleNamespace(user_id="usr_user1", email="user@example.com", is_admin=False, status="ACTIVE", role="user"),
    }

    def get_profile(self, token):
        if token not in self.users:
            raise ValueError("unknown token")
        return self.users[token]

    def login(self, email, password):
        if (email, password) != ("admin@example.com", "right-password"):
            raise ValueError("wrong email or password")
        return "admin-token"


@pytest.fixture
def secured_client(proxy_store, monkeypatch):
    monkeypatch.setattr(routers, "_client_ip", lambda _request: "127.0.0.1")
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    app = FastAPI()
    app.state.centralwatch_proxy_store = proxy_store
    app.state.container = SimpleNamespace(auth=FakeHostAuth())
    app.include_router(proxy_router, prefix="/centralwatch")
    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize("path", ["/centralwatch/proxy/roles/proxy_reader/reveal-token", "/centralwatch/proxy/keys/mock_service/reveal-token"])
def test_reveal_needs_a_signed_in_admin_and_their_own_password(secured_client, proxy_store, monkeypatch, path):
    def reveal(token, password):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return secured_client.post(path, json={"password": password}, headers=headers)

    assert reveal(None, "Password123!").status_code == 401  # not signed in, and the old default password is gone
    assert reveal("user-token", "right-password").status_code == 403  # signed in, but not an administrator
    assert reveal("admin-token", "Password123!").status_code == 401  # administrator, wrong password
    assert proxy_store.audit_logs == []  # nothing was revealed so far

    revealed = reveal("admin-token", "right-password")
    assert revealed.status_code == 200 and revealed.json()["token"]
    assert proxy_store.audit_logs[-1]["actor_email"] == "admin@example.com"

    monkeypatch.setenv("ADMIN_PASSWORD", "ops-secret")  # an explicitly configured password still works
    assert reveal("admin-token", "ops-secret").status_code == 200



ADMIN_ONLY = [
    ("get", "/centralwatch/proxy/keys", None),
    ("get", "/centralwatch/proxy/roles", None),
    ("get", "/centralwatch/proxy/history", None),
    ("get", "/centralwatch/proxy/metrics", None),
    ("get", "/centralwatch/proxy/quarantine", None),
    ("get", "/centralwatch/proxy/audit-logs", None),
    ("post", "/centralwatch/proxy/quarantine/unblock", {"ip_address": "198.51.100.42"}),
]


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_ONLY)
def test_management_endpoints_are_for_administrators_only(secured_client, method, path, body):
    def call(token):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return getattr(secured_client, method)(path, headers=headers, **({"json": body} if body else {}))

    assert call(None).status_code == 401  # not signed in
    assert call("user-token").status_code == 403  # signed in, but not an administrator
    assert call("admin-token").status_code in (200, 404)  # 404 only for unblocking an IP that is not quarantined


def test_only_an_administrator_can_unblock_an_ip_and_it_is_audited(secured_client, proxy_store):
    proxy_store.quarantined["198.51.100.42"] = {"ip_address": "198.51.100.42"}

    def unblock(token):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return secured_client.post("/centralwatch/proxy/quarantine/unblock", json={"ip_address": "198.51.100.42"}, headers=headers)

    assert unblock(None).status_code == 401  # a blocked caller cannot release itself
    assert unblock("user-token").status_code == 403
    assert "198.51.100.42" in proxy_store.quarantined
    assert unblock("admin-token").status_code == 200
    assert "198.51.100.42" not in proxy_store.quarantined
    assert proxy_store.audit_logs[-1]["actor_email"] == "admin@example.com"


def test_proxy_health_is_open_and_shows_no_configuration(secured_client):
    response = secured_client.get("/centralwatch/proxy/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
