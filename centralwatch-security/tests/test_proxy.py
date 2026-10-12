"""Contract tests for CentralWatch's managed API proxy."""

from copy import deepcopy

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

    async def update_service_token(self, service_name, token_hash, token_hint):
        service = self.services.get(service_name)
        if not service:
            return False
        service["token_hash"] = token_hash
        service["token_hint"] = token_hint
        return True

    async def list_roles(self):
        return [deepcopy(self.roles[name]) for name in sorted(self.roles)]

    async def get_role(self, role_name):
        role = self.roles.get(role_name)
        return deepcopy(role) if role else None

    async def upsert_role(self, role):
        self.roles[role["role_name"]] = deepcopy(role)


@pytest.fixture(autouse=True)
def restore_service_registry():
    original_history = deepcopy(PROXY_USAGE_HISTORY)
    yield
    PROXY_USAGE_HISTORY.clear()
    PROXY_USAGE_HISTORY.extend(original_history)


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
        response = test_client.get(
            "/centralwatch/proxy/mock_service/users/1",
            headers={"X-Forwarded-For": "127.0.0.1"},
        )

    assert response.status_code == 403


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
