"""Contract tests for the demo chatbot's CentralWatch proxy flow."""

from types import SimpleNamespace

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import chat


def create_client() -> TestClient:
    app = FastAPI()
    app.state.settings = SimpleNamespace(port=8000)
    app.include_router(chat.router)
    return TestClient(app)


def test_chat_requires_centralwatch_proxy_token():
    response = create_client().post("/chat", json={"prompt": "Hello"})

    assert response.status_code == 403
    assert "proxy token" in response.json()["detail"]


def test_chat_sends_prompt_through_centralwatch(monkeypatch):
    captured = {}

    class FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def post(self, url, **kwargs):
            captured["url"] = url
            captured.update(kwargs)
            return httpx.Response(
                200,
                json={
                    "candidates": [
                        {
                            "content": {"parts": [{"text": "CentralWatch protected reply"}]},
                            "finishReason": "STOP",
                        }
                    ]
                },
                request=httpx.Request("POST", url),
            )

    monkeypatch.setattr(chat.httpx, "AsyncClient", FakeAsyncClient)
    response = create_client().post(
        "/chat",
        json={"prompt": "Explain the proxy", "model": "gemini-3.8-flash"},
        headers={"X-CentralWatch-Proxy-Token": "cw_proxy_application_token"},
    )

    assert response.status_code == 200
    assert response.json()["reply"] == "CentralWatch protected reply"
    assert captured["url"].endswith(
        "/centralwatch/proxy/gemini_api/models/gemini-3.8-flash:generateContent"
    )
    assert captured["headers"] == {
        "X-CentralWatch-Proxy-Token": "cw_proxy_application_token"
    }
    assert captured["json"] == {
        "contents": [{"role": "user", "parts": [{"text": "Explain the proxy"}]}]
    }
