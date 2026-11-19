"""Contract tests for the OWASP security scan control routes."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from centralwatch_security import routers
from centralwatch_security.routers import create_security_router

OPERATOR = {"Authorization": "Bearer operator-token"}


def _operator(token):
    return {"user_id": "operator"} if token == "operator-token" else None


def _app(get_token_user=_operator, **router_kwargs) -> FastAPI:
    app = FastAPI()
    app.include_router(create_security_router(get_token_user=get_token_user, **router_kwargs), prefix="/centralwatch")
    return app


def _client(get_token_user=_operator, **router_kwargs) -> TestClient:
    return TestClient(_app(get_token_user, **router_kwargs))


@pytest.fixture
def scan_env(tmp_path, monkeypatch):
    """Fakes the scan process. Set ``hang`` to make it run until killed, or ``release`` to make it wait for an event."""
    script = tmp_path / "security_scan.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    report = tmp_path / "security-report.html"
    env = SimpleNamespace(script=script, report=report, launched=[], killed=[], returncode=0, hang=False, release=None, proc=None)

    class FakeProcess:
        pid = 4242

        def __init__(self):
            self.killed = asyncio.Event()

        async def wait(self):
            if env.hang:
                await self.killed.wait()
                return -9
            if env.release is not None:
                await env.release.wait()
            report.write_text("<html><body>verified report</body></html>", encoding="utf-8")
            return env.returncode

    async def fake_exec(*cmd, **kwargs):
        env.launched.append((list(cmd), kwargs))
        env.stdout = kwargs.get("stdout")  # the scan log the router reads progress from
        env.proc = FakeProcess()
        return env.proc

    def fake_kill(pid):
        env.killed.append(pid)
        env.proc.killed.set()

    monkeypatch.setenv("ASTF_SCRIPT_PATH", str(script))
    monkeypatch.setenv("ASTF_REPORT_PATH", str(report))
    monkeypatch.setattr(routers.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(routers, "_kill_process_group", fake_kill)
    return env


def test_security_scan_runs_script_and_returns_report_metadata(scan_env):
    response = _client().post("/centralwatch/security-scan", params={"target_url": "http://127.0.0.1:8000"}, headers=OPERATOR)

    assert response.status_code == 200
    assert response.json() == {
        "status": "Scan complete",
        "target": "http://127.0.0.1:8000",
        "report": str(scan_env.report),
        "report_bytes": scan_env.report.stat().st_size,
        "findings_detected": False,
    }
    cmd, kwargs = scan_env.launched[0]
    assert cmd == [str(scan_env.script), "http://127.0.0.1:8000", "operator-token", str(scan_env.report)]
    assert kwargs["start_new_session"] is True  # so a stop can kill ASTF's java process too, not just the script
    assert scan_env.killed == []


@pytest.mark.parametrize(
    ("target", "token"),
    [
        ("http://127.0.0.1:8000", "operator-token"),
        ("http://localhost:8000/docs", "operator-token"),
        ("http://demo-app:8000", "operator-token"),
        ("http://rest.vulnweb.com/", ""),
        ("https://fake-json-api.mock.beeceptor.com/users", ""),
        ("http://127.0.0.1.attacker.example/", ""),
    ],
)
def test_callers_token_goes_only_to_this_application(scan_env, target, token):
    response = _client(self_hosts={"demo-app"}).post("/centralwatch/security-scan", params={"target_url": target}, headers=OPERATOR)

    assert response.status_code == 200
    assert scan_env.launched[0][0][2] == token


@pytest.mark.anyio
async def test_only_one_scan_runs_at_a_time(scan_env):
    scan_env.release = asyncio.Event()
    transport = httpx.ASGITransport(app=_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        scan = {"params": {"target_url": "http://127.0.0.1:8000"}, "headers": OPERATOR}
        first = asyncio.create_task(client.post("/centralwatch/security-scan", **scan))
        while not scan_env.launched:
            await asyncio.sleep(0.01)

        second = await client.post("/centralwatch/security-scan", **scan)
        scan_env.release.set()
        first = await first

    assert second.status_code == 409
    assert "already running" in second.json()["detail"]
    assert first.status_code == 200
    assert len(scan_env.launched) == 1


ASTF_LINES = b"""\
12:48:58.124 [main] INFO  org.owasp.astf.core.Scanner - No endpoints provided. Attempting endpoint discovery...
12:48:58.438 [main] INFO  org.owasp.astf.core.Scanner - Running 16 test cases against 12 endpoints
12:48:58.456 [] INFO  org.owasp.astf.testcases.BrokenAuthenticationTestCase - Executing ASTF-API2-2023 test on GET /api/v1/products/{id}
12:48:58.616 [] INFO  org.owasp.astf.core.Scanner - Scan progress: 5.2% (10/192 tasks completed)
12:48:58.620 [] INFO  org.owasp.astf.testcases.SqlNoSqlInjectionTestCase - Executing ASTF-INJECTION-2023 test on POST /api/v1/users
"""


@pytest.mark.anyio
async def test_status_shows_astf_progress_while_a_scan_runs(scan_env):
    scan_env.release = asyncio.Event()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=_app()), base_url="http://test") as client:
        assert (await client.get("/centralwatch/security-scan/status", headers=OPERATOR)).json() == {"running": False}
        first = asyncio.create_task(client.post(
            "/centralwatch/security-scan", params={"target_url": "http://127.0.0.1:8000"}, headers=OPERATOR,
        ))
        while not scan_env.launched:
            await asyncio.sleep(0.01)
        scan_env.stdout.write(ASTF_LINES)
        scan_env.stdout.flush()

        status = (await client.get("/centralwatch/security-scan/status", headers=OPERATOR)).json()
        scan_env.release.set()
        assert (await first).status_code == 200
        after = (await client.get("/centralwatch/security-scan/status", headers=OPERATOR)).json()

    assert status["running"] is True
    assert status["target"] == "http://127.0.0.1:8000"
    assert status["phase"] == "Testing endpoints"
    assert (status["percent"], status["tasks_done"], status["tasks_total"], status["endpoints"]) == (5.2, 10, 192, 12)
    assert status["current_test"] == "ASTF-INJECTION-2023 on POST /api/v1/users"
    assert status["limit_seconds"] == 600
    assert after == {"running": False}


def test_progress_reads_the_end_of_a_scan():
    done = ASTF_LINES + b"12:49:01.382 [main] INFO  org.owasp.astf.core.Scanner - Scan completed. Found 4 issues: 0 critical\n"

    progress = routers._scan_progress(done.decode())

    assert (progress["phase"], progress["percent"], progress["tasks_done"], progress["issues_found"]) == ("Writing the report", 100.0, 192, 4)
    assert progress["current_test"] is None
    assert routers._scan_progress("")["phase"] == "Starting the scanner"


@pytest.mark.anyio
async def test_stop_button_stops_the_running_scan_and_everything_it_started(scan_env):
    scan_env.hang = True
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=_app()), base_url="http://test") as client:
        first = asyncio.create_task(client.post(
            "/centralwatch/security-scan", params={"target_url": "http://127.0.0.1:8000"}, headers=OPERATOR,
        ))
        while not scan_env.launched:
            await asyncio.sleep(0.01)

        stop = await client.post("/centralwatch/security-scan/stop", headers=OPERATOR)
        first = await asyncio.wait_for(first, timeout=5)
        again = await client.post("/centralwatch/security-scan/stop", headers=OPERATOR)

    assert stop.status_code == 200
    assert first.status_code == 499
    assert first.json()["detail"] == "The scan was stopped."
    assert scan_env.killed == [4242]
    assert again.status_code == 409  # nothing left to stop


def test_status_and_stop_require_a_recognised_token(scan_env):
    client = _client()
    assert client.get("/centralwatch/security-scan/status").status_code == 401
    assert client.post("/centralwatch/security-scan/stop", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_scan_past_its_time_limit_is_stopped_with_everything_it_started(scan_env):
    scan_env.hang = True

    response = _client(scan_timeout_seconds=0).post(
        "/centralwatch/security-scan", params={"target_url": "http://127.0.0.1:8000"}, headers=OPERATOR
    )

    assert response.status_code == 504
    assert scan_env.killed == [4242]


def test_scan_is_stopped_when_the_browser_goes_away(scan_env):
    """The disconnect arrives through a BaseHTTPMiddleware, like the app's SecurityEnforcementMiddleware."""
    scan_env.hang = True
    app = _app()

    async def passthrough(request, call_next):
        return await call_next(request)

    app.add_middleware(BaseHTTPMiddleware, dispatch=passthrough)
    statuses = []

    async def run():
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
            "path": "/centralwatch/security-scan", "raw_path": b"/centralwatch/security-scan",
            "query_string": b"target_url=http%3A%2F%2F127.0.0.1%3A8000", "root_path": "",
            "headers": [(b"authorization", b"Bearer operator-token"), (b"host", b"test")],
            "client": ("127.0.0.1", 50000), "server": ("test", 80),
        }
        sent = False

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            while not scan_env.launched:  # the browser leaves once the scan has started
                await asyncio.sleep(0.01)
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.start":
                statuses.append(message["status"])

        await asyncio.wait_for(app(scope, receive, send), timeout=5)

    asyncio.run(run())

    assert statuses == [499]
    assert scan_env.killed == [4242]


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer not-a-real-token"}])
def test_security_scan_rejects_callers_the_host_does_not_recognise(scan_env, headers):
    response = _client().post("/centralwatch/security-scan", params={"target_url": "http://example.invalid"}, headers=headers)

    assert response.status_code == 401
    assert scan_env.launched == []  # no attack traffic for unauthenticated callers


def test_security_scan_fails_closed_without_a_token_resolver(scan_env):
    response = _client(get_token_user=None).post(
        "/centralwatch/security-scan", params={"target_url": "http://example.invalid"}, headers=OPERATOR
    )

    assert response.status_code == 501
    assert scan_env.launched == []


def test_failed_scan_is_reported_as_an_error(scan_env):
    scan_env.returncode = 2

    response = _client().post("/centralwatch/security-scan", params={"target_url": "http://127.0.0.1:8000"}, headers=OPERATOR)

    assert response.status_code == 502
    assert "exit code 2" in response.json()["detail"]


def test_latest_report_is_served_inline(tmp_path, monkeypatch):
    report = tmp_path / "security-report.html"
    report.write_text("<html><body>latest report</body></html>", encoding="utf-8")
    monkeypatch.setenv("ASTF_REPORT_PATH", str(report))

    response = _client().get("/centralwatch/security-scan/report", headers=OPERATOR)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["content-disposition"].startswith("inline;")
    assert "latest report" in response.text


def test_latest_report_requires_a_recognised_token(tmp_path, monkeypatch):
    report = tmp_path / "security-report.html"
    report.write_text("<html><body>vulnerability details</body></html>", encoding="utf-8")
    monkeypatch.setenv("ASTF_REPORT_PATH", str(report))

    response = _client().get("/centralwatch/security-scan/report", headers={"Authorization": "Bearer not-a-real-token"})

    assert response.status_code == 401
    assert "vulnerability details" not in response.text


def test_latest_report_returns_404_before_first_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("ASTF_REPORT_PATH", str(tmp_path / "missing.html"))

    response = _client().get("/centralwatch/security-scan/report", headers=OPERATOR)

    assert response.status_code == 404
    assert response.json()["detail"] == "No security scan report is available yet."
