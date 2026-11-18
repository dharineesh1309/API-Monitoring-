"""Contract tests for the OWASP security scan control routes."""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from centralwatch_security import routers
from centralwatch_security.routers import create_security_router

OPERATOR = {"Authorization": "Bearer operator-token"}


def _client(get_token_user=lambda token: {"user_id": "operator"} if token == "operator-token" else None) -> TestClient:
    app = FastAPI()
    app.include_router(create_security_router(get_token_user=get_token_user), prefix="/centralwatch")
    return TestClient(app)


@pytest.fixture
def scan_env(tmp_path, monkeypatch):
    script = tmp_path / "security_scan.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    report = tmp_path / "security-report.html"
    launched = []

    def fake_run(cmd, **kwargs):
        launched.append((cmd, kwargs))
        report.write_text("<html><body>verified report</body></html>", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="scan complete", stderr="")

    monkeypatch.setenv("ASTF_SCRIPT_PATH", str(script))
    monkeypatch.setenv("ASTF_REPORT_PATH", str(report))
    monkeypatch.setattr(routers.subprocess, "run", fake_run)
    return SimpleNamespace(script=script, report=report, launched=launched)


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
    assert kwargs["timeout"] == 1800


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


def test_failed_scan_is_reported_as_an_error(scan_env, monkeypatch):
    monkeypatch.setattr(routers.subprocess, "run", lambda *_, **__: SimpleNamespace(returncode=2, stdout="", stderr="boom"))

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
