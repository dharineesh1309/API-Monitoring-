"""Contract tests for the OWASP security scan control routes."""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from centralwatch_security import routers
from centralwatch_security.routers import security_router


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(security_router, prefix="/centralwatch")
    return TestClient(app)


def test_security_scan_runs_script_and_returns_report_metadata(tmp_path, monkeypatch):
    script = tmp_path / "security_scan.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    report = tmp_path / "security-report.html"
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        report.write_text("<html><body>verified report</body></html>", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="scan complete", stderr="")

    monkeypatch.setenv("ASTF_SCRIPT_PATH", str(script))
    monkeypatch.setenv("ASTF_REPORT_PATH", str(report))
    monkeypatch.setattr(routers.subprocess, "run", fake_run)

    response = _client().post(
        "/centralwatch/security-scan",
        params={"target_url": "http://127.0.0.1:8000"},
        headers={"Authorization": "Bearer operator-token"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "Scan complete",
        "target": "http://127.0.0.1:8000",
        "report": str(report),
        "report_bytes": report.stat().st_size,
        "findings_detected": False,
    }
    assert captured["cmd"] == [str(script), "http://127.0.0.1:8000", "operator-token"]
    assert captured["kwargs"]["timeout"] == 1800


def test_latest_report_is_served_inline(tmp_path, monkeypatch):
    report = tmp_path / "security-report.html"
    report.write_text("<html><body>latest report</body></html>", encoding="utf-8")
    monkeypatch.setenv("ASTF_REPORT_PATH", str(report))

    response = _client().get("/centralwatch/security-scan/report")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["content-disposition"].startswith("inline;")
    assert "latest report" in response.text


def test_latest_report_returns_404_before_first_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("ASTF_REPORT_PATH", str(tmp_path / "missing.html"))

    response = _client().get("/centralwatch/security-scan/report")

    assert response.status_code == 404
    assert response.json()["detail"] == "No security scan report is available yet."
