"""The ASTF deep test attacks only allow-listed APIs, feeds ASTF their real routes, and maps its findings."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import api_astf

APIS = [
    {
        "source": "API Gateway Http", "region": "ap-south-1", "id": "h1", "name": "cw-lab-orders-api", "public": True,
        "urls": ["https://h1.example"],
        "routes": [
            {"route": "GET /orders/{id}", "auth": "NONE"},
            {"route": "ANY /admin", "auth": "AWS_IAM"},
            {"route": "OPTIONS /orders", "auth": "NONE"},
            {"route": "$default", "auth": "NONE"},
        ],
    },
    {
        "source": "Lambda function URL", "region": "ap-south-1", "id": "prod-fn", "name": "prod-fn", "public": True,
        "urls": ["https://fn.example/"], "routes": [],
    },
]
REPORT = {"findings": [
    {"title": "Missing Authentication Controls", "description": "Open.", "severity": "HIGH",
     "testCaseId": "ASTF-API2-2023", "endpoint": "GET /orders/1", "remediation": "Add auth."},
    {"title": "Possible Injection", "description": "SQL error.", "severity": "INFO",
     "testCaseId": "ASTF-INJECTION-2023", "endpoint": "POST /", "remediation": "Validate input.", "evidence": "syntax error"},
    {"title": "Administrative Endpoint Accessible Without Authorization", "severity": "CRITICAL",  # guessed path
     "testCaseId": "ASTF-API5-2023", "endpoint": "GET /actuator", "remediation": "Restrict it."},
]}
SETTINGS = SimpleNamespace(api_scan_allowlist="cw-lab-*")


@pytest.fixture
def astf_runs(monkeypatch):
    runs = []

    def fake_run(command, **_):
        flags = dict(zip(command[3::2], command[4::2]))  # flag/value pairs after "java -jar <jar>"
        runs.append({"url": flags["-u"], "endpoints": Path(flags["--endpoints-file"]).read_text().splitlines()})
        Path(flags["-o"]).write_text(json.dumps(REPORT))
        return SimpleNamespace(returncode=1, stdout="", stderr="")  # 1 = scan finished with findings

    monkeypatch.setattr(api_astf.subprocess, "run", fake_run)
    monkeypatch.setattr(api_astf, "crawl", lambda *_: {"apis": APIS})
    monkeypatch.setattr(api_astf, "_ensure_jar", lambda: None)
    return runs


def test_deep_test_attacks_only_allow_listed_apis_with_their_real_routes(astf_runs):
    result = api_astf.deep_test(object(), SETTINGS)

    assert astf_runs == [{
        "url": "https://h1.example",
        "endpoints": ["GET /", "GET /admin", "GET /orders/1", "POST /", "POST /admin"],  # no OPTIONS preflight
    }]
    assert result["tested"] == ["cw-lab-orders-api"] and result["skipped"] == ["prod-fn"]
    findings = {f["check"]: f for f in result["findings"]}
    assert findings["ASTF-API2-2023"]["owasp"] == "API2:2023 Broken Authentication"
    assert findings["ASTF-API2-2023"]["severity"] == "high" and findings["ASTF-API2-2023"]["fix"] == "Add auth."
    assert findings["ASTF-INJECTION-2023"]["severity"] == "low"  # ASTF INFO
    assert findings["ASTF-INJECTION-2023"]["evidence"] == "Possible Injection. syntax error"
    assert result["summary"]["findings"] == {"critical": 0, "high": 1, "medium": 0, "low": 1}
    assert result["scans"][0]["ignored_guessed_paths"] == 1  # GET /actuator is not a route of this API


def test_deep_test_refuses_apis_outside_the_allowlist(astf_runs):
    with pytest.raises(PermissionError, match="prod-fn"):
        api_astf.deep_test(object(), SETTINGS, ["prod-fn"])
    with pytest.raises(LookupError):  # also proves the run lock was released after the refusal
        api_astf.deep_test(object(), SETTINGS, ["not-in-inventory"])
    assert astf_runs == []
