"""The API watcher publishes each scan, logs only what changed, and runs scheduled scans with the probe on."""

import logging
from types import SimpleNamespace

from app.services import api_watch
from app.services.api_watch import ApiWatch


class Instrument:
    def __init__(self):
        self.calls = []

    def set(self, value, attributes):
        self.calls.append((value, attributes))

    add = set


def metrics():
    names = ("apis", "findings", "rescans", "up", "response_time", "leaks", "deep_test_findings")
    return SimpleNamespace(**{f"api_exposure_{name}": Instrument() for name in names})


def scan(open_apis, health, leaks=()):
    findings = [{"source": "Lambda function URL", "region": "ap-south-1", "api": name, "check": "url_no_auth", "target": "function URL"}
                for name in open_apis]
    findings += [{"source": "API Gateway HTTP", "region": "ap-south-1", "api": "orders", "check": "response_leak", "kind": kind,
                  "target": "GET /users"} for kind in leaks]
    api = {"name": "orders", "source": "API Gateway HTTP", "region": "ap-south-1",
           "health": {"status": health, "checked": 2, "answered": 2 if health == "up" else 0, "server_errors": 0,
                      "avg_ms": 90 if health == "up" else None}}
    summary = {"total": 3, "public": 2, "unauthenticated": len(open_apis),
               "findings": {"critical": len(open_apis), "high": len(leaks), "medium": 1, "low": 0}}
    return {"summary": summary, "findings": findings, "apis": [api]}


def test_record_publishes_metrics_and_logs_new_exposures_leaks_and_outages(caplog):
    m = metrics()
    watch = ApiWatch(object(), SimpleNamespace(), m)
    probed = {"type": "scheduled", "probe": True}

    watch.record(scan(["old-fn"], "up"), {"type": "startup", "probe": True})
    caplog.clear()
    with caplog.at_level(logging.INFO):
        latest = watch.record(scan(["old-fn", "new-fn"], "down", leaks=["email"]), probed)
        watch.record(scan(["old-fn", "new-fn"], "up", leaks=["email"]), probed)

    assert watch.latest["trigger"] == probed and latest["summary"]["unauthenticated"] == 2
    assert [r.getMessage() for r in caplog.records] == [
        "API exposure: newly exposed API without authentication: Lambda function URL new-fn in ap-south-1",
        "API exposure: data leak on orders: an email address at GET /users",
        "API exposure: orders (API Gateway HTTP, ap-south-1) is down: 0 of 2 probed routes answered, 0 with server errors",
        "API exposure: orders is answering again",  # the third scan; the leak is not logged twice
    ]
    labels = {"api": "orders", "source": "API Gateway HTTP", "region": "ap-south-1"}
    assert m.api_exposure_up.calls == [(1, labels), (0, labels), (1, labels)]
    assert m.api_exposure_response_time.calls == [(90, labels), (90, labels)]  # no time when nothing answered
    assert (1, {"kind": "email", "severity": "high"}) in m.api_exposure_leaks.calls
    assert (0, {"kind": "aws_access_key", "severity": "critical"}) in m.api_exposure_leaks.calls  # cleared kinds read 0
    assert [call[1]["trigger"] for call in m.api_exposure_rescans.calls] == ["startup", "scheduled", "scheduled"]


def test_a_manual_scan_without_probe_does_not_make_known_leaks_look_new(caplog):
    watch = ApiWatch(object(), SimpleNamespace(), metrics())
    watch.record(scan([], "up", leaks=["email"]), {"type": "startup", "probe": True})
    watch.record(scan([], "not checked"), {"type": "manual", "probe": False})  # sees no response leaks
    caplog.clear()
    with caplog.at_level(logging.INFO):
        watch.record(scan([], "up", leaks=["email"]), {"type": "scheduled", "probe": True})
    assert caplog.records == []


def test_manual_scan_without_probe_leaves_health_and_leak_metrics_alone():
    m = metrics()
    ApiWatch(object(), SimpleNamespace(), m).record(scan([], "not checked"), {"type": "manual", "probe": False})
    assert m.api_exposure_up.calls == [] and m.api_exposure_leaks.calls == []


def test_rescan_probes_and_deep_test_publishes(monkeypatch):
    m = metrics()
    crawled = []
    monkeypatch.setattr(api_watch, "crawl", lambda session, settings, probe: crawled.append(probe) or scan([], "up"))
    result = {"tested": ["cw-lab-orders"], "summary": {"findings": {"critical": 0, "high": 9, "medium": 11, "low": 0}}}
    monkeypatch.setattr(api_watch.api_astf, "deep_test", lambda session, settings, api_ids: result)
    watch = ApiWatch(object(), SimpleNamespace(), m)

    assert watch.rescan("scheduled")["trigger"] == {"type": "scheduled", "probe": True} and crawled == [True]
    assert watch.deep_test() is result and watch.latest_deep_test is result
    assert (9, {"severity": "high"}) in m.api_exposure_deep_test_findings.calls
