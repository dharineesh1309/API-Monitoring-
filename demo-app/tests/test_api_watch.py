"""The API watcher picks out exposure-changing CloudTrail events once, and publishes each scan."""

import logging
from datetime import datetime, timezone
from types import SimpleNamespace

from app.services import api_watch
from app.services.api_watch import ApiWatch


class Instrument:
    def __init__(self):
        self.calls = []

    def set(self, value, attributes):
        self.calls.append((value, attributes))

    add = set


def event(event_id, name):
    return {"EventId": event_id, "EventName": name, "Username": "dev-user", "EventTime": datetime(2026, 11, 18, tzinfo=timezone.utc)}


def test_poll_returns_each_exposure_event_once(monkeypatch):
    page = {"Events": [event("e1", "AddPermission20150331v2"), event("e2", "PutObject"), event("e3", "CreateRestApi")]}
    cloudtrail = SimpleNamespace(get_paginator=lambda _: SimpleNamespace(paginate=lambda **_: [page]))
    monkeypatch.setattr(api_watch, "_regions", lambda *_: ["ap-south-1"])
    monkeypatch.setattr(api_watch, "make_client", lambda *_, **__: cloudtrail)
    watch = ApiWatch(object(), SimpleNamespace(), None)

    first = watch.poll_cloudtrail()
    assert [(e["event"], e["user"], e["region"]) for e in first] == [
        ("AddPermission", "dev-user", "ap-south-1"),  # Lambda's versioned event name, normalised
        ("CreateRestApi", "dev-user", "ap-south-1"),
    ]
    assert watch.poll_cloudtrail() == []  # the overlapping lookback window does not re-trigger


def test_record_publishes_metrics_and_logs_newly_unauthenticated_apis(caplog):
    metrics = SimpleNamespace(api_exposure_apis=Instrument(), api_exposure_findings=Instrument(), api_exposure_rescans=Instrument())
    watch = ApiWatch(object(), SimpleNamespace(), metrics)

    def scan(open_apis):
        findings = [{"source": "Lambda function URL", "region": "ap-south-1", "api": name, "check": "url_no_auth"} for name in open_apis]
        summary = {"total": 3, "public": 2, "unauthenticated": len(open_apis),
                   "findings": {"critical": len(open_apis), "high": 0, "medium": 1, "low": 0}}
        return {"summary": summary, "findings": findings}

    watch.record(scan(["old-fn"]), {"type": "startup"})
    with caplog.at_level(logging.WARNING):
        latest = watch.record(scan(["old-fn", "new-fn"]), {"type": "cloudtrail", "events": []})

    assert watch.latest is latest and latest["trigger"]["type"] == "cloudtrail"
    assert [r.getMessage() for r in caplog.records] == [
        "API exposure: newly exposed API without authentication: Lambda function URL new-fn in ap-south-1"
    ]
    assert metrics.api_exposure_apis.calls[-3:] == [(3, {"exposure": "total"}), (2, {"exposure": "public"}), (2, {"exposure": "unauthenticated"})]
    assert (2, {"severity": "critical"}) in metrics.api_exposure_findings.calls
    assert metrics.api_exposure_rescans.calls == [(1, {"trigger": "startup"}), (1, {"trigger": "cloudtrail"})]
