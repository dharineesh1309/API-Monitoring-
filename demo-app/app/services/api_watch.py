"""Keeps the latest API exposure result, publishes it as metrics, and rescans when CloudTrail
records a change that can create or open up an API.

CloudTrail Event History is free and always on, but per region and delayed (usually about
5 minutes), so a new or newly opened API shows up within roughly 5-10 minutes.
Automatic rescans read configuration only; they never send traffic to the APIs.
"""

import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from ..utils.aws import make_client
from .api_inventory import NO_AUTH_CHECKS, _regions, crawl

logger = logging.getLogger(__name__)

LOOKBACK = timedelta(minutes=20)  # covers CloudTrail's delivery delay; event IDs dedupe the overlap
TRIGGER_EVENTS = {
    # API Gateway (REST, HTTP and WebSocket)
    "CreateRestApi", "ImportRestApi", "PutRestApi", "UpdateRestApi", "CreateDeployment", "CreateStage", "UpdateStage",
    "PutMethod", "UpdateMethod", "CreateApi", "ImportApi", "ReimportApi", "UpdateApi", "CreateRoute", "UpdateRoute",
    "DeleteAuthorizer",
    # Lambda function URLs and resource policies
    "CreateFunctionUrlConfig", "UpdateFunctionUrlConfig", "AddPermission",
    # AppSync, CloudFront (recorded in us-east-1), load balancers
    "CreateGraphqlApi", "UpdateGraphqlApi", "CreateDistribution", "CreateDistributionWithTags", "UpdateDistribution",
    "CreateLoadBalancer", "CreateListener", "ModifyListener", "CreateRule", "ModifyRule",
    # EC2 reachability, and WAF protection being removed
    "RunInstances", "AuthorizeSecurityGroupIngress", "AssociateAddress", "DisassociateWebACL",
}


def _unauthenticated(result) -> set[tuple[str, str, str]]:
    return {(f["source"], f["region"], f["api"]) for f in result["findings"] if f["check"] in NO_AUTH_CHECKS}


class ApiWatch:
    def __init__(self, session, settings, metrics) -> None:
        self.session, self.settings, self.metrics = session, settings, metrics
        self.latest: dict[str, Any] | None = None
        self._seen: dict[str, float] = {}  # CloudTrail event ID -> when first seen
        self._clients: list | None = None
        self._lock = threading.Lock()

    def record(self, result: dict[str, Any], trigger: dict[str, Any]) -> dict[str, Any]:
        """Keep the result as the latest, publish it as metrics, and log newly unauthenticated APIs."""
        result["trigger"] = trigger
        with self._lock:
            before = _unauthenticated(self.latest) if self.latest else None
            self.latest = result
        summary = result["summary"]
        for exposure in ("total", "public", "unauthenticated"):
            self.metrics.api_exposure_apis.set(summary[exposure], {"exposure": exposure})
        for severity, count in summary["findings"].items():
            self.metrics.api_exposure_findings.set(count, {"severity": severity})
        self.metrics.api_exposure_rescans.add(1, {"trigger": trigger["type"]})
        if before is not None:
            for source, region, name in sorted(_unauthenticated(result) - before):
                logger.warning("API exposure: newly exposed API without authentication: %s %s in %s", source, name, region)
        return result

    def rescan(self, trigger_type: str, events: list[dict[str, str]] = ()) -> dict[str, Any]:
        if events:
            logger.warning(
                "API exposure rescan triggered by CloudTrail: %s",
                "; ".join(f"{e['event']} by {e['user']} in {e['region']}" for e in events),
            )
        return self.record(crawl(self.session, self.settings), {"type": trigger_type, "events": list(events)})

    def poll_cloudtrail(self) -> list[dict[str, str]]:
        """Exposure-changing write events from every region that were not seen in an earlier poll."""
        if self._clients is None:
            # ponytail: built lazily in the watcher thread; a crawl creating clients at the same instant
            # could race on the shared boto3 session. Build these at startup if that ever bites.
            regions = _regions(self.session, self.settings, [])
            self._clients = [(r, make_client(self.session, "cloudtrail", self.settings, region=r)) for r in regions]
        end = datetime.now(timezone.utc)
        found = []
        for region, client in self._clients:
            try:
                pages = client.get_paginator("lookup_events").paginate(
                    LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
                    StartTime=end - LOOKBACK,
                    EndTime=end,
                )
                for page in pages:
                    for event in page["Events"]:
                        name = re.sub(r"\d{8}(v\d+)?$", "", event["EventName"])  # Lambda: AddPermission20150331v2
                        if name in TRIGGER_EVENTS and event["EventId"] not in self._seen:
                            self._seen[event["EventId"]] = time.time()
                            found.append({
                                "event": name,
                                "user": event.get("Username", "unknown"),
                                "region": region,
                                "time": event["EventTime"].isoformat(),
                                "event_id": event["EventId"],
                            })
            except Exception as exc:  # noqa: BLE001 - one unreachable region must not stop the others
                logger.warning("CloudTrail lookup failed in %s: %s", region, exc)
        cutoff = time.time() - 2 * LOOKBACK.total_seconds()
        self._seen = {event_id: seen for event_id, seen in self._seen.items() if seen > cutoff}
        return found
