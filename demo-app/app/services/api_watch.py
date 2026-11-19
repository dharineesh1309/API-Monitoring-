"""Keeps the latest API exposure result, publishes it as metrics, and logs what changed.

main.py rescans on a fixed schedule (API_RESCAN_INTERVAL_SECONDS) with the live probe on, so a new
or newly opened API, an outage or a data leak shows up within one interval. The scan itself is the
source of truth: no CloudTrail or CloudWatch. The ASTF deep test runs on its own, slower schedule.
"""

import logging
import threading
from collections import Counter
from typing import Any

from . import api_astf
from .api_inventory import LEAK_KINDS, LEAKS, NO_AUTH_CHECKS, crawl

logger = logging.getLogger(__name__)
DOWN = {"down", "errors"}


def _unauthenticated(result) -> set[tuple[str, str, str]]:
    return {(f["source"], f["region"], f["api"]) for f in result["findings"] if f["check"] in NO_AUTH_CHECKS}


def _leaked(result) -> set[tuple[str, str, str]]:
    return {(f["api"], f["kind"], f["target"]) for f in result["findings"] if f.get("kind")}


def _down(result) -> dict[str, dict]:
    return {api["name"]: api for api in result["apis"] if api.get("health", {}).get("status") in DOWN}


class ApiWatch:
    def __init__(self, session, settings, metrics) -> None:
        self.session, self.settings, self.metrics = session, settings, metrics
        self.latest: dict[str, Any] | None = None
        self.latest_deep_test: dict[str, Any] | None = None
        self._probed: dict[str, Any] | None = None  # the last scan that probed: leaks and health compare with it
        self._lock = threading.Lock()

    def record(self, result: dict[str, Any], trigger: dict[str, Any]) -> dict[str, Any]:
        """Keep the result as the latest, publish it as metrics, and log new exposures, leaks and outages."""
        result["trigger"] = trigger
        empty = {"findings": [], "apis": []}
        with self._lock:
            before = self.latest or empty
            # A manual crawl without the probe sees no response leaks or health; comparing the next probed
            # scan with it would report every existing leak as new again.
            probed_before = self._probed or empty
            self.latest = result
            if trigger.get("probe"):
                self._probed = result
        summary = result["summary"]
        for exposure in ("total", "public", "unauthenticated"):
            self.metrics.api_exposure_apis.set(summary[exposure], {"exposure": exposure})
        for severity, count in summary["findings"].items():
            self.metrics.api_exposure_findings.set(count, {"severity": severity})
        self.metrics.api_exposure_rescans.add(1, {"trigger": trigger["type"]})

        if trigger.get("probe"):  # health and response leaks exist only when the scan probed
            # ponytail: series of an API that disappears keep their last value until restart; drop them if that misleads.
            for api in result["apis"]:
                health = api.get("health")
                if not health or health["status"] == "not checked":
                    continue
                labels = {"api": api["name"], "source": api["source"], "region": api["region"]}
                self.metrics.api_exposure_up.set(int(health["status"] == "up"), labels)
                if health["avg_ms"] is not None:
                    self.metrics.api_exposure_response_time.set(health["avg_ms"], labels)
            leaks = Counter(f["kind"] for f in result["findings"] if f.get("kind"))
            for kind, severity in LEAK_KINDS.items():
                self.metrics.api_exposure_leaks.set(leaks[kind], {"kind": kind, "severity": severity})

        for source, region, name in sorted(_unauthenticated(result) - _unauthenticated(before)):
            logger.warning("API exposure: newly exposed API without authentication: %s %s in %s", source, name, region)
        for name, kind, target in sorted(_leaked(result) - _leaked(probed_before)):
            what = LEAKS[kind][3] if kind in LEAKS else kind.replace("_", " ")
            logger.warning("API exposure: data leak on %s: %s at %s", name, what, target)
        if trigger.get("probe"):
            down_before, down_now = _down(probed_before), _down(result)
            for name, api in sorted(down_now.items()):
                if name not in down_before:
                    health = api["health"]
                    logger.warning(
                        "API exposure: %s (%s, %s) is %s: %d of %d probed routes answered, %d with server errors",
                        name, api["source"], api["region"], health["status"], health["answered"], health["checked"], health["server_errors"],
                    )
            for name in sorted(set(down_before) - set(down_now)):
                logger.info("API exposure: %s is answering again", name)
        return result

    def rescan(self, trigger_type: str) -> dict[str, Any]:
        """A full crawl with the live probe: settings, health and leaks of every public API."""
        return self.record(crawl(self.session, self.settings, probe=True), {"type": trigger_type, "probe": True})

    def deep_test(self, api_ids: list[str] | None = None) -> dict[str, Any]:
        """OWASP ASTF against allow-listed APIs (raises like api_astf.deep_test); publishes the result."""
        result = api_astf.deep_test(self.session, self.settings, api_ids)
        self.latest_deep_test = result
        for severity, count in result["summary"]["findings"].items():
            self.metrics.api_exposure_deep_test_findings.set(count, {"severity": severity})
        logger.info(
            "API exposure: deep test of %s found %s",
            ", ".join(result["tested"]) or "no allow-listed APIs",
            ", ".join(f"{count} {severity}" for severity, count in result["summary"]["findings"].items()),
        )
        return result
