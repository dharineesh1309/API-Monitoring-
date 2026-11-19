"""The DNS watchdog restarts the app when a lookup hangs, and leaves it alone when lookups fail fast."""

import asyncio
import threading
from types import SimpleNamespace

import pytest

from app import main

SETTINGS = SimpleNamespace(aws_endpoint_url="", aws_region="ap-south-1", dns_watchdog_interval_seconds=0)


class Exited(Exception):
    pass


def test_watchdog_restarts_the_app_when_a_dns_lookup_hangs(monkeypatch):
    release = threading.Event()
    looked_up = []
    monkeypatch.setattr(main.socket, "getaddrinfo", lambda host, port: looked_up.append(host) or release.wait(1))
    monkeypatch.setattr(main, "DNS_HANG_SECONDS", 0.2)
    exits = []

    def fake_exit(code):
        exits.append(code)
        raise Exited

    monkeypatch.setattr(main.os, "_exit", fake_exit)
    with pytest.raises(Exited):
        asyncio.run(main._dns_watchdog(SimpleNamespace(settings=SETTINGS)))
    release.set()

    assert looked_up == ["sts.ap-south-1.amazonaws.com"] and exits == [3]


def test_watchdog_keeps_running_when_lookups_fail_fast(monkeypatch):
    calls = []

    def failing(host, port):
        calls.append(host)
        if len(calls) == 3:
            raise KeyboardInterrupt  # stop the endless loop after three checks
        raise OSError("Name or service not known")

    monkeypatch.setattr(main.socket, "getaddrinfo", failing)
    monkeypatch.setattr(main.os, "_exit", lambda code: pytest.fail("must not restart on a fast failure"))
    with pytest.raises(KeyboardInterrupt):
        asyncio.run(main._dns_watchdog(SimpleNamespace(settings=SETTINGS)))
    assert len(calls) == 3
