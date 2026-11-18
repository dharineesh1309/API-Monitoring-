"""
CentralWatch Traffic Generator
Sends realistic HTTP traffic to the demo app to keep Grafana dashboards live.
"""
import asyncio
import logging
import os
import random
import signal
import time

import httpx

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEMO_APP_URL = os.getenv("DEMO_APP_URL", "http://demo-app:8000").rstrip("/")
TRAFFIC_TOKEN = os.getenv("TRAFFIC_TOKEN", "")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("traffic-gen")

# ---------------------------------------------------------------------------
# Auth credentials
# ---------------------------------------------------------------------------
AUTH_USERNAME = "trafficgen"
AUTH_PASSWORD = "TrafficGen123!"
AUTH_EMAIL = "trafficgen@centralwatch.local"

# ---------------------------------------------------------------------------
# Shared mutable state (token + shutdown flag)
# ---------------------------------------------------------------------------
state: dict = {"token": TRAFFIC_TOKEN, "shutdown": False}


def _jitter(base: float) -> float:
    """Return base seconds ± 20% random jitter."""
    return base * random.uniform(0.8, 1.2)


def _headers() -> dict:
    if state["token"]:
        return {"Authorization": f"Bearer {state['token']}"}
    return {}


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
async def register(client: httpx.AsyncClient) -> None:
    try:
        resp = await client.post(
            f"{DEMO_APP_URL}/auth/register",
            json={
                "name": "Traffic Generator",
                "email": AUTH_EMAIL,
                "password": AUTH_PASSWORD,
                "allowed_cidrs": ["0.0.0.0/0"],
            },
        )
        if resp.status_code == 409:
            log.debug("User already registered — continuing.")
        else:
            resp.raise_for_status()
            log.info("Registered trafficgen user.")
    except httpx.HTTPStatusError as exc:
        log.warning("Register error: %s", exc)
    except Exception as exc:
        log.warning("Register failed: %s", exc)


async def login(client: httpx.AsyncClient) -> bool:
    try:
        resp = await client.post(
            f"{DEMO_APP_URL}/auth/login",
            json={"email": AUTH_EMAIL, "password": AUTH_PASSWORD},
        )
        resp.raise_for_status()
        data = resp.json()
        token = data.get("access_token") or data.get("token", "")
        if token:
            state["token"] = token
            log.info("Authenticated — token acquired.")
            return True
        log.warning("Login response had no token: %s", data)
    except Exception as exc:
        log.warning("Login failed: %s", exc)
    return False


async def authenticate(client: httpx.AsyncClient) -> None:
    await register(client)
    for attempt in range(5):
        if await login(client):
            return
        wait = 5 * (attempt + 1)
        log.info("Retrying login in %ds (attempt %d/5)…", wait, attempt + 1)
        await asyncio.sleep(wait)
    log.error("Could not authenticate after 5 attempts; continuing unauthenticated.")


# ---------------------------------------------------------------------------
# Request helper
# ---------------------------------------------------------------------------
async def request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    *,
    json: dict | None = None,
    _retry: bool = True,
) -> None:
    url = f"{DEMO_APP_URL}{path}"
    t0 = time.monotonic()
    try:
        resp = await client.request(method, url, headers=_headers(), json=json)
        latency_ms = (time.monotonic() - t0) * 1000
        log.info(
            "%s %s → %d  (%.1f ms)",
            method,
            path,
            resp.status_code,
            latency_ms,
        )
        if resp.status_code == 401 and _retry:
            log.info("Got 401 — re-authenticating…")
            await authenticate(client)
            await request(client, method, path, json=json, _retry=False)
    except httpx.TimeoutException:
        latency_ms = (time.monotonic() - t0) * 1000
        log.warning("%s %s → TIMEOUT  (%.1f ms)", method, path, latency_ms)
    except Exception as exc:
        latency_ms = (time.monotonic() - t0) * 1000
        log.warning("%s %s → ERROR %s  (%.1f ms)", method, path, exc, latency_ms)


# ---------------------------------------------------------------------------
# Individual traffic tasks
# ---------------------------------------------------------------------------
async def task_healthz(client: httpx.AsyncClient) -> None:
    while not state["shutdown"]:
        await request(client, "GET", "/healthz")
        await asyncio.sleep(_jitter(10))


async def task_list_orders(client: httpx.AsyncClient) -> None:
    while not state["shutdown"]:
        await request(client, "GET", "/orders")
        await asyncio.sleep(_jitter(15))


async def task_create_order(client: httpx.AsyncClient) -> None:
    products = ["Widget", "Gadget", "Doohickey"]
    while not state["shutdown"]:
        chosen_prod = random.choice(products)
        await request(
            client,
            "POST",
            "/orders",
            json={
                "user_id": "usr_trafficgen",
                "items": [
                    {
                        "product_id": f"prod_{chosen_prod.lower()}",
                        "name": chosen_prod,
                        "quantity": random.randint(1, 10),
                        "unit_price": round(random.uniform(9.99, 49.99), 2),
                    }
                ],
            },
        )
        await asyncio.sleep(_jitter(20))


async def task_simulate_error(client: httpx.AsyncClient) -> None:
    while not state["shutdown"]:
        await request(client, "GET", "/simulate/error")
        await asyncio.sleep(_jitter(60))


async def task_simulate_timeout(client: httpx.AsyncClient) -> None:
    while not state["shutdown"]:
        await request(client, "GET", "/simulate/timeout")
        await asyncio.sleep(_jitter(90))


async def task_simulate_retry(client: httpx.AsyncClient) -> None:
    while not state["shutdown"]:
        await request(client, "GET", "/simulate/retry")
        await asyncio.sleep(_jitter(120))


async def task_list_files(client: httpx.AsyncClient) -> None:
    while not state["shutdown"]:
        await request(client, "GET", "/files")
        await asyncio.sleep(_jitter(30))


async def task_queue_messages(client: httpx.AsyncClient) -> None:
    while not state["shutdown"]:
        await request(client, "GET", "/queue/messages")
        await asyncio.sleep(_jitter(45))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main() -> None:
    # Graceful shutdown on SIGTERM / SIGINT
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: state.update({"shutdown": True}))

    limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
    timeout = httpx.Timeout(30.0, connect=5.0)

    async with httpx.AsyncClient(limits=limits, timeout=timeout) as client:
        log.info("Traffic generator starting — target: %s", DEMO_APP_URL)
        await authenticate(client)

        tasks = [
            asyncio.create_task(task_healthz(client)),
            asyncio.create_task(task_list_orders(client)),
            asyncio.create_task(task_create_order(client)),
            asyncio.create_task(task_simulate_error(client)),
            asyncio.create_task(task_simulate_timeout(client)),
            asyncio.create_task(task_simulate_retry(client)),
            asyncio.create_task(task_list_files(client)),
            asyncio.create_task(task_queue_messages(client)),
        ]

        # Wait until shutdown signal
        while not state["shutdown"]:
            await asyncio.sleep(1)

        log.info("Shutdown signal received — stopping tasks…")
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        log.info("Traffic generator stopped.")


if __name__ == "__main__":
    asyncio.run(main())
