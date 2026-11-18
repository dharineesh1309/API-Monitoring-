"""CentralWatch Python SDK Example.

Demonstrates how to integrate client applications with CentralWatch API Gateway,
using managed proxy tokens for transparent credential injection, rate limiting,
and distributed tracing propagation.
"""

import os
import requests

CENTRALWATCH_BASE = os.getenv("CENTRALWATCH_URL", "http://localhost:8080")
PROXIED_ROUTE = f"{CENTRALWATCH_BASE}/api/centralwatch/proxy/v1/models/gemini-1.5-flash:generateContent"
PROXY_TOKEN = os.getenv("CW_PROXY_TOKEN", "cw_proxy_live_demo_token")


def call_llm_through_proxy(prompt: str) -> dict:
    """Send an LLM prompt through CentralWatch without exposing the Gemini API key.

    CentralWatch validates the proxy token, applies rate limits and budgets,
    injects the real secret upstream key, and emits metrics and logs.
    """
    headers = {
        "Authorization": f"Bearer {PROXY_TOKEN}",
        "Content-Type": "application/json",
        "X-CentralWatch-Trace": "true",
    }
    payload = {
        "contents": [
            {
                "parts": [{"text": prompt}]
            }
        ]
    }

    response = requests.post(PROXIED_ROUTE, json=payload, headers=headers, timeout=10)
    print(f"Status Code: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    if response.ok:
        return response.json()
    else:
        print(f"Error ({response.status_code}): {response.text}")
        response.raise_for_status()


if __name__ == "__main__":
    print("Testing CentralWatch API Proxy call...")
    try:
        res = call_llm_through_proxy("Explain OpenTelemetry distributed tracing in 2 sentences.")
        print("Success:", res)
    except Exception as e:
        print("Call failed (expected if local demo stack proxy token is unconfigured):", e)

