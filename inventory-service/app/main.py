import asyncio
import random
from typing import List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.telemetry import configure_telemetry

app = FastAPI(
    title="CentralWatch Inventory Service",
    description="Inventory microservice for distributed tracing demo",
    version="1.0.0",
)

# Set up OpenTelemetry (before routes handle requests)
configure_telemetry(app)

WAREHOUSES = ["us-east-1", "eu-west-1", "ap-southeast-1"]


class BulkRequest(BaseModel):
    products: List[str]


@app.get("/healthz")
async def health_check():
    return {"status": "ok", "service": "centralwatch-inventory"}


@app.get("/inventory/{product_name}")
async def get_inventory(product_name: str):
    # Simulate DB lookup latency
    await asyncio.sleep(random.uniform(0.01, 0.08))

    # 5% chance of transient failure — generates observable errors in traces
    if random.random() < 0.05:
        raise HTTPException(
            status_code=503,
            detail="Inventory service temporarily unavailable",
        )

    return {
        "product": product_name,
        "stock": random.randint(0, 100),
        "warehouse": random.choice(WAREHOUSES),
        "reserved": random.randint(0, 20),
    }


@app.post("/inventory/bulk")
async def get_bulk_inventory(request: BulkRequest):
    result = {}
    for product in request.products:
        # Simulate per-product DB lookup latency
        await asyncio.sleep(random.uniform(0.005, 0.03))
        result[product] = {
            "stock": random.randint(0, 100),
            "warehouse": random.choice(WAREHOUSES),
            "reserved": random.randint(0, 20),
        }
    return result
