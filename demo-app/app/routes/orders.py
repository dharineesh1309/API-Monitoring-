"""Order routes (backed by DynamoDB via LocalStack)."""

import asyncio
import os
import urllib.parse
import urllib.request
from fastapi import APIRouter, Depends, HTTPException
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from ..deps import get_container, require_auth
from ..models.order import Order
from ..schemas.orders import OrderCreate, OrderListOut, OrderOut
from ..services import Container
from ..telemetry.tracing import aws_attributes, business_span
from ..utils.ids import new_id, now_iso

router = APIRouter(prefix="/orders", tags=["orders"], dependencies=[Depends(require_auth)])


@router.post("", response_model=OrderOut, status_code=201, summary="Create an order (DynamoDB)")
async def create_order(body: OrderCreate, container: Container = Depends(get_container)) -> OrderOut:
    # Cross-service call to inventory-service (generates distributed traces in Tempo)
    inventory_url = os.getenv("INVENTORY_SERVICE_URL", "http://inventory-service:8001")
    if inventory_url and body.items:
        first_product = body.items[0].name
        carrier = {}
        TraceContextTextMapPropagator().inject(carrier)
        try:
            safe_prod = urllib.parse.quote(first_product, safe="")
            req = urllib.request.Request(
                f"{inventory_url.rstrip('/')}/inventory/{safe_prod}",
                headers=carrier,
            )
            await asyncio.to_thread(urllib.request.urlopen, req, timeout=1.5)
        except Exception:
            # Tolerant of inventory outages so order creation still proceeds
            pass

    total = round(sum(item.quantity * item.unit_price for item in body.items), 2)
    order = Order(
        order_id=new_id("ord"),
        user_id=body.user_id,
        items=[item.model_dump() for item in body.items],
        total=total,
        status="created",
        created_at=now_iso(),
    )
    with business_span(
        "Order Creation",
        attributes=aws_attributes(
            "dynamodb",
            "PutItem",
            {"table.name": container.dynamodb.orders_table, "endpoint": "/orders"},
        ),
    ):
        await asyncio.to_thread(container.dynamodb.put_item, container.dynamodb.orders_table, order.to_item())
    container.metrics.orders_created.add(1, {"status": "created"})
    return order


@router.get("", response_model=OrderListOut, summary="List orders (DynamoDB scan)")
async def list_orders(container: Container = Depends(get_container)) -> OrderListOut:
    items = await asyncio.to_thread(container.dynamodb.scan, container.dynamodb.orders_table, limit=2000)
    orders = [Order.from_item(item) for item in items]
    orders.sort(key=lambda o: o.created_at or "", reverse=True)
    return OrderListOut(orders=orders[:100], count=len(orders[:100]))


@router.get("/{order_id}", response_model=OrderOut, summary="Get an order by id (DynamoDB)")
async def get_order(order_id: str, container: Container = Depends(get_container)) -> OrderOut:
    item = await asyncio.to_thread(container.dynamodb.get_item, container.dynamodb.orders_table, {"order_id": order_id})
    if not item:
        raise HTTPException(status_code=404, detail="Order not found")
    return Order.from_item(item)
