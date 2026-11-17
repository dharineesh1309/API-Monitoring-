"""Order routes (backed by DynamoDB via LocalStack)."""

from fastapi import APIRouter, Depends, HTTPException

from ..deps import get_container, require_auth
from ..models.order import Order
from ..schemas.orders import OrderCreate, OrderListOut, OrderOut
from ..services import Container
from ..telemetry.tracing import aws_attributes, business_span
from ..utils.ids import new_id, now_iso

router = APIRouter(prefix="/orders", tags=["orders"], dependencies=[Depends(require_auth)])


@router.post("", response_model=OrderOut, status_code=201, summary="Create an order (DynamoDB)")
def create_order(body: OrderCreate, container: Container = Depends(get_container)) -> OrderOut:
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
        container.dynamodb.put_item(container.dynamodb.orders_table, order.to_item())
    container.metrics.orders_created.add(1, {"status": "created"})
    return order


@router.get("", response_model=OrderListOut, summary="List orders (DynamoDB scan)")
def list_orders(container: Container = Depends(get_container)) -> OrderListOut:
    items = container.dynamodb.latest(container.dynamodb.orders_table, limit=50)
    orders = [Order.from_item(item) for item in items]
    return OrderListOut(orders=orders, count=len(orders))


@router.get("/{order_id}", response_model=OrderOut, summary="Get an order by id (DynamoDB)")
def get_order(order_id: str, container: Container = Depends(get_container)) -> OrderOut:
    item = container.dynamodb.get_item(container.dynamodb.orders_table, {"order_id": order_id})
    if not item:
        raise HTTPException(status_code=404, detail="Order not found")
    return Order.from_item(item)
