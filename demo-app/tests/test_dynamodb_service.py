"""DynamoDB listing must read every Scan page and return the newest items."""

from types import SimpleNamespace

import boto3
from botocore.stub import Stubber

from app.services import dynamodb_service as dynamodb_module
from app.services.dynamodb_service import DynamoDBService


def _order(order_id, created_at):
    return {"order_id": {"S": order_id}, "created_at": {"S": created_at}}


def test_latest_reads_every_page_and_returns_newest_first(monkeypatch):
    client = boto3.client("dynamodb", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    monkeypatch.setattr(dynamodb_module, "make_client", lambda *_: client)
    settings = SimpleNamespace(dynamodb_users_table="users", dynamodb_orders_table="orders", dynamodb_files_table="files")
    service = DynamoDBService(session=None, settings=settings)

    with Stubber(client) as stub:
        # DynamoDB returns pages in key order, not time order; the newest order is on page 2.
        stub.add_response(
            "scan",
            {"Items": [_order("ord_a", "2026-11-17T09:00:00.000+00:00"), _order("ord_b", "2026-11-17T08:00:00.000+00:00")],
             "LastEvaluatedKey": {"order_id": {"S": "ord_b"}}},
            {"TableName": "orders"},
        )
        stub.add_response(
            "scan",
            {"Items": [_order("ord_c", "2026-11-17T10:00:00.000+00:00")]},
            {"TableName": "orders", "ExclusiveStartKey": {"order_id": {"S": "ord_b"}}},
        )
        latest = service.latest("orders", limit=2)
        stub.assert_no_pending_responses()

    assert [item["order_id"] for item in latest] == ["ord_c", "ord_a"]
