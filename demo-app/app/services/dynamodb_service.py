"""DynamoDB service (users, orders, files tables) with automatic type (de)serialization."""

from decimal import Decimal

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

from ..config.settings import Settings
from ..utils.aws import make_client

_serializer = TypeSerializer()
_deserializer = TypeDeserializer()


def _decimalize(value):
    """boto3's TypeSerializer rejects Python floats — convert them to Decimal."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, list):
        return [_decimalize(item) for item in value]
    if isinstance(value, dict):
        return {key: _decimalize(item) for key, item in value.items()}
    return value


def _to_typed(item: dict) -> dict:
    return {key: _serializer.serialize(_decimalize(value)) for key, value in item.items()}


def _from_typed(item: dict) -> dict:
    return {key: _deserializer.deserialize(value) for key, value in item.items()}


class DynamoDBService:
    def __init__(self, session, settings: Settings) -> None:
        self.settings = settings
        self.client = make_client(session, "dynamodb", settings)
        self.users_table = settings.dynamodb_users_table
        self.orders_table = settings.dynamodb_orders_table
        self.files_table = settings.dynamodb_files_table

    def put_item(self, table: str, item: dict) -> None:
        self.client.put_item(TableName=table, Item=_to_typed(item))

    def get_item(self, table: str, key: dict) -> dict | None:
        resp = self.client.get_item(TableName=table, Key=_to_typed(key))
        item = resp.get("Item")
        return _from_typed(item) if item else None

    def delete_item(self, table: str, key: dict) -> None:
        self.client.delete_item(TableName=table, Key=_to_typed(key))

    def scan(self, table: str, limit: int = 100) -> list[dict]:
        items = []
        paginator = self.client.get_paginator("scan")
        for page in paginator.paginate(TableName=table):
            for item in page.get("Items", []):
                items.append(_from_typed(item))
                if len(items) >= limit:
                    return items
        return items

    def query_by_email(self, email: str) -> dict | None:
        """Look up a user by email using the email-index GSI."""
        resp = self.client.query(
            TableName=self.users_table,
            IndexName="email-index",
            KeyConditionExpression="#email = :email",
            ExpressionAttributeNames={"#email": "email"},
            ExpressionAttributeValues={":email": {"S": email}},
        )
        items = resp.get("Items", [])
        return _from_typed(items[0]) if items else None
