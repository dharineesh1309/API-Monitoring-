"""Order domain model (stored in DynamoDB)."""

from dataclasses import dataclass, field
from decimal import Decimal

from ..utils.ids import now_iso


def _clean_decimals(val):
    """Recursively convert boto3 Decimal instances to float or int for clean JSON serialization."""
    if isinstance(val, Decimal):
        return float(val) if val % 1 else int(val)
    if isinstance(val, dict):
        return {k: _clean_decimals(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_clean_decimals(v) for v in val]
    return val


@dataclass
class Order:
    order_id: str
    user_id: str
    items: list[dict]
    total: float
    status: str = "created"
    created_at: str = field(default_factory=now_iso)

    def to_item(self) -> dict:
        return {
            "order_id": self.order_id,
            "user_id": self.user_id,
            "items": _clean_decimals(self.items),
            "total": self.total,
            "status": self.status,
            "created_at": self.created_at,
        }

    @classmethod
    def from_item(cls, item: dict) -> "Order":
        raw_items = item.get("items", [])
        clean_items = _clean_decimals(raw_items)
        if not isinstance(clean_items, list):
            clean_items = []
        return cls(
            order_id=item.get("order_id", "ord_unknown"),
            user_id=item.get("user_id", ""),
            items=clean_items,
            total=float(item.get("total", 0.0)),
            status=item.get("status", "created"),
            created_at=item.get("created_at", ""),
        )
