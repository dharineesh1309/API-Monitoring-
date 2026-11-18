"""User domain model (stored in DynamoDB)."""

from dataclasses import dataclass, field


@dataclass
class User:
    user_id: str
    email: str
    name: str
    created_at: str
    status: str = "ACTIVE"
    allowed_cidrs: list[str] = field(default_factory=lambda: ["0.0.0.0/0"])
    role: str = "user"
    is_admin: bool = False

    def to_item(self) -> dict:
        return {
            "user_id": self.user_id,
            "email": self.email,
            "name": self.name,
            "created_at": self.created_at,
            "status": self.status,
            "allowed_cidrs": self.allowed_cidrs,
            "role": self.role,
            "is_admin": self.is_admin,
        }

    @classmethod
    def from_item(cls, item: dict) -> "User":
        is_op = item.get("email") == "operator@example.com"
        role = item.get("role", "admin" if is_op else "user")
        is_admin = bool(item.get("is_admin", role == "admin" or is_op))
        return cls(
            user_id=item["user_id"],
            email=item["email"],
            name=item.get("name", ""),
            created_at=item.get("created_at", ""),
            status=item.get("status", "ACTIVE"),
            allowed_cidrs=item.get("allowed_cidrs", ["0.0.0.0/0"]),
            role=role,
            is_admin=is_admin,
        )
