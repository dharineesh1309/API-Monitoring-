"""Auth service: register / login / profile backed by DynamoDB.

Passwords are hashed with PBKDF2-HMAC-SHA256 (stdlib). Tokens are stateless
HMAC-signed ids with an expiry — no session table required.
"""

import base64
import hashlib
import hmac
import time
from uuid import uuid4

from fastapi import HTTPException

from ..config.settings import Settings
from ..models.user import User
from ..telemetry.tracing import aws_attributes, business_span
from ..utils.ids import now_iso


class AuthService:
    def __init__(self, settings: Settings, dynamodb_service) -> None:
        self.settings = settings
        self.dynamodb = dynamodb_service

    # ------------------------------------------------------------------ public
    def register(self, email: str, password: str, name: str, allowed_cidrs: list[str] = None) -> User:
        email = email.strip().lower()
        with business_span(
            "User Registration",
            attributes=aws_attributes(
                "dynamodb", "PutItem", {"table.name": self.dynamodb.users_table, "endpoint": "/auth/register"}
            ),
        ):
            if self.dynamodb.query_by_email(email):
                raise HTTPException(status_code=409, detail="A user with this email already exists")
            user = User(
                user_id=f"usr_{uuid4().hex[:12]}", 
                email=email, 
                name=name, 
                created_at=now_iso(),
                status="ACTIVE",
                allowed_cidrs=allowed_cidrs or ["0.0.0.0/0"]
            )
            item = user.to_item()
            item["password_hash"] = self._hash_password(password)
            self.dynamodb.put_item(self.dynamodb.users_table, item)
        return user

    def login(self, email: str, password: str) -> dict:
        email = email.strip().lower()
        with business_span(
            "User Login",
            attributes=aws_attributes(
                "dynamodb", "Query", {"table.name": self.dynamodb.users_table, "endpoint": "/auth/login"}
            ),
        ):
            item = self.dynamodb.query_by_email(email)
            if not item or not self._verify_password(password, item.get("password_hash", "")):
                raise HTTPException(status_code=401, detail="Invalid email or password")
        token = self._issue_token(item["user_id"])
        return {
            "token": token,
            "token_type": "bearer",
            "expires_in": self.settings.token_ttl_seconds,
            "user": User.from_item(item),
        }

    def get_profile(self, token: str) -> User:
        user_id = self._verify_token(token)
        item = self.dynamodb.get_item(self.dynamodb.users_table, {"user_id": user_id})
        if not item:
            raise HTTPException(status_code=401, detail="Invalid token")
        return User.from_item(item)

    def seed_admin_if_needed(self) -> None:
        """Ensure the default operator account exists with administrator privileges."""
        admin_email = "operator@example.com"
        try:
            if not self.dynamodb.query_by_email(admin_email):
                user = User(
                    user_id="usr_admin_operator",
                    email=admin_email,
                    name="CentralWatch Admin",
                    created_at=now_iso(),
                    status="ACTIVE",
                    allowed_cidrs=["0.0.0.0/0", "::/0"],
                    role="admin",
                    is_admin=True,
                )
                item = user.to_item()
                item["password_hash"] = self._hash_password("Password123!")
                self.dynamodb.put_item(self.dynamodb.users_table, item)
        except Exception:
            pass

    # ------------------------------------------------------------------ helpers
    def _hash_password(self, password: str) -> str:
        salt = uuid4().hex
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
        return f"{salt}${digest}"

    def _verify_password(self, password: str, stored: str) -> bool:
        try:
            salt, digest = stored.split("$", 1)
        except ValueError:
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000).hex()
        return hmac.compare_digest(candidate, digest)

    def _issue_token(self, user_id: str) -> str:
        expires = int(time.time()) + self.settings.token_ttl_seconds
        payload = f"{user_id}.{expires}"
        signature = hmac.new(
            self.settings.auth_token_secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        return base64.urlsafe_b64encode(f"{payload}.{signature}".encode()).decode()

    def _verify_token(self, token: str) -> str:
        try:
            raw = base64.urlsafe_b64decode(token.encode()).decode()
            user_id, expires, signature = raw.split(".")
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token") from None
        expected = hmac.new(
            self.settings.auth_token_secret.encode(), f"{user_id}.{expires}".encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected) or int(expires) < time.time():
            raise HTTPException(status_code=401, detail="Invalid or expired token") from None
        return user_id
