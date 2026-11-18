"""Auth request/response schemas."""

from pydantic import BaseModel, ConfigDict, Field

# Basic email-format contract matching the frontend's validation. Kept as a
# regex (stdlib `re` via pydantic `pattern`) to avoid adding a dependency
# (email-validator). Applied to REGISTRATION only, so users created before this
# validation existed can still log in.
_EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class RegisterRequest(BaseModel):
    email: str = Field(
        min_length=3,
        max_length=254,
        pattern=_EMAIL_PATTERN,
        examples=["alice@example.com"],
    )
    password: str = Field(min_length=6, max_length=128)
    name: str = Field(min_length=1, max_length=100, examples=["Alice"])
    allowed_cidrs: list[str] = Field(default=["0.0.0.0/0"])


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    email: str
    name: str
    created_at: str
    status: str
    allowed_cidrs: list[str]
    role: str = "user"
    is_admin: bool = False


class LoginResponse(BaseModel):
    token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut
