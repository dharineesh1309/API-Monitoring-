import ipaddress
from fastapi import Depends, Header, HTTPException, Request

from .services import Container
from .telemetry.logging import get_logger

logger = get_logger(__name__)


def get_container(request: Request) -> Container:
    """Return the application's service container (created once at startup)."""
    return request.app.state.container


def get_bearer_token(authorization: str = Header(default="")) -> str:
    """Extract the raw bearer token from the Authorization header."""
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return token


def require_auth(
    token: str = Depends(get_bearer_token), 
    container: Container = Depends(get_container)
) -> str:
    """Require a valid bearer token."""
    container.auth.get_profile(token)
    return token


def require_admin(
    token: str = Depends(get_bearer_token),
    container: Container = Depends(get_container),
):
    """Require valid bearer token and admin privileges."""
    user = container.auth.get_profile(token)
    if not getattr(user, "is_admin", False) and getattr(user, "role", "") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user
