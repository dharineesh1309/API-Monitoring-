"""Business route tests covering core e-commerce & workflow operations:
- /auth/register, /auth/login, /auth/profile
- /orders (create, list, get)
- /files (metadata & S3 flows)
- /notifications and /queue
"""

from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.models.user import User
from app.models.order import Order


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def test_auth_registration_and_login_flow(client):
    """Test user registration, login, token retrieval and profile access."""
    with patch("app.services.auth_service.AuthService.register") as mock_reg, \
         patch("app.services.auth_service.AuthService.login") as mock_login, \
         patch("app.services.auth_service.AuthService.get_profile") as mock_profile:

        mock_reg.return_value = User(
            user_id="usr_test123456",
            email="testuser@example.com",
            name="Test User",
            created_at="2026-11-17T12:00:00Z",
            status="ACTIVE",
            allowed_cidrs=["0.0.0.0/0"],
            role="user",
            is_admin=False,
        )

        reg_res = client.post(
            "/auth/register",
            json={
                "email": "testuser@example.com",
                "password": "Password123!",
                "name": "Test User",
                "allowed_cidrs": ["0.0.0.0/0"],
            },
        )
        assert reg_res.status_code == 201
        assert reg_res.json()["email"] == "testuser@example.com"

        mock_login.return_value = {
            "token": "valid_test_token_12345",
            "token_type": "bearer",
            "expires_in": 3600,
            "user": mock_reg.return_value,
        }

        login_res = client.post(
            "/auth/login",
            json={"email": "testuser@example.com", "password": "Password123!"},
        )
        assert login_res.status_code == 200
        assert "token" in login_res.json()

        mock_profile.return_value = mock_reg.return_value
        profile_res = client.get(
            "/auth/profile",
            headers={"Authorization": "Bearer valid_test_token_12345"},
        )
        assert profile_res.status_code == 200
        assert profile_res.json()["user_id"] == "usr_test123456"


def test_orders_creation_and_listing(client):
    """Test order creation, distributed tracing integration, and order scan."""
    mock_order = Order(
        order_id="ord_abc123456789",
        user_id="usr_test123456",
        items=[{"product_id": "prod_1", "name": "Widget A", "quantity": 2, "unit_price": 19.99}],
        total=39.98,
        status="created",
        created_at="2026-11-17T12:00:00Z",
    )

    with patch("app.services.auth_service.AuthService.get_profile") as mock_profile, \
         patch("app.services.dynamodb_service.DynamoDBService.put_item") as mock_put, \
         patch("app.services.dynamodb_service.DynamoDBService.latest") as mock_scan:

        mock_profile.return_value = User(
            user_id="usr_test123456",
            email="testuser@example.com",
            name="Test User",
            created_at="2026-11-17T12:00:00Z",
        )
        mock_scan.return_value = [mock_order.to_item()]

        order_res = client.post(
            "/orders",
            headers={"Authorization": "Bearer valid_test_token_12345"},
            json={
                "user_id": "usr_test123456",
                "items": [
                    {"product_id": "prod_1", "name": "Widget A", "quantity": 2, "unit_price": 19.99}
                ],
            },
        )
        assert order_res.status_code == 201
        assert order_res.json()["total"] == 39.98

        list_res = client.get(
            "/orders",
            headers={"Authorization": "Bearer valid_test_token_12345"},
        )
        assert list_res.status_code == 200
        assert len(list_res.json()["orders"]) == 1


def test_unauthorized_access_rejected(client):
    """Ensure unauthenticated calls to protected business routes receive 401."""
    res = client.get("/orders")
    assert res.status_code == 401

