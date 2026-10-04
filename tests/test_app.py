import os

os.environ["JWT_SECRET"] = "test-secret-that-is-long-enough-123456"
os.environ["ENVIRONMENT"] = "test"
os.environ["ADMIN_PASSWORD"] = "ChangeThisTestPassword!12345"
os.environ["ALLOWED_ORIGINS"] = '["https://client.example"]'

from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from app.security import Role, create_access_token

client = TestClient(app)


def test_health_and_security_headers():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_invalid_login_is_rejected():
    response = client.post("/auth/token", json={"username": "admin@example.com", "password": "wrong-password-long"})
    assert response.status_code == 401


def test_login_and_protected_route():
    response = client.post("/auth/token", json={"username": "admin@example.com", "password": "ChangeThisTestPassword!12345"})
    assert response.status_code == 200
    token = response.json()["access_token"]
    protected = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert protected.status_code == 200
    assert protected.json()["role"] == "admin"


def test_admin_can_access_admin_endpoint():
    response = client.post(
        "/auth/token",
        json={"username": "admin@example.com", "password": "ChangeThisTestPassword!12345"},
    )
    token = response.json()["access_token"]

    protected = client.get("/admin/status", headers={"Authorization": f"Bearer {token}"})

    assert protected.status_code == 200
    assert protected.json() == {"status": "ok", "admin_id": "admin"}


def test_non_admin_is_forbidden_from_admin_endpoint():
    token = create_access_token("user-1", Role.USER, get_settings())

    protected = client.get("/admin/status", headers={"Authorization": f"Bearer {token}"})

    assert protected.status_code == 403
    assert protected.json() == {"detail": "Insufficient permissions"}
