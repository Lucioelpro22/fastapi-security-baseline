import os

os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-123456")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("ADMIN_PASSWORD", "ChangeThisTestPassword!12345")

import jwt
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app
from app.security import Role, create_access_token

client = TestClient(app)


def _login() -> str:
    response = client.post(
        "/auth/token",
        json={"username": "admin@example.com", "password": "ChangeThisTestPassword!12345"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_access_tokens_have_unique_jti_and_required_claims():
    settings = get_settings()
    first = create_access_token("admin", Role.ADMIN, settings)
    second = create_access_token("admin", Role.ADMIN, settings)
    first_claims = jwt.decode(
        first,
        settings.jwt_secret.get_secret_value(),
        algorithms=[settings.jwt_algorithm],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )
    second_claims = jwt.decode(
        second,
        settings.jwt_secret.get_secret_value(),
        algorithms=[settings.jwt_algorithm],
        audience=settings.jwt_audience,
        issuer=settings.jwt_issuer,
    )
    assert isinstance(first_claims["jti"], str)
    assert first_claims["jti"] != second_claims["jti"]


def test_logout_revokes_only_current_token():
    token = _login()
    other_token = _login()
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/me", headers=headers).status_code == 200
    response = client.post("/auth/logout", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"status": "revoked"}
    assert client.get("/me", headers=headers).status_code == 401
    assert client.get("/me", headers={"Authorization": f"Bearer {other_token}"}).status_code == 200


def test_logout_requires_a_valid_bearer_token():
    assert client.post("/auth/logout").status_code == 401
