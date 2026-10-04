import os

os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-123456")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("ADMIN_PASSWORD", "ChangeThisTestPassword!12345")

import jwt
from fastapi.testclient import TestClient

from app.config import Settings
from app.security import Role, create_access_token


def test_access_token_contains_key_id_and_old_key_can_be_verified():
    settings = Settings(jwt_secret="new-secret-that-is-long-enough-123456", jwt_key_id="new")
    token = create_access_token("u1", Role.USER, settings)
    assert jwt.get_unverified_header(token)["kid"] == "new"
    old = Settings(
        jwt_secret="new-secret-that-is-long-enough-123456",
        jwt_key_id="new",
        jwt_previous_secrets={"old": "old-secret-that-is-long-enough-123456"},
    )
    legacy = jwt.encode(
        {"sub": "u1", "role": "user", "typ": "access", "iss": old.jwt_issuer,
         "aud": old.jwt_audience, "jti": "legacy", "iat": 1, "exp": 4102444800},
        old.jwt_previous_secrets["old"].get_secret_value(), algorithm="HS256", headers={"kid": "old"},
    )
    assert jwt.decode(legacy, old.jwt_previous_secrets["old"].get_secret_value(), algorithms=["HS256"],
                      audience=old.jwt_audience, issuer=old.jwt_issuer)["sub"] == "u1"


def test_refresh_token_rotates_and_reuse_is_rejected():
    from app.main import app

    with TestClient(app) as client:
        login = client.post("/auth/token", json={"username": "admin@example.com", "password": "ChangeThisTestPassword!12345"})
        assert login.status_code == 200
        first = login.json()["refresh_token"]
        rotated = client.post("/auth/refresh", json={"refresh_token": first})
        assert rotated.status_code == 200
        second = rotated.json()["refresh_token"]
        assert second != first
        assert client.post("/auth/refresh", json={"refresh_token": first}).status_code == 401
        assert client.get("/me", headers={"Authorization": f"Bearer {rotated.json()['access_token']}"}).status_code == 200
