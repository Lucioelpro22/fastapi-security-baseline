"""Regression tests for the v0.2 security baseline.

These tests exercise externally observable controls rather than implementation
details, so they also act as an executable production checklist.
"""

import os
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.limiter import RateLimiter
from app.main import app

client = TestClient(app)


def _login() -> str:
    response = client.post(
        "/auth/token",
        json={"username": "admin@example.com", "password": "ChangeThisTestPassword!12345"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_jwt_rejects_tampered_signature_and_wrong_claims():
    token = _login()
    tampered = f"{token[:-1]}{'a' if token[-1] != 'a' else 'b'}"
    assert client.get("/me", headers={"Authorization": f"Bearer {tampered}"}).status_code == 401

    settings = get_settings()
    payload = {
        "sub": "admin",
        "role": "admin",
        "typ": "access",
        "iss": settings.jwt_issuer,
        "aud": "wrong-audience",
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=5),
    }
    wrong_audience = jwt.encode(payload, settings.jwt_secret.get_secret_value(), algorithm="HS256")
    assert client.get("/me", headers={"Authorization": f"Bearer {wrong_audience}"}).status_code == 401


def test_login_rate_limit_returns_429_and_retry_after(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "1")
    get_settings.cache_clear()
    app.state.rate_limiter = RateLimiter(get_settings())
    try:
        first = client.post(
            "/auth/token",
            json={"username": "admin@example.com", "password": "wrong-password-long"},
        )
        second = client.post(
            "/auth/token",
            json={"username": "admin@example.com", "password": "wrong-password-long"},
        )
        assert first.status_code == 401
        assert second.status_code == 429
        assert 1 <= int(second.headers["retry-after"]) <= 60
    finally:
        monkeypatch.delenv("RATE_LIMIT_PER_MINUTE")
        get_settings.cache_clear()
        app.state.rate_limiter = RateLimiter(get_settings())


def test_cors_allows_configured_origin_and_rejects_unknown_origin():
    allowed = client.options(
        "/auth/token",
        headers={
            "Origin": "https://client.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "https://client.example"

    unknown = client.options(
        "/auth/token",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "access-control-allow-origin" not in unknown.headers


def test_production_configuration_requires_persistent_controls():
    common = {
        "environment": "production",
        "jwt_secret": "production-secret-that-is-longer-than-32-chars",
        "admin_password": "production-admin-password-1234",
        "redis_url": "redis://redis:6379/0",
    }
    assert Settings(**common).environment == "production"

    for field, value in (("redis_url", None), ("admin_password", None), ("database_url", "sqlite:///:memory:")):
        values = dict(common)
        values[field] = value
        try:
            Settings(**values)
        except ValueError:
            pass
        else:
            raise AssertionError(f"production configuration unexpectedly accepted {field}")


def test_production_debug_is_rejected_at_application_startup(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("ADMIN_PASSWORD", "production-admin-password-1234")
    monkeypatch.setenv("JWT_SECRET", "production-secret-that-is-longer-than-32-chars")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="DEBUG must be false in production"):
            with TestClient(app):
                pass
    finally:
        for name in ("ENVIRONMENT", "DEBUG", "REDIS_URL", "ADMIN_PASSWORD", "JWT_SECRET"):
            os.environ.pop(name, None)
        os.environ["ENVIRONMENT"] = "test"
        os.environ["JWT_SECRET"] = "test-secret-that-is-long-enough-123456"
        os.environ["ADMIN_PASSWORD"] = "ChangeThisTestPassword!12345"
        get_settings.cache_clear()
