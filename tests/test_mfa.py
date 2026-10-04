import os

import pyotp
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET", "test-secret-that-is-long-enough-123456")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("ADMIN_PASSWORD", "ChangeThisTestPassword!12345")

from app.db import get_session_factory, init_db
from app.main import app
from app.models import User


def _token(client: TestClient, **extra) -> str:
    payload = {"username": "admin@example.com", "password": "ChangeThisTestPassword!12345", **extra}
    response = client.post("/auth/token", json=payload)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def test_admin_totp_enrollment_login_and_one_time_recovery_code():
    init_db()
    with get_session_factory()() as session:
        admin = session.get(User, "admin")
        if admin:
            admin.mfa_enabled = False
            admin.mfa_secret_encrypted = None
            admin.recovery_codes_hashes = None
            session.commit()
    client = TestClient(app)
    token = _token(client)
    headers = {"Authorization": f"Bearer {token}"}
    enrollment = client.post("/auth/mfa/enroll", headers=headers)
    assert enrollment.status_code == 200
    data = enrollment.json()
    assert len(data["recovery_codes"]) == 10
    assert data["secret"] not in str(_stored_admin())

    code = pyotp.TOTP(data["secret"]).now()
    assert client.post("/auth/mfa/verify", headers=headers, json={"code": code}).status_code == 200
    assert client.post("/auth/token", json={"username": "admin@example.com", "password": "ChangeThisTestPassword!12345"}).status_code == 401
    totp_login = client.post("/auth/token", json={"username": "admin@example.com", "password": "ChangeThisTestPassword!12345", "totp_code": pyotp.TOTP(data["secret"]).now()})
    assert totp_login.status_code == 200
    recovery = data["recovery_codes"][0]
    first = client.post("/auth/token", json={"username": "admin@example.com", "password": "ChangeThisTestPassword!12345", "recovery_code": recovery})
    second = client.post("/auth/token", json={"username": "admin@example.com", "password": "ChangeThisTestPassword!12345", "recovery_code": recovery})
    assert first.status_code == 200
    assert second.status_code == 401
    with get_session_factory()() as session:
        admin = session.get(User, "admin")
        admin.mfa_enabled = False
        admin.mfa_secret_encrypted = None
        admin.recovery_codes_hashes = None
        session.commit()


def _stored_admin() -> dict:
    with get_session_factory()() as session:
        user = session.get(User, "admin")
        return {"secret": user.mfa_secret_encrypted, "hashes": user.recovery_codes_hashes}
