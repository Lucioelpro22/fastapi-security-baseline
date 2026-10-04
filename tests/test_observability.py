import logging

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_request_id_is_propagated_and_invalid_values_are_replaced():
    supplied = "trace_123.safe"
    response = client.get("/health/live", headers={"X-Request-ID": supplied})
    assert response.status_code == 200
    assert response.headers["x-request-id"] == supplied

    invalid = client.get("/health/live", headers={"X-Request-ID": "bad id secret"})
    assert invalid.status_code == 200
    generated = invalid.headers["x-request-id"]
    assert generated != "bad id secret"
    assert len(generated) <= 64


def test_health_probes_have_safe_contract():
    live = client.get("/health/live")
    assert live.status_code == 200
    assert live.json() == {"status": "ok"}

    ready = client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ok", "checks": {"database": "ok", "redis": "ok"}}


def test_request_logs_exclude_credentials_and_payload(caplog):
    caplog.set_level(logging.INFO, logger="security.request")
    response = client.post(
        "/auth/token",
        params={"password": "query-secret"},
        json={"username": "admin@example.com", "password": "body-secret-long"},
        headers={"Authorization": "Bearer access-token"},
    )
    assert response.status_code == 401
    records = [record.message for record in caplog.records if record.name == "security.request"]
    assert records
    assert "query-secret" not in records[-1]
    assert "body-secret-long" not in records[-1]
    assert "access-token" not in records[-1]
    assert "request_id" in records[-1]
