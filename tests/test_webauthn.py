import pytest
from pydantic import ValidationError

from app.config import Settings
from app.webauthn import DisabledWebAuthnProvider, WebAuthnNotConfigured


def test_disabled_provider_fails_closed_without_emitting_options():
    provider = DisabledWebAuthnProvider()
    with pytest.raises(WebAuthnNotConfigured):
        provider.registration_options(user_id="admin", username="admin@example.com")
    with pytest.raises(WebAuthnNotConfigured):
        provider.authentication_options()


def test_webauthn_production_configuration_requires_https_origin_and_rp_id():
    base = {"jwt_secret": "test-secret-that-is-long-enough-123456", "environment": "production", "admin_password": "ChangeThisProductionPassword!123"}
    with pytest.raises(ValidationError):
        Settings(**base, webauthn_enabled=True, webauthn_origin="https://example.com")
    with pytest.raises(ValidationError):
        Settings(**base, webauthn_enabled=True, webauthn_rp_id="example.com", webauthn_origin="http://example.com")


def test_webauthn_origin_and_rp_id_are_validated():
    settings = Settings(
        jwt_secret="test-secret-that-is-long-enough-123456",
        environment="test",
        webauthn_enabled=True,
        webauthn_rp_id="example.com",
        webauthn_origin="https://example.com/",
    )
    assert settings.webauthn_origin == "https://example.com"
