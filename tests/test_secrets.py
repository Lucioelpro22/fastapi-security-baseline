import pytest

from app.secrets import EnvironmentSecretProvider, SecretValidationError, validate_secret


def test_environment_provider_reads_mapping_without_using_global_environment():
    provider = EnvironmentSecretProvider({"JWT_SECRET": "a" * 32})
    assert provider.get("JWT_SECRET") == "a" * 32
    assert provider.get("MISSING") is None


def test_required_secret_rejects_missing_and_blank_values():
    provider = EnvironmentSecretProvider({"EMPTY": "   "})
    with pytest.raises(SecretValidationError, match="MISSING is required"):
        provider.get_required("MISSING")
    with pytest.raises(SecretValidationError, match="EMPTY is required"):
        provider.get_required("EMPTY")


def test_required_secret_enforces_length_without_disclosing_value():
    secret = "too-short-secret"
    with pytest.raises(SecretValidationError, match="JWT_SECRET must be at least 32 characters") as error:
        validate_secret("JWT_SECRET", secret, min_length=32)
    assert secret not in str(error.value)


@pytest.mark.parametrize("value", ["change-me", "CHANGE_ME", "secret", "your-secret-here"])
def test_demo_values_are_rejected_in_production(value):
    with pytest.raises(SecretValidationError, match="must not use a demo value"):
        validate_secret("JWT_SECRET", value, environment="production")


def test_demo_values_can_be_explicitly_rejected_outside_production():
    with pytest.raises(SecretValidationError):
        validate_secret("JWT_SECRET", "secret", reject_demo=True)


def test_custom_provider_can_use_shared_required_validation():
    provider = EnvironmentSecretProvider({"ADMIN_PASSWORD": "safe-password-123456"})
    assert (
        provider.get_required("ADMIN_PASSWORD", min_length=16, reject_demo=True)
        == "safe-password-123456"
    )

