from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .secrets import validate_secret


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    app_name: str = "fastapi-security-baseline"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False
    jwt_secret: SecretStr = Field(default=..., min_length=32)
    jwt_algorithm: Literal["HS256"] = "HS256"
    jwt_issuer: str = "fastapi-security-baseline"
    jwt_audience: str = "fastapi-security-baseline-api"
    # ``jwt_secret`` is the active signing key. Previous keys may remain here
    # during a rollout so already-issued access tokens can expire naturally.
    jwt_key_id: str = Field(default="default", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    jwt_previous_secrets: dict[str, SecretStr] = Field(default_factory=dict)
    admin_password: SecretStr | None = None
    access_token_minutes: int = Field(default=15, ge=5, le=60)
    refresh_token_days: int = Field(default=30, ge=1, le=365)
    allowed_origins: list[str] = Field(default_factory=list)
    redis_url: str | None = None
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10000)
    database_url: str = "sqlite:///./security_baseline.db"
    mfa_issuer: str = "fastapi-security-baseline"
    # WebAuthn is intentionally opt-in until an audited provider is wired in.
    webauthn_enabled: bool = False
    webauthn_rp_id: str | None = None
    webauthn_rp_name: str = "FastAPI Security Baseline"
    webauthn_origin: str | None = None

    @field_validator("jwt_secret")
    @classmethod
    def reject_weak_secret(cls, value: SecretStr) -> SecretStr:
        validate_secret(
            "JWT_SECRET",
            value.get_secret_value(),
            min_length=32,
            reject_demo=True,
        )
        return value

    @field_validator("admin_password")
    @classmethod
    def require_admin_password_in_production(cls, value: SecretStr | None, info):
        environment = info.data.get("environment")
        if environment == "production" and value is None:
            raise ValueError("ADMIN_PASSWORD is required in production")
        if value is not None:
            validate_secret(
                "ADMIN_PASSWORD",
                value.get_secret_value(),
                min_length=16,
                reject_demo=True,
                environment=environment or "development",
            )
        return value

    @field_validator("redis_url")
    @classmethod
    def require_redis_in_production(cls, value: str | None, info):
        if info.data.get("environment") == "production" and not value:
            raise ValueError("REDIS_URL is required in production")
        return value

    @field_validator("database_url")
    @classmethod
    def reject_ephemeral_database_in_production(cls, value: str, info) -> str:
        """Critical state must survive a process restart in production."""
        if info.data.get("environment") == "production":
            normalized = value.strip().lower()
            if normalized in {"sqlite:///:memory:", "sqlite://", "sqlite:///:memory"}:
                raise ValueError("DATABASE_URL must use a persistent backend in production")
        return value

    @field_validator("webauthn_rp_id")
    @classmethod
    def validate_webauthn_rp_id(cls, value: str | None, info) -> str | None:
        if info.data.get("webauthn_enabled") and not value:
            raise ValueError("WEBAUTHN_RP_ID is required when WebAuthn is enabled")
        if value and ("/" in value or "://" in value or not value.strip()):
            raise ValueError("WEBAUTHN_RP_ID must be a registrable host name, without a scheme or path")
        return value

    @field_validator("webauthn_origin")
    @classmethod
    def validate_webauthn_origin(cls, value: str | None, info) -> str | None:
        if info.data.get("webauthn_enabled") and not value:
            raise ValueError("WEBAUTHN_ORIGIN is required when WebAuthn is enabled")
        if value:
            from urllib.parse import urlparse

            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
                raise ValueError("WEBAUTHN_ORIGIN must be an absolute HTTP(S) origin")
            if info.data.get("environment") == "production" and parsed.scheme != "https":
                raise ValueError("WEBAUTHN_ORIGIN must use HTTPS in production")
        return value.rstrip("/") if value else value


@lru_cache
def get_settings() -> Settings:
    return Settings()
