from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(254), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    # The TOTP secret is encrypted with MFA_ENCRYPTION_KEY. Older development
    # records may use the legacy JWT-derived key during migration. Recovery
    # codes are Argon2 hashes, never plaintext.
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    recovery_codes_hashes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Incremented when MFA is enabled (and for future credential changes).
    # Access and refresh tokens carry this value, invalidating prior sessions.
    session_version: Mapped[int] = mapped_column(nullable=False, default=0)
