"""Small, database-backed TOTP helper for administrator MFA."""
import base64
import hashlib
import json
import secrets

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from .config import Settings
from .security import hash_password, verify_password


def _cipher(settings: Settings) -> Fernet:
    if settings.mfa_encryption_key is not None:
        return Fernet(settings.mfa_encryption_key.get_secret_value())
    if settings.environment == "production":
        raise RuntimeError("MFA_ENCRYPTION_KEY is required for MFA in production")
    # Migration compatibility for records created before v0.5. New records
    # are always written with MFA_ENCRYPTION_KEY when it is configured.
    digest = hashlib.sha256(settings.jwt_secret.get_secret_value().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(secret: str, settings: Settings) -> str:
    return _cipher(settings).encrypt(secret.encode()).decode()


def decrypt_secret(value: str, settings: Settings) -> str | None:
    try:
        return _cipher(settings).decrypt(value.encode()).decode()
    except (InvalidToken, ValueError, UnicodeDecodeError):
        # During migration, try the legacy JWT-derived key after the dedicated
        # key. This path is intentionally unavailable in production without a
        # dedicated key because _cipher fails closed there.
        if settings.mfa_encryption_key is None and settings.environment != "production":
            digest = hashlib.sha256(settings.jwt_secret.get_secret_value().encode()).digest()
            try:
                return Fernet(base64.urlsafe_b64encode(digest)).decrypt(value.encode()).decode()
            except (InvalidToken, ValueError, UnicodeDecodeError):
                pass
        return None


def new_totp_secret() -> str:
    return pyotp.random_base32(length=32)


def valid_code(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def generate_recovery_codes(count: int = 10) -> list[str]:
    return [secrets.token_hex(8) for _ in range(count)]


def hash_recovery_codes(codes: list[str]) -> str:
    return json.dumps([hash_password(code) for code in codes], separators=(",", ":"))


def consume_recovery_code(stored: str | None, candidate: str) -> tuple[bool, str | None]:
    if not stored:
        return False, stored
    try:
        hashes = json.loads(stored)
    except (TypeError, ValueError):
        return False, stored
    if not isinstance(hashes, list):
        return False, stored
    for index, hashed in enumerate(hashes):
        if isinstance(hashed, str) and verify_password(candidate, hashed):
            remaining = hashes[:index] + hashes[index + 1 :]
            return True, json.dumps(remaining, separators=(",", ":"))
    return False, stored
