from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import uuid4

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash

from .config import Settings, get_settings
from .db import get_session_factory
from .models import User
from .revocation import RevocationStore, RevocationUnavailable

password_hash = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


class Role(StrEnum):
    """Roles recognized by the API authorization layer."""

    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    USER = "user"


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return password_hash.verify(password, hashed)


def create_access_token(
    subject: str,
    role: str | Role,
    settings: Settings,
    *,
    jti: str | None = None,
    session_version: int = 0,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": subject,
        "role": str(role),
        "typ": "access",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "jti": jti or str(uuid4()),
        "sv": session_version,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(
        payload,
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
        headers={"kid": settings.jwt_key_id},
    )


def _verification_key(token: str, settings: Settings) -> str:
    """Select a signing key by JWT ``kid`` while allowing a staged rotation.

    Tokens created by versions before key IDs existed have no ``kid`` and are
    verified with the current key for backwards compatibility. Unknown IDs are
    rejected instead of trying every configured key.
    """
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if kid is None:
        return settings.jwt_secret.get_secret_value()
    if kid == settings.jwt_key_id:
        return settings.jwt_secret.get_secret_value()
    previous = settings.jwt_previous_secrets.get(kid)
    if previous is None:
        raise jwt.InvalidTokenError("Unknown signing key")
    return previous.get_secret_value()


async def current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    settings: Settings = Depends(get_settings),
) -> dict:
    credentials_error = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    try:
        payload = jwt.decode(
            token,
            _verification_key(token, settings),
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["sub", "role", "typ", "iss", "aud", "iat", "exp", "jti"]},
        )
        subject = payload.get("sub")
        role = payload.get("role")
        jti = payload.get("jti")
        if (
            payload.get("typ") != "access"
            or not isinstance(subject, str)
            or not isinstance(role, str)
            or not isinstance(jti, str)
            or role not in {item.value for item in Role}
        ):
            raise credentials_error
        token_session_version = payload.get("sv", 0)
        if not isinstance(token_session_version, int) or token_session_version < 0:
            raise credentials_error
        # The user record is the authoritative session epoch. A change that
        # requires re-authentication (currently MFA activation) increments it,
        # invalidating all previously issued access tokens.
        with get_session_factory()() as session:
            account = session.get(User, subject)
            # Keep compatibility with service-to-service subjects that are not
            # represented in the local users table. Persisted users are always
            # checked against the current session epoch.
            if account is not None and (not account.is_active or account.session_version != token_session_version):
                raise credentials_error
        store = getattr(request.app.state, "revocation_store", None)
        if store is None:
            store = request.app.state.revocation_store = RevocationStore(settings)
        if await store.is_revoked(jti):
            raise credentials_error
        return {
            "id": subject,
            "role": role,
            "jti": jti,
            "exp": payload["exp"],
            "session_version": token_session_version,
        }
    except RevocationUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except (jwt.PyJWTError, HTTPException) as exc:
        raise credentials_error from exc


def require_roles(*roles: Role | str):
    """Build a dependency that permits only the supplied roles.

    The dependency first authenticates the bearer token through ``current_user``
    and then applies authorization. Invalid or missing tokens remain 401;
    authenticated users without a required role receive 403.
    """
    if not roles:
        raise ValueError("At least one role is required")
    try:
        allowed_roles = {Role(role) for role in roles}
    except ValueError as exc:
        raise ValueError("Unknown role") from exc

    def role_dependency(user: dict = Depends(current_user)) -> dict:
        if Role(user["role"]) not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return role_dependency
