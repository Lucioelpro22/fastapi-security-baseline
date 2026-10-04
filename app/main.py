import json
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .audit import audit_event
from .config import Settings, get_settings
from .db import get_session_factory, init_db
from .limiter import RateLimiter
from .mfa import (
    consume_recovery_code,
    decrypt_secret,
    encrypt_secret,
    generate_recovery_codes,
    hash_recovery_codes,
    new_totp_secret,
    valid_code,
)
from .observability import database_ready, redacted_log_fields, redis_ready, request_id
from .redis import close_redis
from .refresh import RefreshStoreUnavailable, RefreshTokenReuse, RefreshTokenStore
from .repositories import UserRepository
from .revocation import RevocationStore, RevocationUnavailable
from .security import (
    Role,
    create_access_token,
    current_user,
    hash_password,
    require_roles,
    verify_password,
)
from .webauthn import WebAuthnNotConfigured, provider_for_settings


class TokenRequest(BaseModel):
    username: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=256)
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")
    recovery_code: str | None = Field(default=None, min_length=8, max_length=64)


class MFACodeRequest(BaseModel):
    code: str = Field(pattern=r"^\d{6}$")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=40, max_length=256)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    if settings.environment == "production" and settings.debug:
        raise RuntimeError("DEBUG must be false in production")
    init_db()
    limiter = RateLimiter(settings)
    app.state.revocation_store = RevocationStore(settings)
    app.state.webauthn_provider = provider_for_settings(
        enabled=settings.webauthn_enabled,
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        origin=settings.webauthn_origin,
    )
    app.state.refresh_store = RefreshTokenStore(settings)
    app.state.rate_limiter = limiter
    try:
        yield
    finally:
        if limiter._redis is not None:
            await close_redis(limiter._redis)
        await app.state.revocation_store.close()
        await app.state.refresh_store.close()


app = FastAPI(title="FastAPI Security Baseline", version="0.2.0", docs_url="/docs", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=get_settings().allowed_origins, allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"], max_age=600)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    correlation_id = request_id(request.headers.get("X-Request-ID"))
    request.state.request_id = correlation_id
    started = time.perf_counter()
    response: Response = await call_next(request)
    response.headers["X-Request-ID"] = correlation_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Deliberately log an allow-list of metadata only. Never log headers, query
    # parameters, request bodies, credentials, or tokens.
    import logging

    logging.getLogger("security.request").info(json.dumps(redacted_log_fields({
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "request_id": correlation_id,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }), separators=(",", ":")))
    return response


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.url.path == "/auth/token":
        settings = get_settings()
        limiter = getattr(request.app.state, "rate_limiter", None)
        if limiter is None:
            limiter = request.app.state.rate_limiter = RateLimiter(settings)
        key = request.client.host if request.client else "unknown"
        decision = await limiter.check(key)
        if not decision.allowed:
            if decision.unavailable:
                return JSONResponse(
                    status_code=503,
                    content={"detail": "Rate limiting service unavailable"},
                    headers={"Retry-After": str(decision.retry_after)},
                )
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests"},
                headers={"Retry-After": str(decision.retry_after)},
            )
    return await call_next(request)


@app.get("/health", tags=["system"], include_in_schema=False)
def health():
    return {"status": "ok"}


@app.get("/health/live", tags=["system"])
def health_live():
    """Liveness probe: process routing is functioning."""
    return {"status": "ok"}


@app.get("/health/ready", tags=["system"])
async def health_ready(request: Request, settings: Settings = Depends(get_settings)):
    """Readiness probe for dependencies, with safe, stable public output."""
    database_ok = database_ready(settings)
    limiter = getattr(request.app.state, "rate_limiter", None)
    redis_client = getattr(limiter, "_redis", None)
    redis_ok, _ = await redis_ready(settings, redis_client)
    checks = {"database": "ok" if database_ok else "unavailable", "redis": "ok" if redis_ok else "unavailable"}
    if database_ok and redis_ok:
        return {"status": "ok", "checks": checks}
    return JSONResponse(status_code=503, content={"status": "not_ready", "checks": checks})


@app.post("/auth/token", tags=["auth"])
async def token(request: Request, body: TokenRequest, settings: Settings = Depends(get_settings)):
    username = body.username.lower()
    init_db()
    with get_session_factory()() as session:
        repository = UserRepository(session)
        user = repository.get_by_username(username)
        if user is None and username == "admin@example.com" and settings.admin_password is not None:
            user = repository.create(
                user_id="admin",
                username=username,
                role="admin",
                password_hash=hash_password(settings.admin_password.get_secret_value()),
            )
    if user is None or not user.is_active or not verify_password(body.password, user.password_hash):
        audit_event("login", body.username.lower(), "failure", getattr(request.state, "request_id", None))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if user.mfa_enabled:
        secret = decrypt_secret(user.mfa_secret_encrypted or "", settings)
        code_valid = bool(secret and body.totp_code and valid_code(secret, body.totp_code))
        recovery_used = False
        if not code_valid and body.recovery_code:
            recovery_used, remaining = consume_recovery_code(user.recovery_codes_hashes, body.recovery_code)
            if recovery_used:
                with get_session_factory()() as session:
                    persisted = UserRepository(session).get_by_id(user.id)
                    if persisted:
                        persisted.recovery_codes_hashes = remaining
                        session.commit()
        if not code_valid and not recovery_used:
            audit_event("mfa_login", user.id, "failure", getattr(request.state, "request_id", None))
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA required")
    audit_event("login", user.id, "success", getattr(request.state, "request_id", None))
    refresh_store = getattr(request.app.state, "refresh_store", None)
    if refresh_store is None:
        refresh_store = request.app.state.refresh_store = RefreshTokenStore(settings)
    refresh_token, _ = await refresh_store.issue(user.id, user.role)
    return {
        "access_token": create_access_token(user.id, user.role, settings),
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@app.post("/auth/refresh", tags=["auth"])
async def refresh(request: Request, body: RefreshRequest, settings: Settings = Depends(get_settings)):
    """Rotate a one-time refresh token and issue a fresh access token."""
    store = getattr(request.app.state, "refresh_store", None)
    if store is None:
        store = request.app.state.refresh_store = RefreshTokenStore(settings)
    try:
        new_refresh, grant = await store.rotate(body.refresh_token)
    except RefreshStoreUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RefreshTokenReuse as exc:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from exc
    access = create_access_token(grant.subject, grant.role, settings)
    return {"access_token": access, "refresh_token": new_refresh, "token_type": "bearer"}


@app.post("/auth/logout", tags=["auth"])
async def logout(
    request: Request,
    user: dict = Depends(current_user),
):
    """Revoke the current access token until its natural expiry."""
    store = getattr(request.app.state, "revocation_store", None)
    if store is None:
        store = request.app.state.revocation_store = RevocationStore(get_settings())
    try:
        await store.revoke(user["jti"], user["exp"])
    except RevocationUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    audit_event("logout", user["id"], "success")
    return {"status": "revoked"}


@app.get("/me", tags=["auth"])
def me(user: dict = Depends(current_user)):
    return {"id": user["id"], "role": user["role"]}


@app.get("/admin/status", tags=["admin"])
def admin_status(user: dict = Depends(require_roles(Role.ADMIN))):
    """Example endpoint restricted to administrators."""
    return {"status": "ok", "admin_id": user["id"]}


@app.post("/auth/webauthn/register/options", tags=["auth"], status_code=501)
def webauthn_registration_options(request: Request, user: dict = Depends(require_roles(Role.ADMIN))):
    """Return passkey registration options once an audited provider is installed."""
    provider = getattr(request.app.state, "webauthn_provider", None)
    if provider is None:
        provider = request.app.state.webauthn_provider = provider_for_settings(
            enabled=False, rp_id=None, rp_name="", origin=None
        )
    try:
        return provider.registration_options(user_id=user["id"], username=user["id"])
    except WebAuthnNotConfigured as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc


@app.post("/auth/webauthn/authenticate/options", tags=["auth"], status_code=501)
def webauthn_authentication_options(request: Request, user: dict = Depends(require_roles(Role.ADMIN))):
    """Return passkey authentication options once an audited provider is installed."""
    provider = getattr(request.app.state, "webauthn_provider", None)
    if provider is None:
        provider = request.app.state.webauthn_provider = provider_for_settings(
            enabled=False, rp_id=None, rp_name="", origin=None
        )
    try:
        return provider.authentication_options(username=user["id"])
    except WebAuthnNotConfigured as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc


@app.post("/auth/mfa/enroll", tags=["auth"])
def enroll_mfa(user: dict = Depends(require_roles(Role.ADMIN)), settings: Settings = Depends(get_settings)):
    with get_session_factory()() as session:
        account = UserRepository(session).get_by_id(user["id"])
        if account is None:
            raise HTTPException(status_code=404, detail="User not found")
        if account.mfa_enabled:
            raise HTTPException(status_code=409, detail="MFA is already enabled")
        secret = new_totp_secret()
        recovery_codes = generate_recovery_codes()
        account.mfa_secret_encrypted = encrypt_secret(secret, settings)
        account.recovery_codes_hashes = hash_recovery_codes(recovery_codes)
        session.commit()
        username = account.username
    import pyotp
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=settings.mfa_issuer)
    audit_event("mfa_enrollment_started", user["id"], "success")
    return {"secret": secret, "provisioning_uri": uri, "recovery_codes": recovery_codes}


@app.post("/auth/mfa/verify", tags=["auth"])
def verify_mfa(body: MFACodeRequest, user: dict = Depends(require_roles(Role.ADMIN)), settings: Settings = Depends(get_settings)):
    with get_session_factory()() as session:
        account = UserRepository(session).get_by_id(user["id"])
        secret = decrypt_secret(account.mfa_secret_encrypted or "", settings) if account else None
        if account is None or not secret or account.mfa_enabled or not valid_code(secret, body.code):
            raise HTTPException(status_code=400, detail="Invalid MFA enrollment code")
        account.mfa_enabled = True
        session.commit()
    audit_event("mfa_enabled", user["id"], "success")
    return {"status": "enabled"}
