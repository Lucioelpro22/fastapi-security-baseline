"""Opaque refresh-token rotation and reuse detection.

Refresh values are never JWTs and are stored only as SHA-256 digests. The
in-memory implementation supports development/tests; production requires the
configured Redis backend so token state is shared across workers.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from .config import Settings
from .redis import close_redis, create_redis_client


class RefreshStoreUnavailable(RuntimeError):
    """Raised when production cannot verify refresh-token state."""


class RefreshTokenReuse(RuntimeError):
    """Raised when a previously rotated refresh token is presented."""


@dataclass(frozen=True)
class RefreshGrant:
    subject: str
    role: str
    family: str
    expires_at: int


class RefreshTokenStore:
    def __init__(self, settings: Settings, redis_client: Any | None = None):
        self.settings = settings
        self._redis = redis_client
        self._memory: dict[str, RefreshGrant] = {}
        self._used: set[str] = set()
        self._used_families: dict[str, str] = {}
        self._families_revoked: set[str] = set()

    @property
    def using_memory(self) -> bool:
        return self._redis is None and self.settings.environment in {"development", "test"}

    def _ensure_client(self) -> Any:
        if self._redis is None:
            self._redis = create_redis_client(self.settings.redis_url or "")
        return self._redis

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _key(self, digest: str) -> str:
        return f"fastapi-security-baseline:refresh:{digest}"

    def _family_key(self, family: str) -> str:
        return f"fastapi-security-baseline:refresh-family:{family}"

    async def issue(self, subject: str, role: str, family: str | None = None) -> tuple[str, RefreshGrant]:
        raw = secrets.token_urlsafe(48)
        grant = RefreshGrant(subject, role, family or str(uuid4()), int(time.time()) + self.settings.refresh_token_days * 86400)
        digest = self._digest(raw)
        if self.using_memory:
            self._memory[digest] = grant
            return raw, grant
        try:
            await self._ensure_client().hset(self._key(digest), mapping={"sub": subject, "role": role, "family": grant.family, "exp": grant.expires_at})
            await self._ensure_client().expireat(self._key(digest), grant.expires_at)
            return raw, grant
        except Exception as exc:
            if self.settings.environment == "production":
                raise RefreshStoreUnavailable("Refresh token service unavailable") from exc
            self._redis = None
            self._memory[digest] = grant
            return raw, grant

    async def rotate(self, raw: str) -> tuple[str, RefreshGrant]:
        digest = self._digest(raw)
        if self.using_memory:
            grant = self._memory.pop(digest, None)
            if digest in self._used or grant is None:
                if digest in self._used and grant is None:
                    family = self._used_families.get(digest)
                    if family:
                        self._families_revoked.add(family)
                raise RefreshTokenReuse("Refresh token is invalid or already used")
            if grant.family in self._families_revoked or grant.expires_at <= int(time.time()):
                raise RefreshTokenReuse("Refresh token is invalid or expired")
            self._used.add(digest)
            self._used_families[digest] = grant.family
            return await self.issue(grant.subject, grant.role, grant.family)
        client = self._ensure_client()
        try:
            key = self._key(digest)
            # Redis GETDEL is atomic and prevents two workers from rotating the
            # same token concurrently.
            values = await client.hgetall(key)
            if not values or not await client.delete(key):
                raise RefreshTokenReuse("Refresh token is invalid or already used")
            if await client.exists(self._family_key(values["family"])):
                raise RefreshTokenReuse("Refresh token family is revoked")
            grant = RefreshGrant(values["sub"], values["role"], values["family"], int(values["exp"]))
            if grant.expires_at <= int(time.time()):
                raise RefreshTokenReuse("Refresh token is expired")
            return await self.issue(grant.subject, grant.role, grant.family)
        except RefreshTokenReuse:
            raise
        except Exception as exc:
            if self.settings.environment == "production":
                raise RefreshStoreUnavailable("Refresh token service unavailable") from exc
            self._redis = None
            raise RefreshTokenReuse("Refresh token is invalid or already used") from exc

    async def revoke_family(self, family: str, ttl: int | None = None) -> None:
        ttl = ttl or self.settings.refresh_token_days * 86400
        if self.using_memory:
            self._families_revoked.add(family)
            return
        try:
            await self._ensure_client().setex(self._family_key(family), ttl, "1")
        except Exception as exc:
            if self.settings.environment == "production":
                raise RefreshStoreUnavailable("Refresh token service unavailable") from exc
            self._redis = None
            self._families_revoked.add(family)

    async def close(self) -> None:
        if self._redis is not None:
            await close_redis(self._redis)
