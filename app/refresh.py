"""Opaque refresh-token rotation with shared, atomic replay detection.

Redis retains consumed-token digests until the original session expires. A
replay revokes that entire family, including descendants issued by other
workers. Rotation never extends the original session's absolute lifetime.
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

# Issuance and revocation must not interleave between checking a family and
# storing a token. Only hashes are stored; raw bearer values never reach Redis.
_ISSUE_SCRIPT = """
if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
local expires = tonumber(ARGV[4])
local bound = tonumber(redis.call('GET', KEYS[3]))
if bound then expires = bound end
if expires <= tonumber(redis.call('TIME')[1]) then return 0 end
if not bound then redis.call('SET', KEYS[3], expires, 'EXAT', expires) end
redis.call('HSET', KEYS[1], 'sub', ARGV[1], 'role', ARGV[2],
           'family', ARGV[3], 'exp', expires, 'sv', ARGV[5])
redis.call('EXPIREAT', KEYS[1], expires)
return expires
"""

# One operation consumes the old token, retains its family/expiry as a
# tombstone, and stores its successor. Another worker replaying the old token
# then revokes the family through the same absolute expiry. A competing
# descendant rotation either happens before revocation or observes it; no
# descendant remains usable once the replay operation has completed.
_ROTATE_SCRIPT = """
local values = redis.call('HMGET', KEYS[1], 'sub', 'role', 'family', 'exp', 'sv', 'used')
if not values[1] then return {} end
local expires = tonumber(values[4])
if not expires or expires <= tonumber(ARGV[2]) then return {} end
local family_key = ARGV[1] .. values[3]
local session_key = family_key .. ':expires'
local bound = tonumber(redis.call('GET', session_key))
if bound then expires = math.min(expires, bound) end
if expires <= tonumber(ARGV[2]) then return {} end
if not bound then redis.call('SET', session_key, expires, 'EXAT', expires) end
if values[6] == '1' then
    local ttl = redis.call('TTL', family_key)
    if ttl ~= -1 then
        if ttl >= 0 then expires = math.max(expires, tonumber(ARGV[2]) + ttl) end
        redis.call('SET', family_key, '1', 'EXAT', expires)
    end
    return {}
end
if redis.call('EXISTS', family_key) == 1 then return {} end
redis.call('HSET', KEYS[1], 'used', '1')
redis.call('EXPIREAT', KEYS[1], expires)
redis.call('HSET', KEYS[2], 'sub', values[1], 'role', values[2],
           'family', values[3], 'exp', expires, 'sv', values[5] or '0')
redis.call('EXPIREAT', KEYS[2], expires)
return {values[1], values[2], values[3], tostring(expires), values[5] or '0'}
"""


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
    session_version: int = 0


class RefreshTokenStore:
    def __init__(self, settings: Settings, redis_client: Any | None = None):
        self.settings = settings
        self._redis = redis_client
        self._memory: dict[str, RefreshGrant] = {}
        self._used: dict[str, RefreshGrant] = {}
        self._families_revoked: set[str] = set()
        self._family_expirations: dict[str, int] = {}

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

    async def issue(
        self,
        subject: str,
        role: str,
        family: str | None = None,
        session_version: int = 0,
        *,
        expires_at: int | None = None,
    ) -> tuple[str, RefreshGrant]:
        raw = secrets.token_urlsafe(48)
        deadline = int(time.time()) + self.settings.refresh_token_days * 86400
        grant = RefreshGrant(
            subject,
            role,
            family or str(uuid4()),
            min(expires_at, deadline) if expires_at is not None else deadline,
            session_version,
        )
        if grant.expires_at <= int(time.time()):
            raise RefreshTokenReuse("Refresh token session is expired")
        digest = self._digest(raw)
        if self.using_memory:
            if grant.family in self._families_revoked:
                raise RefreshTokenReuse("Refresh token family is revoked")
            bound = self._family_expirations.setdefault(grant.family, grant.expires_at)
            grant = RefreshGrant(subject, role, grant.family, bound, session_version)
            if grant.expires_at <= int(time.time()):
                raise RefreshTokenReuse("Refresh token session is expired")
            self._memory[digest] = grant
            return raw, grant
        try:
            issued = await self._ensure_client().eval(
                _ISSUE_SCRIPT, 3, self._key(digest), self._family_key(grant.family),
                self._family_key(grant.family) + ":expires",
                subject, role, grant.family, grant.expires_at, grant.session_version,
            )
            if not issued:
                raise RefreshTokenReuse("Refresh token family is revoked")
            return raw, RefreshGrant(subject, role, grant.family, int(issued), session_version)
        except RefreshTokenReuse:
            raise
        except Exception as exc:
            if self.settings.environment == "production":
                raise RefreshStoreUnavailable("Refresh token service unavailable") from exc
            self._redis = None
            if grant.family in self._families_revoked:
                raise RefreshTokenReuse("Refresh token family is revoked") from exc
            self._memory[digest] = grant
            return raw, grant

    async def rotate(self, raw: str) -> tuple[str, RefreshGrant]:
        digest = self._digest(raw)
        if self.using_memory:
            grant = self._memory.pop(digest, None)
            if grant is None:
                used = self._used.get(digest)
                if used is not None and used.expires_at > int(time.time()):
                    self._families_revoked.add(used.family)
                raise RefreshTokenReuse("Refresh token is invalid or already used")
            if grant.family in self._families_revoked or grant.expires_at <= int(time.time()):
                raise RefreshTokenReuse("Refresh token is invalid or expired")
            self._used[digest] = grant
            return await self.issue(
                grant.subject, grant.role, grant.family, grant.session_version,
                expires_at=grant.expires_at,
            )
        try:
            replacement = secrets.token_urlsafe(48)
            values = await self._ensure_client().eval(
                _ROTATE_SCRIPT, 2, self._key(digest), self._key(self._digest(replacement)),
                self._family_key(""), int(time.time()),
            )
            if not values:
                raise RefreshTokenReuse("Refresh token is invalid or already used")
            grant = RefreshGrant(values[0], values[1], values[2], int(values[3]), int(values[4]))
            return replacement, grant
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
