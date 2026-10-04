"""Short-lived access-token revocation storage.

Redis is used when configured so revocations are shared by all API workers.
Development and test environments use a process-local set, while production
fails closed if Redis cannot answer a revocation check.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .config import Settings
from .redis import close_redis, create_redis_client


class RevocationUnavailable(RuntimeError):
    """Raised when production cannot verify a token's revocation status."""


class RevocationStore:
    def __init__(self, settings: Settings, redis_client: Any | None = None):
        self.settings = settings
        self._redis = redis_client
        self._memory: set[str] = set()

    @property
    def using_memory(self) -> bool:
        return self._redis is None and self.settings.environment in {"development", "test"}

    def _key(self, jti: str) -> str:
        return f"fastapi-security-baseline:revoked-token:{jti}"

    def _ensure_client(self) -> Any:
        if self._redis is None:
            self._redis = create_redis_client(self.settings.redis_url or "")
        return self._redis

    async def is_revoked(self, jti: str) -> bool:
        if self.using_memory:
            return jti in self._memory
        try:
            return bool(await self._ensure_client().exists(self._key(jti)))
        except Exception as exc:
            if self.settings.environment == "production":
                raise RevocationUnavailable("Token revocation service unavailable") from exc
            # Redis is optional outside production. Keep local development usable.
            self._redis = None
            return jti in self._memory

    async def revoke(self, jti: str, expires_at: int | float) -> None:
        now = datetime.now(UTC).timestamp()
        ttl = max(1, int(expires_at - now))
        if self.using_memory:
            self._memory.add(jti)
            return
        try:
            await self._ensure_client().setex(self._key(jti), ttl, "1")
        except Exception as exc:
            if self.settings.environment == "production":
                raise RevocationUnavailable("Token revocation service unavailable") from exc
            self._redis = None
            self._memory.add(jti)

    async def close(self) -> None:
        if self._redis is not None:
            await close_redis(self._redis)

