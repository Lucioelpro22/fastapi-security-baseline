"""Distributed request limiting with a safe development fallback."""
from __future__ import annotations

import math
import time
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .config import Settings
from .redis import create_redis_client

# Keep increment and expiry in one Redis-side operation.  A client-side
# INCR followed by EXPIRE has a failure window where a counter can survive
# forever if the process is interrupted between the two commands.
_ATOMIC_INCREMENT_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {count, ttl}
"""


@dataclass(frozen=True)
class LimitDecision:
    allowed: bool
    retry_after: int
    unavailable: bool = False


class RateLimiter:
    """Fixed-window limiter backed by Redis in production.

    Memory fallback is deliberately available only for development and test. Any
    Redis error in production denies the request, preventing an outage from
    silently removing the security control.
    """

    def __init__(self, settings: Settings, redis_client: Any | None = None):
        self.settings = settings
        self._redis = redis_client
        self._memory: dict[str, list[float]] = defaultdict(list)
        self._window_seconds = 60

    @property
    def using_memory(self) -> bool:
        return self._redis is None and self.settings.environment in {"development", "test"}

    async def _redis_check(self, key: str) -> LimitDecision:
        window = int(time.time() // self._window_seconds)
        redis_key = f"fastapi-security-baseline:ratelimit:{key}:{window}"
        # The script sets expiry only when the key has no TTL, so requests do
        # not extend a fixed window while still repairing a key accidentally
        # created without expiry. Both operations execute atomically in Redis.
        count, ttl = await self._redis.eval(
            _ATOMIC_INCREMENT_SCRIPT,
            1,
            redis_key,
            self._window_seconds,
        )
        count = int(count)
        ttl = int(ttl)
        retry_after = max(1, ttl if ttl > 0 else self._window_seconds)
        return LimitDecision(
            allowed=count <= self.settings.rate_limit_per_minute,
            retry_after=retry_after,
        )

    async def check(self, key: str) -> LimitDecision:
        if self.using_memory:
            now = time.monotonic()
            attempts = self._memory[key]
            attempts[:] = [stamp for stamp in attempts if now - stamp < self._window_seconds]
            if len(attempts) >= self.settings.rate_limit_per_minute:
                oldest = attempts[0] if attempts else now
                return LimitDecision(False, max(1, math.ceil(self._window_seconds - (now - oldest))))
            attempts.append(now)
            return LimitDecision(True, self._window_seconds)

        if self._redis is None:
            self._redis = create_redis_client(self.settings.redis_url or "")
        try:
            return await self._redis_check(key)
        except Exception:
            if self.settings.environment == "production":
                return LimitDecision(False, self._window_seconds, unavailable=True)
            # A configured Redis URL in development/test is optional. Keep local
            # runs usable if Redis is stopped, while never doing this in prod.
            self._redis = None
            return await self.check(key)

    async def check_many(self, keys: list[str] | tuple[str, ...]) -> LimitDecision:
        """Apply the same limit to each dimension and fail on the first block.

        Callers can combine independent dimensions (for example, client IP and
        normalized username) so changing one dimension cannot bypass the
        credential-attempt limit. Empty and duplicate keys are ignored.
        """
        seen: set[str] = set()
        for key in keys:
            if not key or key in seen:
                continue
            seen.add(key)
            decision = await self.check(key)
            if not decision.allowed:
                return decision
        return LimitDecision(True, self._window_seconds)


def normalize_username(username: str) -> str:
    """Canonicalize a login identifier before using it as a limiter key."""
    return unicodedata.normalize("NFKC", username).strip().casefold()
