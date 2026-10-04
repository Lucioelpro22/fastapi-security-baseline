"""Distributed request limiting with a safe development fallback."""
from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .config import Settings
from .redis import create_redis_client


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
        # Set expiry only on the first hit so later requests cannot extend the
        # fixed window indefinitely. Redis keeps the key bounded by this TTL.
        pipe = self._redis.pipeline(transaction=True)
        pipe.incr(redis_key)
        result = await pipe.execute()
        count = result[0]
        if int(count) == 1:
            await self._redis.expire(redis_key, self._window_seconds)
        ttl = await self._redis.ttl(redis_key)
        retry_after = max(1, int(ttl) if int(ttl) > 0 else self._window_seconds)
        return LimitDecision(
            allowed=int(count) <= self.settings.rate_limit_per_minute,
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
