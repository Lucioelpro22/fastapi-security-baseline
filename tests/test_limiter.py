from types import SimpleNamespace

import pytest

from app.limiter import RateLimiter


class FakePipeline:
    def __init__(self, redis):
        self.redis = redis
        self.commands = []

    def incr(self, key):
        self.commands.append(("incr", key))

    async def execute(self):
        key = self.commands[0][1]
        self.redis.counts[key] = self.redis.counts.get(key, 0) + 1
        return [self.redis.counts[key]]


class FakeRedis:
    def __init__(self):
        self.counts = {}
        self.expirations = {}

    def pipeline(self, transaction=True):
        return FakePipeline(self)

    async def expire(self, key, seconds):
        self.expirations[key] = seconds
        return True

    async def ttl(self, key):
        return self.expirations.get(key, 60)


@pytest.mark.anyio
async def test_redis_limiter_sets_ttl_and_returns_429_decision():
    settings = SimpleNamespace(environment="production", redis_url="redis://test", rate_limit_per_minute=1)
    limiter = RateLimiter(settings, redis_client=FakeRedis())

    first = await limiter.check("127.0.0.1")
    second = await limiter.check("127.0.0.1")

    assert first.allowed is True
    assert second.allowed is False
    assert second.retry_after == 60
    assert len(limiter._redis.expirations) == 1


@pytest.mark.anyio
async def test_production_redis_failure_fails_closed():
    class BrokenRedis:
        def pipeline(self, transaction=True):
            raise ConnectionError("Redis unavailable")

    settings = SimpleNamespace(environment="production", redis_url="redis://test", rate_limit_per_minute=60)
    decision = await RateLimiter(settings, redis_client=BrokenRedis()).check("127.0.0.1")

    assert decision.allowed is False
    assert decision.unavailable is True
