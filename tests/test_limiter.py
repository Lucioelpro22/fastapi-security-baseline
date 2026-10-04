from types import SimpleNamespace

import pytest

from app.limiter import RateLimiter, normalize_username


class FakeRedis:
    def __init__(self):
        self.counts = {}
        self.expirations = {}
        self.eval_calls = []

    async def eval(self, script, numkeys, key, seconds):
        self.eval_calls.append((script, numkeys, key, seconds))
        self.counts[key] = self.counts.get(key, 0) + 1
        if key not in self.expirations:
            self.expirations[key] = seconds
        return [self.counts[key], self.expirations[key]]


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
    assert len(limiter._redis.eval_calls) == 2
    assert limiter._redis.eval_calls[0][1] == 1


@pytest.mark.anyio
async def test_redis_limiter_repairs_missing_ttl_without_extending_existing_window():
    settings = SimpleNamespace(environment="production", redis_url="redis://test", rate_limit_per_minute=60)
    redis = FakeRedis()
    limiter = RateLimiter(settings, redis_client=redis)

    first = await limiter.check("127.0.0.1")
    redis_key = next(iter(redis.counts))
    redis.expirations[redis_key] = 42
    second = await limiter.check("127.0.0.1")

    assert first.retry_after == 60
    assert second.retry_after == 42
    assert redis.expirations[redis_key] == 42

    del redis.expirations[redis_key]
    third = await limiter.check("127.0.0.1")
    assert third.retry_after == 60
    assert redis.expirations[redis_key] == 60


@pytest.mark.anyio
async def test_production_redis_failure_fails_closed():
    class BrokenRedis:
        def pipeline(self, transaction=True):
            raise ConnectionError("Redis unavailable")

    settings = SimpleNamespace(environment="production", redis_url="redis://test", rate_limit_per_minute=60)
    decision = await RateLimiter(settings, redis_client=BrokenRedis()).check("127.0.0.1")

    assert decision.allowed is False
    assert decision.unavailable is True


@pytest.mark.anyio
async def test_combined_dimensions_prevent_ip_rotation_bypass():
    settings = SimpleNamespace(environment="test", redis_url=None, rate_limit_per_minute=1)
    limiter = RateLimiter(settings)

    first = await limiter.check_many(["ip:198.51.100.10", "username:user@example.com"])
    rotated_ip = await limiter.check_many(["ip:198.51.100.11", "username:user@example.com"])

    assert first.allowed is True
    assert rotated_ip.allowed is False


def test_username_normalization_is_stable_for_limiter_keys():
    assert normalize_username("  User@Example.COM ") == "user@example.com"
    assert normalize_username("Ｕｓｅｒ@Ｅｘａｍｐｌｅ.ＣＯＭ") == "user@example.com"
