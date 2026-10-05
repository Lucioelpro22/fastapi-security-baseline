"""Refresh state regressions, including shared-worker tests against real Redis."""
import asyncio
import os
import time
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from app.config import Settings
from app.refresh import RefreshStoreUnavailable, RefreshTokenReuse, RefreshTokenStore


def settings():
    return Settings(environment="test", jwt_secret="test-secret-that-is-long-enough-123456")


def test_memory_replay_revokes_descendants_without_extending_session(monkeypatch):
    async def exercise():
        store = RefreshTokenStore(settings())
        first, original = await store.issue("user", "user", session_version=7)
        monkeypatch.setattr("app.refresh.time.time", lambda: original.expires_at - 2)
        second, grant = await store.rotate(first)
        assert grant.expires_at == original.expires_at
        assert grant.session_version == 7
        with pytest.raises(RefreshTokenReuse):
            await store.rotate(first)
        with pytest.raises(RefreshTokenReuse):
            await store.rotate(second)
        with pytest.raises(RefreshTokenReuse):
            await store.issue("user", "user", family=original.family)
    asyncio.run(exercise())


def redis_url():
    url = os.environ.get("TEST_REDIS_URL")
    if not url:
        pytest.skip("Set TEST_REDIS_URL to run real Redis integration tests")
    return url


async def workers(url):
    # An independent namespace keeps parallel runs away from real session keys;
    # the database must be dedicated to tests. Never flush a shared database.
    prefix = f"test-refresh:{uuid4()}:"

    class IsolatedStore(RefreshTokenStore):
        def _key(self, digest):
            return prefix + "token:" + digest

        def _family_key(self, family):
            return prefix + "family:" + family

    clients = [Redis.from_url(url, decode_responses=True) for _ in range(2)]
    await clients[0].ping()  # Configured but unavailable Redis must fail the suite.
    stores = [IsolatedStore(settings(), client) for client in clients]
    return stores, clients, prefix


async def cleanup(clients, prefix):
    keys = [key async for key in clients[0].scan_iter(match=prefix + "*")]
    if keys:
        await clients[0].delete(*keys)
    for client in clients:
        await client.aclose()


def test_redis_replay_revokes_descendants_across_workers_and_restart():
    url = redis_url()

    async def exercise():
        stores, clients, prefix = await workers(url)
        first_worker, other_worker = stores
        try:
            first, original = await first_worker.issue("user", "admin", session_version=9)
            second, grant = await other_worker.rotate(first)
            third, _ = await first_worker.rotate(second)
            assert grant == original
            assert await clients[0].hget(first_worker._key(first_worker._digest(first)), "used") == "1"
            assert await clients[0].expiretime(first_worker._key(first_worker._digest(third))) == original.expires_at
            with pytest.raises(RefreshTokenReuse):
                await other_worker.rotate(first)
            with pytest.raises(RefreshTokenReuse):
                await first_worker.rotate(third)
            # Constructing a new store does not lose the consumed-token family.
            restarted = type(other_worker)(settings(), clients[1])
            with pytest.raises(RefreshTokenReuse):
                await restarted.rotate(second)
            with pytest.raises(RefreshTokenReuse):
                await restarted.issue("user", "admin", family=original.family)
        finally:
            await cleanup(clients, prefix)
    asyncio.run(exercise())


def test_redis_concurrent_rotation_has_one_winner_and_revokes_its_successor():
    url = redis_url()

    async def exercise():
        stores, clients, prefix = await workers(url)
        try:
            first, _ = await stores[0].issue("user", "user")
            results = await asyncio.gather(
                *(stores[i % 2].rotate(first) for i in range(8)), return_exceptions=True,
            )
            successes = [result for result in results if isinstance(result, tuple)]
            assert len(successes) == 1
            assert sum(isinstance(result, RefreshTokenReuse) for result in results) == 7
            with pytest.raises(RefreshTokenReuse):
                await stores[1].rotate(successes[0][0])
        finally:
            await cleanup(clients, prefix)
    asyncio.run(exercise())


def test_redis_descendant_rotation_racing_replay_cannot_survive_revocation():
    url = redis_url()

    async def exercise():
        stores, clients, prefix = await workers(url)
        try:
            for _ in range(12):
                first, _ = await stores[0].issue("user", "user")
                second, _ = await stores[0].rotate(first)
                replay, rotation = await asyncio.gather(
                    stores[0].rotate(first), stores[1].rotate(second), return_exceptions=True,
                )
                assert isinstance(replay, RefreshTokenReuse)
                if isinstance(rotation, tuple):
                    with pytest.raises(RefreshTokenReuse):
                        await stores[0].rotate(rotation[0])
                else:
                    assert isinstance(rotation, RefreshTokenReuse)
        finally:
            await cleanup(clients, prefix)
    asyncio.run(exercise())


def test_redis_expiry_bounds_tombstones_and_rotations():
    url = redis_url()

    async def exercise():
        stores, clients, prefix = await workers(url)
        try:
            expiry = int(time.time()) + 60
            first, grant = await stores[0].issue("user", "user", expires_at=expiry)
            second, rotated = await stores[1].rotate(first)
            assert rotated.expires_at == grant.expires_at == expiry
            for raw in (first, second):
                key = stores[0]._key(stores[0]._digest(raw))
                assert await clients[0].expiretime(key) == expiry
            with pytest.raises(RefreshTokenReuse):
                await stores[0].rotate(first)
            assert await clients[0].expiretime(stores[0]._family_key(grant.family)) == expiry
            with pytest.raises(RefreshTokenReuse):
                await stores[0].issue("user", "user", expires_at=int(time.time()) - 1)
        finally:
            await cleanup(clients, prefix)
    asyncio.run(exercise())


def test_production_store_failure_does_not_issue_an_untracked_token():
    class UnavailableRedis:
        async def eval(self, *args):
            raise ConnectionError("synthetic backend failure")

    async def exercise():
        config = settings().model_copy(update={"environment": "production"})
        store = RefreshTokenStore(config, UnavailableRedis())
        with pytest.raises(RefreshStoreUnavailable):
            await store.issue("user", "user")
        with pytest.raises(RefreshStoreUnavailable):
            await store.rotate("synthetic-value")
        assert not store._memory
    asyncio.run(exercise())


def test_redis_family_expiry_is_authoritative_and_replay_keeps_longer_revocation():
    url = redis_url()

    async def exercise():
        stores, clients, prefix = await workers(url)
        try:
            expiry = int(time.time()) + 60
            first, original = await stores[0].issue("user", "user", expires_at=expiry)
            sibling, grant = await stores[1].issue(
                "user", "user", family=original.family, expires_at=expiry + 600,
            )
            assert grant.expires_at == expiry
            await stores[0].rotate(first)
            await stores[1].revoke_family(original.family, ttl=180)
            with pytest.raises(RefreshTokenReuse):
                await stores[0].rotate(first)
            assert await clients[0].ttl(stores[0]._family_key(original.family)) >= 170
            with pytest.raises(RefreshTokenReuse):
                await stores[1].rotate(sibling)
        finally:
            await cleanup(clients, prefix)
    asyncio.run(exercise())
