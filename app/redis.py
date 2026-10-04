"""Redis client lifecycle helpers.

The client is intentionally created lazily so development and test environments can
run without a Redis server. Production configuration requires ``REDIS_URL`` and
uses this module as the single place where the connection is managed.
"""
from __future__ import annotations

from typing import Any

from redis.asyncio import Redis


def create_redis_client(redis_url: str) -> Redis:
    """Create an async Redis client from a configured URL."""
    return Redis.from_url(redis_url, decode_responses=True)


async def ping_redis(client: Redis) -> bool:
    """Return whether Redis is reachable, without hiding connection errors."""
    return bool(await client.ping())


async def close_redis(client: Any) -> None:
    """Close a Redis client across redis-py versions."""
    close = getattr(client, "aclose", None) or getattr(client, "close", None)
    if close is not None:
        result = close()
        if hasattr(result, "__await__"):
            await result
