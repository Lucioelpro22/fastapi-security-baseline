"""Request correlation and dependency health helpers."""
from __future__ import annotations

import re
import secrets
from collections.abc import Mapping
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import text

from .config import Settings
from .db import get_session_factory
from .redis import close_redis, create_redis_client, ping_redis

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._~-]{1,64}$")


def request_id(value: str | None) -> str:
    """Return a safe correlation id, accepting only bounded header values."""
    if value and _REQUEST_ID_RE.fullmatch(value):
        return value
    return secrets.token_urlsafe(16)


def redacted_log_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Allow-list fields used by request logs; bodies, query strings and secrets never enter logs."""
    allowed = {"method", "path", "status_code", "request_id", "duration_ms"}
    return {key: fields[key] for key in allowed if key in fields}


def database_ready(settings: Settings) -> bool:
    """Run a cheap database probe without returning backend details to callers."""
    try:
        with get_session_factory(settings.database_url)() as session:
            session.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def redis_ready(settings: Settings, client: Redis | None = None) -> tuple[bool, bool]:
    """Return ``(healthy, owned)`` for configured Redis, keeping errors private.

    ``owned`` tells the caller that the temporary client should be closed.
    Unconfigured Redis is intentionally treated as healthy outside production;
    production configuration validation requires a URL.
    """
    if not settings.redis_url:
        return (settings.environment != "production", False)
    owned = client is None
    probe = client or create_redis_client(settings.redis_url)
    try:
        return (await ping_redis(probe), owned)
    except Exception:
        return (False, owned)
    finally:
        if owned:
            await close_redis(probe)
