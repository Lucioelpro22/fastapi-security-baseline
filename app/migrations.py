"""Minimal schema bootstrap used until Alembic migrations are introduced."""

from .db import init_db


def migrate() -> None:
    """Create missing tables without modifying existing data."""
    init_db()
