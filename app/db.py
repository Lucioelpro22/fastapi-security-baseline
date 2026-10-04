"""Database engine and session management.

The baseline uses synchronous SQLAlchemy so it works with SQLite in local
development and with PostgreSQL in production by changing DATABASE_URL.
"""

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


@lru_cache(maxsize=4)
def get_engine(database_url: str | None = None) -> Engine:
    """Return an engine for the configured database URL.

    ``database_url`` is injectable to make repository tests isolated without
    changing application configuration.
    """
    url = database_url or get_settings().database_url
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args, pool_pre_ping=True)


def get_session_factory(database_url: str | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(database_url), autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def init_db(database_url: str | None = None) -> None:
    # Import models before create_all so all mapped tables are registered.
    from . import models  # noqa: F401

    engine = get_engine(database_url)
    Base.metadata.create_all(bind=engine)
    # Keep the starter project upgrade-safe for users who created the SQLite
    # database with v0.2. A real deployment should use Alembic migrations.
    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns("users")}
    additions = {
        "mfa_secret_encrypted": "TEXT",
        "mfa_enabled": "BOOLEAN NOT NULL DEFAULT 0",
        "recovery_codes_hashes": "TEXT",
        "session_version": "INTEGER NOT NULL DEFAULT 0",
    }
    with engine.begin() as connection:
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(text(f"ALTER TABLE users ADD COLUMN {name} {definition}"))
