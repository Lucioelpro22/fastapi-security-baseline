from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.repositories import UserRepository


def test_user_repository_persists_and_normalizes_username(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'users.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    with sessions() as session:
        repository = UserRepository(session)
        created = repository.create(
            user_id="u-1", username="User@Example.COM", password_hash="argon2-hash", role="user"
        )
        assert created.username == "user@example.com"

    with sessions() as session:
        found = UserRepository(session).get_by_username("USER@example.com")
        assert found is not None
        assert found.id == "u-1"
        assert found.role == "user"
