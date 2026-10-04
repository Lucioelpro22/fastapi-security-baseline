from concurrent.futures import ThreadPoolExecutor

from app.db import get_session_factory, init_db
from app.mfa import generate_recovery_codes, hash_recovery_codes
from app.models import User
from app.repositories import UserRepository
from app.security import hash_password


def test_recovery_code_can_only_be_consumed_once_concurrently(tmp_path):
    """Concurrent sessions must not both spend the same recovery code."""
    database_url = f"sqlite:///{tmp_path / 'concurrent-mfa.db'}"
    init_db(database_url)
    recovery_code = generate_recovery_codes(1)[0]
    with get_session_factory(database_url)() as session:
        session.add(
            User(
                id="concurrent-admin",
                username="concurrent-admin@example.com",
                password_hash=hash_password("unused-password"),
                role="admin",
                mfa_enabled=True,
                recovery_codes_hashes=hash_recovery_codes([recovery_code]),
            )
        )
        session.commit()

    def spend_code(_attempt: int) -> bool:
        with get_session_factory(database_url)() as session:
            return UserRepository(session).consume_recovery_code("concurrent-admin", recovery_code)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(spend_code, range(8)))

    assert sum(results) == 1
    with get_session_factory(database_url)() as session:
        assert session.get(User, "concurrent-admin").recovery_codes_hashes == "[]"
