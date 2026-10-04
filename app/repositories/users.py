from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..mfa import consume_recovery_code
from ..models import User


class UserRepository:
    """Persistence operations for authentication users."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_username(self, username: str) -> User | None:
        return self.session.scalar(select(User).where(User.username == username.lower()))

    def get_by_id(self, user_id: str) -> User | None:
        return self.session.get(User, user_id)

    def consume_recovery_code(self, user_id: str, candidate: str) -> bool:
        """Consume one recovery code with a compare-and-swap database update.

        Recovery hashes are stored as one JSON value, so checking and removing a
        matching hash must be one conditional write.  The predicate on the
        previously-read value makes concurrent requests safe across processes
        and database sessions: exactly one update can affect the row.
        """
        user = self.get_by_id(user_id)
        if user is None:
            return False
        stored = user.recovery_codes_hashes
        matched, remaining = consume_recovery_code(stored, candidate)
        if not matched:
            return False

        result = self.session.execute(
            update(User)
            .where(User.id == user_id, User.recovery_codes_hashes == stored)
            .values(recovery_codes_hashes=remaining)
        )
        if result.rowcount != 1:
            self.session.rollback()
            return False
        self.session.commit()
        return True

    def create(
        self, *, user_id: str, username: str, password_hash: str, role: str = "user"
    ) -> User:
        user = User(
            id=user_id,
            username=username.lower(),
            password_hash=password_hash,
            role=role,
        )
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        return user
