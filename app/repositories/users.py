from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import User


class UserRepository:
    """Persistence operations for authentication users."""

    def __init__(self, session: Session):
        self.session = session

    def get_by_username(self, username: str) -> User | None:
        return self.session.scalar(select(User).where(User.username == username.lower()))

    def get_by_id(self, user_id: str) -> User | None:
        return self.session.get(User, user_id)

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
