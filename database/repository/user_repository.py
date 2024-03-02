from typing import Optional

from sqlalchemy.orm import Session

from database.models import User


def find_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()
