from typing import Optional, Type

from sqlalchemy.orm import Session

from database.models import User


def find(db: Session) -> list[Type[User]]:
    return db.query(User).all()


def find_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def find_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


def save(db: Session, user: User):
    db.add(user)


def delete(db: Session, user: User):
    db.delete(user)
