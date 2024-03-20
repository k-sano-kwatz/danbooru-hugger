from datetime import datetime
from typing import Tuple

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from authentication import oauth2_active_access_token_user, oauth2_active_admin_access_token_user, \
    oauth2_path_verified_user_with_active_access_token_user
from cryptography import cryptography
from database.database import get_db
from database.models import User
from database.repository import user_repository

router = APIRouter(
    prefix='/users',
    tags=['users'],
    dependencies=[Depends(oauth2_active_access_token_user)],
)


class UserBase(BaseModel):
    username: str
    email: str
    is_admin: bool


class UserGet(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime


class UserPost(UserBase):
    password: str


@router.get('', dependencies=[Depends(oauth2_active_admin_access_token_user)], response_model=list[UserGet])
async def get_users(db: Session = Depends(get_db)):
    return user_repository.find(db)


@router.post('', dependencies=[Depends(oauth2_active_admin_access_token_user)], response_model=UserGet)
async def create_user(user: UserPost, db: Session = Depends(get_db)):
    # Generate user record
    db_user = User(
        username=user.username,
        hashed_password=cryptography.hash(user.password),
        email=user.email,
        is_admin=user.is_admin,
    )

    # Insert record
    user_repository.save(db, db_user)

    # Commit
    db.commit()

    return db_user


@router.get('/{user_id}', response_model=UserGet)
async def get_user(user_with_access_token_user: Tuple[User, User] =
                   Depends(oauth2_path_verified_user_with_active_access_token_user)):
    user, access_token_user = user_with_access_token_user
    return user
