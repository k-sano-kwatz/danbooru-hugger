from datetime import datetime
from typing import Tuple

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status

from authentication import oauth2_active_access_token_user, oauth2_active_admin_access_token_user, \
    oauth2_path_verified_user_with_active_access_token_user, exception_forbidden
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


class UserPut(UserPost):
    is_active: bool


@router.get('', dependencies=[Depends(oauth2_active_admin_access_token_user)], response_model=list[UserGet])
async def get_users(db: Session = Depends(get_db)):
    return user_repository.find(db)


@router.post('', dependencies=[Depends(oauth2_active_admin_access_token_user)], response_model=UserGet,
             status_code=status.HTTP_201_CREATED)
async def create_user(user: UserPost, db: Session = Depends(get_db)):
    # Generate user data
    db_user = User(**user.dict(exclude={'password'}))
    db_user.hashed_password = cryptography.hash(user.password)

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


@router.put('/{user_id}', response_model=UserGet)
async def update_user(user: UserPut, user_with_access_token_user: Tuple[User, User] = Depends(
        oauth2_path_verified_user_with_active_access_token_user), db: Session = Depends(get_db)):
    db_user, access_token_user = user_with_access_token_user

    # Update user data
    db_user.username = user.username
    db_user.hashed_password = cryptography.hash(user.password)
    db_user.email = user.email
    # If non-admin user is trying to promote to admin user
    if not access_token_user.is_admin and user.is_admin:
        raise exception_forbidden
    db_user.is_admin = user.is_admin
    db_user.is_active = user.is_active

    # Update record
    user_repository.save(db, db_user)

    # Commit
    db.commit()

    return db_user
