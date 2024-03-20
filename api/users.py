from datetime import datetime
from typing import Tuple

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from authentication import oauth2_active_access_token_user, oauth2_active_admin_access_token_user, \
    oauth2_path_verified_user_with_active_access_token_user
from database.database import get_db
from database.repository import user_repository

router = APIRouter(
    prefix='/users',
    tags=['users'],
    dependencies=[Depends(oauth2_active_access_token_user)],
)


class User(BaseModel):
    id: int
    username: str
    email: str
    is_admin: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime


@router.get('', dependencies=[Depends(oauth2_active_admin_access_token_user)], response_model=list[User])
async def get_users(db: Session = Depends(get_db)):
    return user_repository.find(db)


@router.get('/{user_id}', response_model=User)
async def get_user(user_with_access_token_user: Tuple[User, User] =
                   Depends(oauth2_path_verified_user_with_active_access_token_user)):
    user, access_token_user = user_with_access_token_user
    return user
