from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status

from config import settings
from cryptography import cryptography
from database.database import get_db
from database.repository import user_repository
from logger import logger

ALGORITHM = 'HS256'

router = APIRouter(tags=['tokens'])


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


@router.post('/token')
async def get_access_token(form: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db))\
        -> TokenResponse:
    logger.debug(f'request: username=\'{form.username}\' password=\'{form.password}\'')

    exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Incorrect username or password',
        headers={
            'WWW-Authenticate': 'Bearer',
        },
    )

    # Get user from database
    user = user_repository.find_by_username(db, form.username)

    # If user does not exist
    if not user:
        logger.debug(f'No user with username {form.username} was found.')
        raise exception

    # If password does not match
    if not cryptography.verify(form.password, user.hashed_password):
        logger.debug(f'User {user.username} does not have given password {form.password}.')
        raise exception

    # Generate claims
    claims = {
        'sub': user.id,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=settings.jwt.access_token_expire_minutes),
    }
    logger.debug(f'claims: {claims}')

    # Generate access token
    access_token = jwt.encode(claims, settings.jwt.secret_key, algorithm=ALGORITHM)

    # Generate response
    response = TokenResponse(access_token=access_token, token_type='bearer')
    logger.debug(f'response: {response}')

    return response
