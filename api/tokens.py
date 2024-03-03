from datetime import datetime, timezone, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from paprika import data
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


@data
class Claims:
    typ: str
    sub: str
    iat: int
    exp: int


class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str


def generate_token(typ: str, sub: int, exp_delta: int):
    # Generate iat and exp
    now = datetime.now(timezone.utc)
    iat = int(now.timestamp())
    exp = int((now + timedelta(minutes=exp_delta)).timestamp())

    # Generate claims
    claims = Claims(typ, str(sub), iat, exp)
    logger.debug(f'claims: {claims}')

    # Generate access token
    access_token = jwt.encode(jsonable_encoder(claims), settings.jwt.secret_key, algorithm=ALGORITHM)

    return access_token


def authenticate(username: str, password: str, db: Session) -> TokenResponse:
    logger.debug(f'request: username=\'{username}\' password=\'{password}\'')

    exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Incorrect username or password',
        headers={
            'WWW-Authenticate': 'Bearer',
        },
    )

    # Get user from database
    user = user_repository.find_by_username(db, username)

    # If user does not exist
    if not user:
        logger.debug(f'No user with username {username} was found.')
        raise exception

    # If user is not active
    if not user.is_active:
        logger.debug(f'User {user.username} is not active.')
        raise exception

    # If password does not match
    if not cryptography.verify(password, user.hashed_password):
        logger.debug(f'User {user.username} does not have given password {password}.')
        raise exception

    # Generate access token and refresh token
    access_token = generate_token('access_token', user.id, settings.jwt.access_token_expire_minutes)
    refresh_token = generate_token('refresh_token', user.id, settings.jwt.refresh_token_expire_minutes)

    # Generate response
    response = TokenResponse(access_token=access_token, token_type='bearer', refresh_token=refresh_token)
    logger.debug(f'response: {response}')

    return response


@router.post('/token')
async def get_access_token(form: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db))\
        -> TokenResponse:
    return authenticate(form.username, form.password, db)


@router.post('/token2')
async def get_access_token(request: TokenRequest, db: Session = Depends(get_db)) -> TokenResponse:
    return authenticate(request.username, request.password, db)
