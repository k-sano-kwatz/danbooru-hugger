from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError, ExpiredSignatureError
from jose.exceptions import JWTClaimsError
from paprika import data
from sqlalchemy.orm import Session
from starlette import status

from config import settings
from database.database import get_db
from database.models import User
from database.repository import user_repository
from logger import logger

ALGORITHM = 'HS256'

oauth2_token = OAuth2PasswordBearer(tokenUrl='token')

exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail='Could not validate credentials',
    headers={
        'WWW-Authenticate': 'Bearer',
    },
)


@data
class Claims:
    typ: str
    sub: str
    iat: int
    exp: int


@data
class RefreshToken:
    sub: str


async def oauth2_claims(token: Annotated[str, Depends(oauth2_token)]) -> Claims:
    try:
        # Decode JWT token
        claims = jwt.decode(token, settings.jwt.secret_key, algorithms=[ALGORITHM])
        claims = Claims(**claims)
        logger.debug(f'claims: {claims}')

    except ExpiredSignatureError:
        logger.debug(f'Token {token} is expired.')
        raise exception

    except JWTClaimsError:
        logger.debug(f'Token {token} has invalid claims.')
        raise exception

    except JWTError:
        logger.debug(f'Token {token} is invalid.')
        raise exception

    return claims


async def oauth2_refresh_token(claims: Annotated[Claims, Depends(oauth2_claims)]) -> RefreshToken:
    # If the type of claims is not refresh token
    if claims.typ != 'refresh_token':
        logger.debug(f'Claims {claims} is not refresh token.')
        raise exception

    return RefreshToken(claims.sub)


async def oauth2_refresh_token_user(refresh_token: Annotated[RefreshToken, Depends(oauth2_refresh_token)],
                                    db: Session = Depends(get_db)) -> User:
    # Get user from database
    user = user_repository.find_by_id(db, int(refresh_token.sub))

    # If user does not exist
    if not user:
        logger.debug(f'No user with id {refresh_token.sub} was found.')
        raise exception

    return user


async def oauth2_active_refresh_token_user(user: Annotated[User, Depends(oauth2_refresh_token_user)]) -> User:
    # If user is not active
    if not user.is_active:
        logger.debug(f'User {user.username} is not active.')
        raise exception

    return user
