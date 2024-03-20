from typing import Annotated, Tuple

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

exception_unauthorized = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail='Could not validate credentials',
    headers={
        'WWW-Authenticate': 'Bearer',
    },
)

exception_forbidden = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail='Access is forbidden',
)

exception_not_found = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail='Not found',
)


@data
class Claims:
    typ: str
    sub: str
    iat: int
    exp: int


@data
class AccessToken:
    sub: str


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
        raise exception_unauthorized

    except JWTClaimsError:
        logger.debug(f'Token {token} has invalid claims.')
        raise exception_unauthorized

    except JWTError:
        logger.debug(f'Token {token} is invalid.')
        raise exception_unauthorized

    return claims


async def oauth2_access_token(claims: Annotated[Claims, Depends(oauth2_claims)]) -> AccessToken:
    # If the type of claims is not access token
    if claims.typ != 'access_token':
        logger.debug(f'Claims {claims} is not access token.')
        raise exception_forbidden

    return AccessToken(claims.sub)


async def oauth2_refresh_token(claims: Annotated[Claims, Depends(oauth2_claims)]) -> RefreshToken:
    # If the type of claims is not refresh token
    if claims.typ != 'refresh_token':
        logger.debug(f'Claims {claims} is not refresh token.')
        raise exception_forbidden

    return RefreshToken(claims.sub)


async def oauth2_access_token_user(access_token: Annotated[AccessToken, Depends(oauth2_access_token)],
                                   db: Session = Depends(get_db)) -> User:
    # Get user from database
    user = user_repository.find_by_id(db, int(access_token.sub))

    # If user does not exist
    if not user:
        logger.debug(f'No user with id {access_token.sub} was found.')
        raise exception_unauthorized

    return user


async def oauth2_refresh_token_user(refresh_token: Annotated[RefreshToken, Depends(oauth2_refresh_token)],
                                    db: Session = Depends(get_db)) -> User:
    # Get user from database
    user = user_repository.find_by_id(db, int(refresh_token.sub))

    # If user does not exist
    if not user:
        logger.debug(f'No user with id {refresh_token.sub} was found.')
        raise exception_unauthorized

    return user


async def oauth2_active_access_token_user(user: Annotated[User, Depends(oauth2_access_token_user)]) -> User:
    # If user is not active
    if not user.is_active:
        logger.debug(f'User {user.username} is not active.')
        raise exception_unauthorized

    return user


async def oauth2_active_refresh_token_user(user: Annotated[User, Depends(oauth2_refresh_token_user)]) -> User:
    # If user is not active
    if not user.is_active:
        logger.debug(f'User {user.username} is not active.')
        raise exception_unauthorized

    return user


async def oauth2_active_admin_access_token_user(user: Annotated[User, Depends(oauth2_active_access_token_user)])\
        -> User:
    # If user is not admin
    if not user.is_admin:
        logger.debug(f'User {user.username} is not admin.')
        raise exception_forbidden

    return user


async def oauth2_path_verified_user_id_with_active_access_token_user(
        user: Annotated[User, Depends(oauth2_active_access_token_user)], user_id: int) -> Tuple[int, User]:
    # If non-admin user is trying to access other user
    if not user.is_admin and user.id != user_id:
        logger.debug(f'Non-admin user {user.username} is forbidden from accessing other user with id {user_id}.')
        raise exception_forbidden

    return user_id, user


async def oauth2_path_verified_user_with_active_access_token_user(
        user_id_with_user: Annotated[Tuple[int, User], Depends(
            oauth2_path_verified_user_id_with_active_access_token_user)], db: Session = Depends(get_db))\
        -> Tuple[User, User]:
    user_id, access_token_user = user_id_with_user

    # Get user from database
    user = user_repository.find_by_id(db, user_id)

    # If user does not exist
    if not user:
        logger.debug(f'No user with id {user_id} was found.')
        raise exception_not_found

    return user, access_token_user
