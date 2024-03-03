from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError, ExpiredSignatureError
from jose.exceptions import JWTClaimsError
from starlette import status

from api.tokens import ALGORITHM, Claims
from config import settings
from logger import logger

oauth2_token = OAuth2PasswordBearer(tokenUrl='token')


async def oauth2_claims(token: Annotated[str, Depends(oauth2_token)]) -> Claims:
    exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={
            'WWW-Authenticate': 'Bearer',
        },
    )

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
