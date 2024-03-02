from datetime import timedelta, datetime, timezone
from typing import Union, Annotated

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from starlette import status


SECRET_KEY = '<32 byte hex string>'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    'johndoe': {
        'username': 'johndoe',
        'full_name': 'John Doe',
        'email': 'johndoe@example.com',
        'hashed_password': '$2b$12$cAd/MEsR7jIdzGpZX1pKROMxJbY/eh27KN8/yd8fZXI1Wm7HHw.sy',
        'disabled': False,
    },
    'alice': {
        'username': 'alice',
        'full_name': 'Alice Wonderson',
        'email': 'alice@example.com',
        'hashed_password': '$2b$12$0w4b0288WJkxHhLFwjN2PeQKH2DgaREi.LQia/21xYsPCXL97JP9y',
        'disabled': True,
    },
}

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


class Item(BaseModel):
    name: str
    price: float
    is_offer: Union[bool, None] = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)

    if not user:
        return False

    if not verify_password(password, user.hashed_password):
        return False

    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({
        'exp': expire,
    })

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Could not validate credentials',
        headers={
            'WWW-Authenticate': 'Bearer',
        },
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception

    user = get_user(fake_users_db, username=token_data.username)
    if not user:
        raise credentials_exception

    return user


async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail='Inactive user')

    return current_user


@app.get('/')
def read_root():
    return {
        'Hello': 'World',
    }


@app.post('/token')
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={
                'WWW-Authenticate': 'Bearer',
            },
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            'sub': user.username,
        },
        expires_delta=access_token_expires,
    )

    return Token(access_token=access_token, token_type='bearer')


@app.get('/users/me')
def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user


@app.get('/items/')
def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
    return {
        'token': token,
    }


@app.get('/items/{item_id}')
def read_item(item_id: int, q: Union[str, None] = None):
    return {
        'item_id': item_id,
        'q': q,
    }


@app.put('/items/{item_id}')
def update_item(item_id: int, item: Item):
    return {
        'item_name': item.name,
        'item_id': item_id,
    }
