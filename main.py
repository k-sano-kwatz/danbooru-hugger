from typing import Union, Annotated

from fastapi import FastAPI, Depends
from pydantic import BaseModel

from api import tokens, users
from authentication import oauth2_token, oauth2_active_access_token_user
from cryptography import cryptography
from database import models
from database.database import engine
from database.models import User
from logger import logger

models.Base.metadata.create_all(bind=engine)

app = FastAPI()
app.include_router(tokens.router)
app.include_router(users.router)


class Item(BaseModel):
    name: str
    price: float
    is_offer: Union[bool, None] = None


class HashRequest(BaseModel):
    plain_text: str


class HashResponse(BaseModel):
    hashed_text: str


@app.get('/')
def read_root():
    logger.debug('test')
    return {
        'Hello': 'World',
    }


@app.get('/users/me')
def read_users_me(user: Annotated[User, Depends(oauth2_active_access_token_user)]):
    return user


@app.get('/items/')
def read_items(token: Annotated[str, Depends(oauth2_token)]):
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


@app.put('/hash')
def hash_text(request: HashRequest):
    return HashResponse(hashed_text=cryptography.hash(request.plain_text))
