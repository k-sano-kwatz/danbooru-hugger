import sqlalchemy.exc
from fastapi import FastAPI
from pydantic import BaseModel
from starlette import status
from starlette.responses import JSONResponse

from api import tokens, users
from cryptography import cryptography
from database import models
from database.database import engine

models.Base.metadata.create_all(bind=engine)

app = FastAPI()
app.include_router(tokens.router)
app.include_router(users.router)


class HashRequest(BaseModel):
    plain_text: str


class HashResponse(BaseModel):
    hashed_text: str


@app.exception_handler(sqlalchemy.exc.IntegrityError)
async def integrity_error_exception_handler(_, __):
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={
            'detail': 'Conflicting request',
        },
    )


@app.get('/')
def read_root():
    return {
        'Hello': 'World',
    }


@app.put('/hash')
def hash_text(request: HashRequest):
    return HashResponse(hashed_text=cryptography.hash(request.plain_text))
