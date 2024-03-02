from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class Jwt(BaseModel):
    secret_key: str
    access_token_expire_minutes: int
    refresh_token_expire_minutes: int


class Logging(BaseModel):
    level: str


class Database(BaseModel):
    url: str


class Settings(BaseSettings):
    jwt: Jwt
    logging: Logging
    database: Database

    model_config = SettingsConfigDict(env_file='.env', env_nested_delimiter='.')


settings = Settings()
