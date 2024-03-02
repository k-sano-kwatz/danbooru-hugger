from sqlalchemy import Column, Integer, String

from database.database import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    hashed_password = Column(String)
    email = Column(String, unique=True)
