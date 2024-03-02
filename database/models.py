from sqlalchemy import Column, Integer, String, Boolean

from database.database import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    is_admin = Column(Boolean, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
