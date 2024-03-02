from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from config import settings

# Database connection parameters
connect_args = {}
# If database is SQLite
if settings.database.url.startswith('sqlite://'):
    # Allow database access from multiple threads
    connect_args = {
        'check_same_thread': False,
    }

engine = create_engine(
    settings.database.url,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
