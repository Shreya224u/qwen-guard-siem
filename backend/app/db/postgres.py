from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool

from app.config import settings


_is_sqlite = settings.DATABASE_URL.startswith("sqlite:")
_engine_options = {"pool_pre_ping": True}

if _is_sqlite:
    # SQLite connections can become stale when the local development database
    # is updated outside the API process. Open a fresh connection per session
    # and allow concurrent requests to wait briefly for SQLite file locks.
    _engine_options.update(
        poolclass=NullPool,
        connect_args={"check_same_thread": False, "timeout": 30},
    )

engine = create_engine(settings.DATABASE_URL, **_engine_options)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
