"""SQLAlchemy database session management."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from src.database.config import settings


engine = create_engine(
    settings.url,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def get_db() -> Generator[Session, None, None]:
    """Provide a database session and close it after use."""

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
