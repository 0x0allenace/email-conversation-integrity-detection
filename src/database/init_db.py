"""Database initialization for Email Conversation Integrity Detection."""

from __future__ import annotations

from src.database.models import Base
from src.database.session import engine


def init_db() -> None:
    """Create all database tables defined by the SQLAlchemy models."""

    Base.metadata.create_all(
        bind=engine,
    )


if __name__ == "__main__":
    init_db()
