"""Database configuration for Email Conversation Integrity Detection."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DatabaseSettings:
    """Store PostgreSQL database configuration."""

    host: str = field(
        default_factory=lambda: os.getenv(
            "ECID_DB_HOST",
            "127.0.0.1",
        )
    )

    port: int = field(
        default_factory=lambda: int(
            os.getenv(
                "ECID_DB_PORT",
                "5432",
            )
        )
    )

    database: str = field(
        default_factory=lambda: os.getenv(
            "ECID_DB_NAME",
            "email_integrity",
        )
    )

    username: str = field(
        default_factory=lambda: os.getenv(
            "ECID_DB_USER",
            "postgres",
        )
    )

    password: str = field(
        default_factory=lambda: os.getenv(
            "ECID_DB_PASSWORD",
            "",
        )
    )

    @property
    def url(self) -> str:
        """Return the PostgreSQL connection URL."""

        return (
            "postgresql://"
            f"{self.username}:"
            f"{self.password}@"
            f"{self.host}:"
            f"{self.port}/"
            f"{self.database}"
        )


settings = DatabaseSettings()
