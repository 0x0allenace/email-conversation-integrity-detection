"""API configuration for Email Conversation Integrity Detection."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class APISettings:
    """Store application-level API configuration."""

    title: str = field(
        default_factory=lambda: os.getenv(
            "ECID_API_TITLE",
            "Email Conversation Integrity Detection",
        )
    )

    description: str = field(
        default_factory=lambda: os.getenv(
            "ECID_API_DESCRIPTION",
            "API for detecting suspicious email conversation "
            "integrity anomalies.",
        )
    )

    version: str = field(
        default_factory=lambda: os.getenv(
            "ECID_API_VERSION",
            "0.1.0",
        )
    )

    host: str = field(
        default_factory=lambda: os.getenv(
            "ECID_API_HOST",
            "127.0.0.1",
        )
    )

    port: int = field(
        default_factory=lambda: int(
            os.getenv(
                "ECID_API_PORT",
                "8000",
            )
        )
    )


settings = APISettings()
