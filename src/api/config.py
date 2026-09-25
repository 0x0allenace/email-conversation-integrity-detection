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

    siem_enabled: bool = field(
        default_factory=lambda: os.getenv(
            "ECID_SIEM_ENABLED",
            "false",
        ).lower()
        in {"1", "true", "yes", "on"}
    )

    siem_provider: str = field(
        default_factory=lambda: os.getenv(
            "ECID_SIEM_PROVIDER",
            "",
        ).strip().lower()
    )

    siem_url: str = field(
        default_factory=lambda: os.getenv(
            "ECID_SIEM_URL",
            "",
        ).strip()
    )

    siem_token: str = field(
        default_factory=lambda: os.getenv(
            "ECID_SIEM_TOKEN",
            "",
        )
    )

    siem_username: str = field(
        default_factory=lambda: os.getenv(
            "ECID_SIEM_USERNAME",
            "",
        )
    )

    siem_password: str = field(
        default_factory=lambda: os.getenv(
            "ECID_SIEM_PASSWORD",
            "",
        )
    )

    siem_index: str = field(
        default_factory=lambda: os.getenv(
            "ECID_SIEM_INDEX",
            "ecid-events",
        )
    )

    siem_source: str = field(
        default_factory=lambda: os.getenv(
            "ECID_SIEM_SOURCE",
            "email-conversation-integrity-detection",
        )
    )

    siem_timeout: float = field(
        default_factory=lambda: float(
            os.getenv(
                "ECID_SIEM_TIMEOUT",
                "10.0",
            )
        )
    )


settings = APISettings()
