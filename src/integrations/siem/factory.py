"""Factory for application-configured SIEM integrations."""

from __future__ import annotations

from src.api.config import APISettings
from src.integrations.siem.base import SIEMIntegration
from src.integrations.siem.elastic import ElasticIntegration
from src.integrations.siem.splunk import SplunkIntegration
from src.integrations.siem.wazuh import WazuhIntegration


def create_siem_integration(
    settings: APISettings,
) -> SIEMIntegration | None:
    """Create the configured SIEM integration."""

    if not settings.siem_enabled:
        return None

    provider = settings.siem_provider

    if provider == "splunk":
        if not settings.siem_url:
            raise ValueError(
                "ECID_SIEM_URL is required for Splunk."
            )

        if not settings.siem_token:
            raise ValueError(
                "ECID_SIEM_TOKEN is required for Splunk."
            )

        return SplunkIntegration(
            url=settings.siem_url,
            token=settings.siem_token,
            index=settings.siem_index,
            source=settings.siem_source,
            timeout=settings.siem_timeout,
        )

    if provider == "elastic":
        if not settings.siem_url:
            raise ValueError(
                "ECID_SIEM_URL is required for Elastic."
            )

        return ElasticIntegration(
            url=settings.siem_url,
            index=settings.siem_index,
            api_key=(
                settings.siem_token
                if settings.siem_token
                else None
            ),
            username=(
                settings.siem_username
                if settings.siem_username
                else None
            ),
            password=(
                settings.siem_password
                if settings.siem_password
                else None
            ),
            timeout=settings.siem_timeout,
        )

    if provider == "wazuh":
        if not settings.siem_url:
            raise ValueError(
                "ECID_SIEM_URL is required for Wazuh."
            )

        if not settings.siem_username:
            raise ValueError(
                "ECID_SIEM_USERNAME is required for Wazuh."
            )

        if not settings.siem_password:
            raise ValueError(
                "ECID_SIEM_PASSWORD is required for Wazuh."
            )

        return WazuhIntegration(
            url=settings.siem_url,
            username=settings.siem_username,
            password=settings.siem_password,
            index=settings.siem_index,
            timeout=settings.siem_timeout,
        )

    raise ValueError(
        f"Unsupported SIEM provider: {provider}"
    )
