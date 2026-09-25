import pytest

from src.api.config import APISettings
from src.integrations.siem.elastic import ElasticIntegration
from src.integrations.siem.factory import (
    create_siem_integration,
)
from src.integrations.siem.splunk import SplunkIntegration
from src.integrations.siem.wazuh import WazuhIntegration


def test_factory_returns_none_when_siem_is_disabled():
    """Test that disabled SIEM configuration returns no integration."""

    settings = APISettings(
        siem_enabled=False,
    )

    integration = create_siem_integration(
        settings,
    )

    assert integration is None


def test_factory_creates_splunk_integration():
    """Test that the factory creates a Splunk integration."""

    settings = APISettings(
        siem_enabled=True,
        siem_provider="splunk",
        siem_url="https://splunk.example.com:8088",
        siem_token="test-token",
        siem_index="security-events",
        siem_source="ecid-test",
        siem_timeout=15.0,
    )

    integration = create_siem_integration(
        settings,
    )

    assert isinstance(
        integration,
        SplunkIntegration,
    )

    assert integration.url == (
        "https://splunk.example.com:8088"
    )
    assert integration.token == "test-token"
    assert integration.index == "security-events"
    assert integration.source == "ecid-test"
    assert integration.timeout == 15.0


def test_factory_creates_elastic_with_api_key():
    """Test that the factory creates Elastic with API key auth."""

    settings = APISettings(
        siem_enabled=True,
        siem_provider="elastic",
        siem_url="https://elastic.example.com:9200",
        siem_token="elastic-api-key",
        siem_index="security-events",
        siem_timeout=20.0,
    )

    integration = create_siem_integration(
        settings,
    )

    assert isinstance(
        integration,
        ElasticIntegration,
    )

    assert integration.url == (
        "https://elastic.example.com:9200"
    )
    assert integration.index == "security-events"
    assert integration.api_key == "elastic-api-key"
    assert integration.timeout == 20.0


def test_factory_creates_elastic_with_basic_auth():
    """Test that the factory creates Elastic with basic auth."""

    settings = APISettings(
        siem_enabled=True,
        siem_provider="elastic",
        siem_url="https://elastic.example.com:9200",
        siem_username="elastic-user",
        siem_password="elastic-password",
    )

    integration = create_siem_integration(
        settings,
    )

    assert isinstance(
        integration,
        ElasticIntegration,
    )

    assert integration.username == "elastic-user"
    assert integration.password == "elastic-password"


def test_factory_creates_wazuh_integration():
    """Test that the factory creates a Wazuh integration."""

    settings = APISettings(
        siem_enabled=True,
        siem_provider="wazuh",
        siem_url="https://wazuh.example.com:55000",
        siem_username="wazuh-user",
        siem_password="wazuh-password",
        siem_index="security-events",
        siem_timeout=12.0,
    )

    integration = create_siem_integration(
        settings,
    )

    assert isinstance(
        integration,
        WazuhIntegration,
    )

    assert integration.url == (
        "https://wazuh.example.com:55000"
    )
    assert integration.username == "wazuh-user"
    assert integration.password == "wazuh-password"
    assert integration.index == "security-events"
    assert integration.timeout == 12.0


@pytest.mark.parametrize(
    "provider",
    [
        "unknown",
        "qradar",
        "",
    ],
)
def test_factory_rejects_unsupported_provider(
    provider,
):
    """Test that unsupported SIEM providers are rejected."""

    settings = APISettings(
        siem_enabled=True,
        siem_provider=provider,
    )

    with pytest.raises(
        ValueError,
        match=f"Unsupported SIEM provider: {provider}",
    ):
        create_siem_integration(
            settings,
        )


def test_factory_requires_splunk_url():
    """Test that Splunk requires a URL."""

    settings = APISettings(
        siem_enabled=True,
        siem_provider="splunk",
        siem_token="test-token",
    )

    with pytest.raises(
        ValueError,
        match="ECID_SIEM_URL is required for Splunk",
    ):
        create_siem_integration(
            settings,
        )


def test_factory_requires_splunk_token():
    """Test that Splunk requires a token."""

    settings = APISettings(
        siem_enabled=True,
        siem_provider="splunk",
        siem_url="https://splunk.example.com:8088",
    )

    with pytest.raises(
        ValueError,
        match="ECID_SIEM_TOKEN is required for Splunk",
    ):
        create_siem_integration(
            settings,
        )


def test_factory_requires_wazuh_credentials():
    """Test that Wazuh requires username and password."""

    settings = APISettings(
        siem_enabled=True,
        siem_provider="wazuh",
        siem_url="https://wazuh.example.com:55000",
    )

    with pytest.raises(
        ValueError,
        match="ECID_SIEM_USERNAME is required for Wazuh",
    ):
        create_siem_integration(
            settings,
        )
