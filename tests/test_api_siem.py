from src.api.config import APISettings
from src.api.app import _create_analysis_service
from src.integrations.siem.elastic import ElasticIntegration
from src.integrations.siem.service import SIEMService
from src.integrations.siem.splunk import SplunkIntegration
from src.integrations.siem.wazuh import WazuhIntegration


def test_create_analysis_service_without_siem(
    monkeypatch,
):
    """Test that SIEM is not configured when disabled."""

    monkeypatch.setattr(
        "src.api.app.settings",
        APISettings(
            siem_enabled=False,
        ),
    )

    service = _create_analysis_service()

    assert service.siem_service is None


def test_create_analysis_service_with_splunk(
    monkeypatch,
):
    """Test that Splunk configuration creates a SIEM service."""

    monkeypatch.setattr(
        "src.api.app.settings",
        APISettings(
            siem_enabled=True,
            siem_provider="splunk",
            siem_url="https://splunk.example.com:8088",
            siem_token="test-token",
        ),
    )

    service = _create_analysis_service()

    assert isinstance(
        service.siem_service,
        SIEMService,
    )

    integrations = (
        service.siem_service.manager.list_integrations()
    )

    assert integrations == ["splunk"]

    integration = (
        service.siem_service.manager.get("splunk")
    )

    assert isinstance(
        integration,
        SplunkIntegration,
    )


def test_create_analysis_service_with_elastic(
    monkeypatch,
):
    """Test that Elastic configuration creates a SIEM service."""

    monkeypatch.setattr(
        "src.api.app.settings",
        APISettings(
            siem_enabled=True,
            siem_provider="elastic",
            siem_url="https://elastic.example.com:9200",
            siem_token="test-api-key",
        ),
    )

    service = _create_analysis_service()

    assert isinstance(
        service.siem_service,
        SIEMService,
    )

    integrations = (
        service.siem_service.manager.list_integrations()
    )

    assert integrations == ["elastic"]

    integration = (
        service.siem_service.manager.get("elastic")
    )

    assert isinstance(
        integration,
        ElasticIntegration,
    )


def test_create_analysis_service_with_wazuh(
    monkeypatch,
):
    """Test that Wazuh configuration creates a SIEM service."""

    monkeypatch.setattr(
        "src.api.app.settings",
        APISettings(
            siem_enabled=True,
            siem_provider="wazuh",
            siem_url="https://wazuh.example.com:55000",
            siem_username="wazuh-user",
            siem_password="wazuh-password",
        ),
    )

    service = _create_analysis_service()

    assert isinstance(
        service.siem_service,
        SIEMService,
    )

    integrations = (
        service.siem_service.manager.list_integrations()
    )

    assert integrations == ["wazuh"]

    integration = (
        service.siem_service.manager.get("wazuh")
    )

    assert isinstance(
        integration,
        WazuhIntegration,
    )
