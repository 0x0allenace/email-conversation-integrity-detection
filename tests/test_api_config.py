import pytest

from src.api.config import APISettings


def test_api_settings_contain_expected_metadata():
    """Test that API settings contain the expected metadata."""

    settings = APISettings()

    assert settings.title == (
        "Email Conversation Integrity Detection"
    )

    assert settings.description == (
        "API for detecting suspicious email conversation "
        "integrity anomalies."
    )

    assert settings.version == "0.1.0"


def test_api_settings_support_environment_overrides(
    monkeypatch,
):
    """Test that API settings support environment overrides."""

    monkeypatch.setenv(
        "ECID_API_TITLE",
        "Test API",
    )

    monkeypatch.setenv(
        "ECID_API_DESCRIPTION",
        "Test description",
    )

    monkeypatch.setenv(
        "ECID_API_VERSION",
        "9.9.9",
    )

    monkeypatch.setenv(
        "ECID_API_HOST",
        "0.0.0.0",
    )

    monkeypatch.setenv(
        "ECID_API_PORT",
        "9000",
    )

    settings = APISettings()

    assert settings.title == "Test API"
    assert settings.description == "Test description"
    assert settings.version == "9.9.9"
    assert settings.host == "0.0.0.0"
    assert settings.port == 9000


def test_siem_settings_are_disabled_by_default(
    monkeypatch,
):
    """Test that SIEM integration is disabled by default."""

    for variable in (
        "ECID_SIEM_ENABLED",
        "ECID_SIEM_PROVIDER",
        "ECID_SIEM_URL",
        "ECID_SIEM_TOKEN",
        "ECID_SIEM_USERNAME",
        "ECID_SIEM_PASSWORD",
        "ECID_SIEM_INDEX",
        "ECID_SIEM_SOURCE",
        "ECID_SIEM_TIMEOUT",
    ):
        monkeypatch.delenv(
            variable,
            raising=False,
        )

    settings = APISettings()

    assert settings.siem_enabled is False
    assert settings.siem_provider == ""
    assert settings.siem_url == ""
    assert settings.siem_token == ""
    assert settings.siem_username == ""
    assert settings.siem_password == ""
    assert settings.siem_index == "ecid-events"
    assert (
        settings.siem_source
        == "email-conversation-integrity-detection"
    )
    assert settings.siem_timeout == 10.0


def test_siem_settings_support_environment_overrides(
    monkeypatch,
):
    """Test that SIEM settings support environment overrides."""

    monkeypatch.setenv(
        "ECID_SIEM_ENABLED",
        "true",
    )

    monkeypatch.setenv(
        "ECID_SIEM_PROVIDER",
        "Splunk",
    )

    monkeypatch.setenv(
        "ECID_SIEM_URL",
        "https://splunk.example.com:8088",
    )

    monkeypatch.setenv(
        "ECID_SIEM_TOKEN",
        "test-token",
    )

    monkeypatch.setenv(
        "ECID_SIEM_USERNAME",
        "test-user",
    )

    monkeypatch.setenv(
        "ECID_SIEM_PASSWORD",
        "test-password",
    )

    monkeypatch.setenv(
        "ECID_SIEM_INDEX",
        "security-events",
    )

    monkeypatch.setenv(
        "ECID_SIEM_SOURCE",
        "ecid-test",
    )

    monkeypatch.setenv(
        "ECID_SIEM_TIMEOUT",
        "15.5",
    )

    settings = APISettings()

    assert settings.siem_enabled is True
    assert settings.siem_provider == "splunk"
    assert (
        settings.siem_url
        == "https://splunk.example.com:8088"
    )
    assert settings.siem_token == "test-token"
    assert settings.siem_username == "test-user"
    assert settings.siem_password == "test-password"
    assert settings.siem_index == "security-events"
    assert settings.siem_source == "ecid-test"
    assert settings.siem_timeout == 15.5


@pytest.mark.parametrize(
    "value",
    [
        "1",
        "true",
        "TRUE",
        "yes",
        "YES",
        "on",
        "ON",
    ],
)
def test_siem_enabled_accepts_common_truthy_values(
    monkeypatch,
    value,
):
    """Test that common truthy environment values enable SIEM."""

    monkeypatch.setenv(
        "ECID_SIEM_ENABLED",
        value,
    )

    settings = APISettings()

    assert settings.siem_enabled is True
