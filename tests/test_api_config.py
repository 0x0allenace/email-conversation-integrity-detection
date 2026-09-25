from src.api.config import APISettings, settings


def test_api_settings_contain_expected_metadata():
    """Test that centralized API settings contain expected metadata."""

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
    """Test that API settings can be overridden by environment variables."""

    monkeypatch.setenv(
        "ECID_API_VERSION",
        "0.2.0",
    )
    monkeypatch.setenv(
        "ECID_API_HOST",
        "0.0.0.0",
    )
    monkeypatch.setenv(
        "ECID_API_PORT",
        "9000",
    )

    overridden_settings = APISettings()

    assert overridden_settings.version == "0.2.0"
    assert overridden_settings.host == "0.0.0.0"
    assert overridden_settings.port == 9000
