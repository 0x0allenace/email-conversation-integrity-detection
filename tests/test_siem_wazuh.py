"""Tests for the Wazuh SIEM integration."""

from __future__ import annotations

import base64
import json
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from src.integrations.siem.event import SIEMEvent
from src.integrations.siem.wazuh import WazuhIntegration


class FakeHTTPResponse:
    """Minimal HTTP response used by the tests."""

    def __init__(
        self,
        *,
        status: int = 200,
        body: str = '{"message":"Event accepted"}',
    ) -> None:
        """Initialize the fake HTTP response."""

        self.status = status
        self._body = body

    def __enter__(self) -> "FakeHTTPResponse":
        """Enter the response context manager."""

        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        """Exit the response context manager."""

    def read(self) -> bytes:
        """Return the fake response body."""

        return self._body.encode("utf-8")


def create_event() -> SIEMEvent:
    """Create a representative normalized SIEM event."""

    return SIEMEvent.create(
        event_type="email_detection",
        message_id="<message-001@example.com>",
        sender_email="attacker@example.net",
        sender_domain="example.net",
        recipient_emails=["alice@company.com"],
        subject="Invoice Update",
        rule_id="BEC-001",
        rule_name="Lookalike Domain Detection",
        severity="high",
        matched=True,
        risk_score=70,
        indicators=["Lookalike domain detected"],
        details={
            "observed_domain": "example.net",
        },
    )


def test_wazuh_integration_has_expected_name():
    """Test the Wazuh integration name."""

    integration = WazuhIntegration(
        url="https://wazuh.example.com",
        username="wazuh-user",
        password="test-password",
    )

    assert integration.name == "wazuh"


@patch("src.integrations.siem.wazuh.request.urlopen")
def test_wazuh_sends_event_to_configured_endpoint(mock_urlopen):
    """Test sending a normalized event to Wazuh."""

    mock_urlopen.return_value = FakeHTTPResponse()

    integration = WazuhIntegration(
        url="https://wazuh.example.com/",
        username="wazuh-user",
        password="test-password",
        index="security-events",
    )

    event = create_event()

    result = integration.send(event)

    assert result == {
        "integration": "wazuh",
        "status": "accepted",
        "status_code": 200,
        "response": '{"message":"Event accepted"}',
    }

    mock_urlopen.assert_called_once()

    http_request = mock_urlopen.call_args.args[0]

    assert (
        http_request.full_url
        == "https://wazuh.example.com/events"
    )
    assert http_request.get_method() == "POST"
    assert http_request.get_header("Content-type") == (
        "application/json"
    )

    payload = json.loads(
        http_request.data.decode("utf-8")
    )

    assert payload["index"] == "security-events"
    assert payload["event"]["event_type"] == "email_detection"
    assert payload["event"]["rule_id"] == "BEC-001"
    assert payload["event"]["risk_score"] == 70
    assert payload["event"]["matched"] is True


@patch("src.integrations.siem.wazuh.request.urlopen")
def test_wazuh_uses_basic_authentication(mock_urlopen):
    """Test Wazuh username/password authentication."""

    mock_urlopen.return_value = FakeHTTPResponse()

    integration = WazuhIntegration(
        url="https://wazuh.example.com",
        username="wazuh-user",
        password="test-password",
    )

    integration.send(create_event())

    http_request = mock_urlopen.call_args.args[0]

    expected_credentials = base64.b64encode(
        b"wazuh-user:test-password"
    ).decode("ascii")

    assert http_request.get_header("Authorization") == (
        f"Basic {expected_credentials}"
    )

    payload = http_request.data.decode("utf-8")

    assert "wazuh-user" not in payload
    assert "test-password" not in payload


@patch("src.integrations.siem.wazuh.request.urlopen")
def test_wazuh_handles_http_error(mock_urlopen):
    """Test handling of an HTTP error from Wazuh."""

    mock_urlopen.side_effect = HTTPError(
        url="https://wazuh.example.com/events",
        code=401,
        msg="Unauthorized",
        hdrs=None,
        fp=None,
    )

    integration = WazuhIntegration(
        url="https://wazuh.example.com",
        username="wazuh-user",
        password="invalid-password",
    )

    result = integration.send(create_event())

    assert result == {
        "integration": "wazuh",
        "status": "error",
        "status_code": 401,
        "error": "Unauthorized",
    }


@patch("src.integrations.siem.wazuh.request.urlopen")
def test_wazuh_handles_connection_error(mock_urlopen):
    """Test handling of a connection error."""

    mock_urlopen.side_effect = URLError(
        "Connection refused"
    )

    integration = WazuhIntegration(
        url="https://wazuh.example.com",
        username="wazuh-user",
        password="test-password",
    )

    result = integration.send(create_event())

    assert result == {
        "integration": "wazuh",
        "status": "error",
        "error": "Connection refused",
    }


@patch("src.integrations.siem.wazuh.request.urlopen")
def test_wazuh_uses_configured_timeout(mock_urlopen):
    """Test that the configured timeout is passed to the HTTP client."""

    mock_urlopen.return_value = FakeHTTPResponse()

    integration = WazuhIntegration(
        url="https://wazuh.example.com",
        username="wazuh-user",
        password="test-password",
        timeout=15.0,
    )

    integration.send(create_event())

    assert mock_urlopen.call_args.kwargs["timeout"] == 15.0
