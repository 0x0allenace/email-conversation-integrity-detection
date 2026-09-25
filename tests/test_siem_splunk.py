"""Tests for the Splunk SIEM integration."""

from __future__ import annotations

import json
from io import BytesIO
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from src.integrations.siem.event import SIEMEvent
from src.integrations.siem.splunk import SplunkIntegration


class FakeHTTPResponse:
    """Minimal HTTP response used by the tests."""

    def __init__(
        self,
        *,
        status: int = 200,
        body: str = '{"text":"Success","code":0}',
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


def test_splunk_integration_has_expected_name():
    """Test the Splunk integration name."""

    integration = SplunkIntegration(
        url="https://splunk.example.com",
        token="test-token",
    )

    assert integration.name == "splunk"


@patch("src.integrations.siem.splunk.request.urlopen")
def test_splunk_sends_event_to_hec(mock_urlopen):
    """Test sending a normalized event to Splunk HEC."""

    mock_urlopen.return_value = FakeHTTPResponse()

    integration = SplunkIntegration(
        url="https://splunk.example.com/",
        token="test-token",
        index="security",
        source="ecid",
        sourcetype="ecid:event",
    )

    event = create_event()

    result = integration.send(event)

    assert result == {
        "integration": "splunk",
        "status": "accepted",
        "status_code": 200,
        "response": '{"text":"Success","code":0}',
    }

    mock_urlopen.assert_called_once()

    http_request = mock_urlopen.call_args.args[0]

    assert (
        http_request.full_url
        == "https://splunk.example.com/services/collector/event"
    )
    assert http_request.get_method() == "POST"
    assert http_request.get_header("Authorization") == (
        "Splunk test-token"
    )
    assert http_request.get_header("Content-type") == (
        "application/json"
    )

    payload = json.loads(
        http_request.data.decode("utf-8")
    )

    assert payload["index"] == "security"
    assert payload["source"] == "ecid"
    assert payload["sourcetype"] == "ecid:event"

    assert payload["event"]["event_type"] == "email_detection"
    assert payload["event"]["rule_id"] == "BEC-001"
    assert payload["event"]["risk_score"] == 70
    assert payload["event"]["matched"] is True

    assert "test-token" not in (
        http_request.data.decode("utf-8")
    )


@patch("src.integrations.siem.splunk.request.urlopen")
def test_splunk_omits_optional_index_and_source(mock_urlopen):
    """Test that optional HEC fields can be omitted."""

    mock_urlopen.return_value = FakeHTTPResponse()

    integration = SplunkIntegration(
        url="https://splunk.example.com",
        token="test-token",
    )

    event = create_event()

    integration.send(event)

    http_request = mock_urlopen.call_args.args[0]

    payload = json.loads(
        http_request.data.decode("utf-8")
    )

    assert "index" not in payload
    assert "source" not in payload
    assert payload["sourcetype"] == "ecid:event"


@patch("src.integrations.siem.splunk.request.urlopen")
def test_splunk_handles_http_error(mock_urlopen):
    """Test handling of an HTTP error from Splunk."""

    mock_urlopen.side_effect = HTTPError(
        url="https://splunk.example.com/services/collector/event",
        code=401,
        msg="Unauthorized",
        hdrs=None,
        fp=BytesIO(b'{"text":"Invalid token","code":4}'),
    )

    integration = SplunkIntegration(
        url="https://splunk.example.com",
        token="invalid-token",
    )

    result = integration.send(create_event())

    assert result == {
        "integration": "splunk",
        "status": "error",
        "status_code": 401,
        "error": "Unauthorized",
    }


@patch("src.integrations.siem.splunk.request.urlopen")
def test_splunk_handles_connection_error(mock_urlopen):
    """Test handling of a connection error."""

    mock_urlopen.side_effect = URLError(
        "Connection refused"
    )

    integration = SplunkIntegration(
        url="https://splunk.example.com",
        token="test-token",
    )

    result = integration.send(create_event())

    assert result == {
        "integration": "splunk",
        "status": "error",
        "error": "Connection refused",
    }


@patch("src.integrations.siem.splunk.request.urlopen")
def test_splunk_uses_configured_timeout(mock_urlopen):
    """Test that the configured timeout is passed to the HTTP client."""

    mock_urlopen.return_value = FakeHTTPResponse()

    integration = SplunkIntegration(
        url="https://splunk.example.com",
        token="test-token",
        timeout=15.0,
    )

    integration.send(create_event())

    assert mock_urlopen.call_args.kwargs["timeout"] == 15.0
