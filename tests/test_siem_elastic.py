"""Tests for the Elastic SIEM integration."""

from __future__ import annotations

import base64
import json
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from src.integrations.siem.elastic import ElasticIntegration
from src.integrations.siem.event import SIEMEvent


class FakeHTTPResponse:
    """Minimal HTTP response used by the tests."""

    def __init__(
        self,
        *,
        status: int = 201,
        body: str = (
            '{"_index":"security-events","result":"created"}'
        ),
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


def test_elastic_integration_has_expected_name():
    """Test the Elastic integration name."""

    integration = ElasticIntegration(
        url="https://elastic.example.com",
    )

    assert integration.name == "elastic"


@patch("src.integrations.siem.elastic.request.urlopen")
def test_elastic_sends_event_to_configured_index(mock_urlopen):
    """Test sending a normalized event to Elasticsearch."""

    mock_urlopen.return_value = FakeHTTPResponse()

    integration = ElasticIntegration(
        url="https://elastic.example.com/",
        index="security-events",
    )

    event = create_event()

    result = integration.send(event)

    assert result == {
        "integration": "elastic",
        "status": "accepted",
        "status_code": 201,
        "response": (
            '{"_index":"security-events","result":"created"}'
        ),
    }

    mock_urlopen.assert_called_once()

    http_request = mock_urlopen.call_args.args[0]

    assert (
        http_request.full_url
        == "https://elastic.example.com/"
        "security-events/_doc"
    )
    assert http_request.get_method() == "POST"
    assert http_request.get_header("Content-type") == (
        "application/json"
    )

    payload = json.loads(
        http_request.data.decode("utf-8")
    )

    assert payload["event_type"] == "email_detection"
    assert payload["rule_id"] == "BEC-001"
    assert payload["risk_score"] == 70
    assert payload["matched"] is True


@patch("src.integrations.siem.elastic.request.urlopen")
def test_elastic_uses_api_key_authentication(mock_urlopen):
    """Test Elasticsearch API key authentication."""

    mock_urlopen.return_value = FakeHTTPResponse()

    integration = ElasticIntegration(
        url="https://elastic.example.com",
        api_key="test-api-key",
    )

    integration.send(create_event())

    http_request = mock_urlopen.call_args.args[0]

    assert http_request.get_header("Authorization") == (
        "ApiKey test-api-key"
    )

    payload = http_request.data.decode("utf-8")

    assert "test-api-key" not in payload


@patch("src.integrations.siem.elastic.request.urlopen")
def test_elastic_uses_basic_authentication(mock_urlopen):
    """Test Elasticsearch username/password authentication."""

    mock_urlopen.return_value = FakeHTTPResponse()

    integration = ElasticIntegration(
        url="https://elastic.example.com",
        username="elastic-user",
        password="test-password",
    )

    integration.send(create_event())

    http_request = mock_urlopen.call_args.args[0]

    expected_credentials = base64.b64encode(
        b"elastic-user:test-password"
    ).decode("ascii")

    assert http_request.get_header("Authorization") == (
        f"Basic {expected_credentials}"
    )

    payload = http_request.data.decode("utf-8")

    assert "elastic-user" not in payload
    assert "test-password" not in payload


@patch("src.integrations.siem.elastic.request.urlopen")
def test_elastic_prefers_api_key_over_basic_auth(mock_urlopen):
    """Test API key authentication takes precedence."""

    mock_urlopen.return_value = FakeHTTPResponse()

    integration = ElasticIntegration(
        url="https://elastic.example.com",
        api_key="test-api-key",
        username="elastic-user",
        password="test-password",
    )

    integration.send(create_event())

    http_request = mock_urlopen.call_args.args[0]

    assert http_request.get_header("Authorization") == (
        "ApiKey test-api-key"
    )


@patch("src.integrations.siem.elastic.request.urlopen")
def test_elastic_handles_http_error(mock_urlopen):
    """Test handling of an HTTP error from Elasticsearch."""

    mock_urlopen.side_effect = HTTPError(
        url=(
            "https://elastic.example.com/"
            "security-events/_doc"
        ),
        code=401,
        msg="Unauthorized",
        hdrs=None,
        fp=None,
    )

    integration = ElasticIntegration(
        url="https://elastic.example.com",
        index="security-events",
        api_key="invalid-api-key",
    )

    result = integration.send(create_event())

    assert result == {
        "integration": "elastic",
        "status": "error",
        "status_code": 401,
        "error": "Unauthorized",
    }


@patch("src.integrations.siem.elastic.request.urlopen")
def test_elastic_handles_connection_error(mock_urlopen):
    """Test handling of a connection error."""

    mock_urlopen.side_effect = URLError(
        "Connection refused"
    )

    integration = ElasticIntegration(
        url="https://elastic.example.com",
    )

    result = integration.send(create_event())

    assert result == {
        "integration": "elastic",
        "status": "error",
        "error": "Connection refused",
    }


@patch("src.integrations.siem.elastic.request.urlopen")
def test_elastic_uses_configured_timeout(mock_urlopen):
    """Test that the configured timeout is passed to the HTTP client."""

    mock_urlopen.return_value = FakeHTTPResponse()

    integration = ElasticIntegration(
        url="https://elastic.example.com",
        timeout=15.0,
    )

    integration.send(create_event())

    assert mock_urlopen.call_args.kwargs["timeout"] == 15.0
