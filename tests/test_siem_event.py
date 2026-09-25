"""Tests for the normalized SIEM event model."""

from datetime import datetime

from src.integrations.siem.event import SIEMEvent


def test_create_generates_normalized_event():
    """Test creation of a normalized SIEM event."""

    event = SIEMEvent.create(
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
        details={"observed_domain": "example.net"},
        authentication={"spf": "fail"},
        infrastructure={"received_hosts": ["mail.example.net"]},
        conversation={"thread_id": "<thread-001@company.com>"},
    )

    assert event.event_type == "email_detection"
    assert event.message_id == "<message-001@example.com>"
    assert event.sender_email == "attacker@example.net"
    assert event.sender_domain == "example.net"
    assert event.recipient_emails == ["alice@company.com"]
    assert event.subject == "Invoice Update"
    assert event.rule_id == "BEC-001"
    assert event.rule_name == "Lookalike Domain Detection"
    assert event.severity == "high"
    assert event.matched is True
    assert event.risk_score == 70
    assert event.indicators == ["Lookalike domain detected"]
    assert event.details["observed_domain"] == "example.net"
    assert event.authentication["spf"] == "fail"
    assert event.infrastructure["received_hosts"] == ["mail.example.net"]
    assert event.conversation["thread_id"] == (
        "<thread-001@company.com>"
    )
    assert event.source == "email-conversation-integrity-detection"
    assert event.schema_version == "1.0"


def test_create_generates_utc_timestamp():
    """Test that generated timestamps are valid UTC timestamps."""

    event = SIEMEvent.create(
        event_type="email_detection",
    )

    timestamp = datetime.fromisoformat(event.timestamp)

    assert timestamp.tzinfo is not None
    assert timestamp.utcoffset().total_seconds() == 0


def test_to_dict_serializes_event():
    """Test conversion of the SIEM event into a dictionary."""

    event = SIEMEvent.create(
        event_type="email_detection",
        rule_id="BEC-004",
        matched=True,
        risk_score=30,
    )

    result = event.to_dict()

    assert isinstance(result, dict)
    assert result["event_type"] == "email_detection"
    assert result["rule_id"] == "BEC-004"
    assert result["matched"] is True
    assert result["risk_score"] == 30
    assert result["source"] == (
        "email-conversation-integrity-detection"
    )
    assert result["schema_version"] == "1.0"
