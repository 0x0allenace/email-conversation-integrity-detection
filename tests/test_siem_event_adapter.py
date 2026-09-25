"""Tests for the SIEM event adapter."""

from src.detection.result import DetectionResult
from src.integrations.siem.event_adapter import SIEMEventAdapter


def test_from_detection_creates_siem_event():
    """Test conversion of a detection result into a SIEM event."""

    detection = DetectionResult(
        rule_id="BEC-001",
        rule_name="Lookalike Domain Detection",
        severity="high",
        matched=True,
        risk_score=70,
        indicators=["Lookalike domain detected"],
        details={
            "observed_domain": "supp1ier.com",
            "known_domain": "supplier.com",
        },
    )

    email = {
        "message_id": "<message-001@supp1ier.com>",
        "from_email": "bob@supp1ier.com",
        "from_domain": "supp1ier.com",
        "to": ["alice@company.com"],
        "subject": "Invoice Update",
    }

    adapter = SIEMEventAdapter()

    event = adapter.from_detection(
        detection=detection,
        email=email,
        authentication={"spf": "fail"},
        infrastructure={
            "received_hosts": ["mail.supp1ier.com"],
        },
        conversation={
            "in_reply_to": "<previous-message-001@company.com>",
        },
    )

    assert event.event_type == "email_detection"
    assert event.message_id == "<message-001@supp1ier.com>"
    assert event.sender_email == "bob@supp1ier.com"
    assert event.sender_domain == "supp1ier.com"
    assert event.recipient_emails == ["alice@company.com"]
    assert event.subject == "Invoice Update"

    assert event.rule_id == "BEC-001"
    assert event.rule_name == "Lookalike Domain Detection"
    assert event.severity == "high"
    assert event.matched is True
    assert event.risk_score == 70

    assert event.indicators == ["Lookalike domain detected"]
    assert event.details["observed_domain"] == "supp1ier.com"
    assert event.authentication["spf"] == "fail"
    assert event.infrastructure["received_hosts"] == [
        "mail.supp1ier.com"
    ]
    assert event.conversation["in_reply_to"] == (
        "<previous-message-001@company.com>"
    )


def test_from_detection_handles_string_recipient():
    """Test conversion when the email recipient is a single string."""

    detection = DetectionResult(
        rule_id="BEC-002",
        rule_name="Reply-To Mismatch",
        severity="medium",
        matched=True,
        risk_score=50,
        indicators=["Reply-To domain differs from sender domain"],
        details={},
    )

    email = {
        "message_id": "<message-002@example.com>",
        "from_email": "sender@example.com",
        "from_domain": "example.com",
        "to": "alice@company.com",
        "subject": "Payment Update",
    }

    event = SIEMEventAdapter().from_detection(
        detection=detection,
        email=email,
    )

    assert event.recipient_emails == ["alice@company.com"]
    assert event.rule_id == "BEC-002"
    assert event.risk_score == 50


def test_from_detection_handles_missing_optional_analysis_data():
    """Test conversion without optional analysis dictionaries."""

    detection = DetectionResult(
        rule_id="BEC-007",
        rule_name="Behavioral Anomaly",
        severity="low",
        matched=False,
        risk_score=0,
        indicators=[],
        details={},
    )

    email = {
        "message_id": "<message-003@example.com>",
        "from_email": "sender@example.com",
        "from_domain": "example.com",
        "to": [],
        "subject": "Normal Message",
    }

    event = SIEMEventAdapter().from_detection(
        detection=detection,
        email=email,
    )

    assert event.matched is False
    assert event.risk_score == 0
    assert event.authentication == {}
    assert event.infrastructure == {}
    assert event.conversation == {}
