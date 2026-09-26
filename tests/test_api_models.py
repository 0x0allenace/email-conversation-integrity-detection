"""Tests for API request and response models."""

from datetime import datetime, timezone

from src.api.models import (
    AnalysisSummaryResponse,
    AuthenticationResponse,
    DetectionResponse,
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    IdentityResponse,
    InfrastructureResponse,
)


def test_email_analysis_request_does_not_require_file_path():
    """Test that the request model contains analysis configuration only."""

    request = EmailAnalysisRequest(
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
    )

    assert request.known_domain == "supplier.com"
    assert request.known_display_name == "Bob Supplier"
    assert request.known_participants == []
    assert request.known_hosts == []
    assert request.known_ip_addresses == []
    assert request.known_behavior == {}

    assert not hasattr(
        request,
        "email_file",
    )


def test_email_analysis_request_accepts_behavioral_baseline():
    """Test that the request model accepts a behavioral baseline."""

    request = EmailAnalysisRequest(
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=[
            "bob@supplier.com",
            "alice@company.com",
        ],
        known_hosts=[
            "mail.supplier.com",
        ],
        known_ip_addresses=[
            "192.0.2.10",
        ],
        known_behavior={
            "typical_hours": list(range(8, 18)),
        },
    )

    assert request.known_participants == [
        "bob@supplier.com",
        "alice@company.com",
    ]

    assert request.known_hosts == [
        "mail.supplier.com",
    ]

    assert request.known_ip_addresses == [
        "192.0.2.10",
    ]

    assert request.known_behavior == {
        "typical_hours": list(range(8, 18)),
    }


def test_detection_response_preserves_detection_details():
    """Test that detection response accepts additional rule details."""

    response = DetectionResponse(
        rule_id="BEC-007",
        rule_name="Behavioral Communication Anomaly",
        severity="MEDIUM",
        matched=True,
        risk_score=20,
        indicators=[
            "Message sent outside established communication hours"
        ],
        observed_hour=22,
        typical_hours=list(range(8, 18)),
    )

    assert response.rule_id == "BEC-007"
    assert response.matched is True
    assert response.risk_score == 20

    response_data = response.model_dump()

    assert response_data["observed_hour"] == 22
    assert response_data["typical_hours"] == list(range(8, 18))


def test_response_models_validate_expected_structure():
    """Test that nested API response models validate correctly."""

    identity = IdentityResponse(
        display_name="Bob Supplier",
        email_address="bob@supplier.com",
        username="bob",
        domain="supplier.com",
    )

    authentication = AuthenticationResponse(
        spf="pass",
        dkim="pass",
        dmarc="pass",
    )

    infrastructure = InfrastructureResponse(
        received_count=2,
        hosts=[
            "mail.supplier.com",
            "relay.supplier.com",
        ],
        ip_addresses=[
            "192.0.2.10",
            "192.0.2.20",
        ],
    )

    response = EmailAnalysisResponse(
        email={
            "subject": "Invoice Update",
        },
        identity=identity,
        participants=[
            "alice@company.com",
            "bob@supplier.com",
        ],
        authentication=authentication,
        infrastructure=infrastructure,
        detections=[],
    )

    assert response.identity.email_address == "bob@supplier.com"
    assert response.authentication.spf == "pass"
    assert response.infrastructure.received_count == 2
    assert response.participants == [
        "alice@company.com",
        "bob@supplier.com",
    ]


def test_analysis_summary_response_accepts_email_sent_at():
    """Test that persisted analysis responses expose the email timestamp."""

    email_sent_at = datetime(
        2026,
        9,
        23,
        10,
        30,
        tzinfo=timezone.utc,
    )

    response = AnalysisSummaryResponse(
        id=1,
        analyzed_at=datetime(
            2026,
            9,
            23,
            11,
            0,
            tzinfo=timezone.utc,
        ),
        email_sent_at=email_sent_at,
        email_message_id="<invoice-update-001@supplier.com>",
        sender_email="bob@supplier.com",
        sender_domain="supplier.com",
        subject="Invoice Update",
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        risk_score=0,
    )

    assert response.email_sent_at == email_sent_at
