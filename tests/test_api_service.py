from pathlib import Path
from unittest.mock import Mock

import pytest

from src.api.service import AnalysisService
from src.engine.detection_engine import DetectionEngine
from src.integrations.siem.service import SIEMService


PROJECT_ROOT = Path(__file__).resolve().parents[1]

LEGITIMATE_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "legitimate"
    / "normal-conversation.eml"
)

KNOWN_PARTICIPANTS = [
    "bob@supplier.com",
    "alice@company.com",
]

KNOWN_HOSTS = [
    "mail.supplier.com",
    "relay.supplier.com",
]

KNOWN_IP_ADDRESSES = [
    "192.0.2.10",
    "192.0.2.20",
]

KNOWN_BEHAVIOR = {
    "typical_hours": list(range(8, 18)),
}


@pytest.fixture
def service():
    """Create an API analysis service."""

    return AnalysisService()


def test_analysis_service_returns_email_analysis(
    service,
):
    """Test that the service returns a complete email analysis."""

    result = service.analyze_email(
        email_file=str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        known_behavior=KNOWN_BEHAVIOR,
    )

    assert "email" in result
    assert "identity" in result
    assert "participants" in result
    assert "authentication" in result
    assert "infrastructure" in result
    assert "detections" in result


def test_analysis_service_preserves_detection_results(
    service,
):
    """Test that the service preserves detection rule results."""

    result = service.analyze_email(
        email_file=str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        known_behavior=KNOWN_BEHAVIOR,
    )

    bec_007 = next(
        detection
        for detection in result["detections"]
        if detection["rule_id"] == "BEC-007"
    )

    assert bec_007["matched"] is False
    assert bec_007["risk_score"] == 0
    assert bec_007["observed_hour"] == 10
    assert bec_007["typical_hours"] == list(range(8, 18))


def test_analysis_service_passes_missing_file_error(
    service,
):
    """Test that a missing email file raises FileNotFoundError."""

    missing_file = PROJECT_ROOT / "does-not-exist.eml"

    with pytest.raises(
        FileNotFoundError,
        match="Email file not found",
    ):
        service.analyze_email(
            email_file=str(missing_file),
            known_domain="supplier.com",
            known_display_name="Bob Supplier",
            known_participants=KNOWN_PARTICIPANTS,
            known_hosts=KNOWN_HOSTS,
            known_ip_addresses=KNOWN_IP_ADDRESSES,
            known_behavior=KNOWN_BEHAVIOR,
        )


def test_analysis_service_passes_malformed_email_error(
    service,
):
    """Test that malformed email content raises ValueError."""

    malformed_email = (
        PROJECT_ROOT
        / "tests"
        / "service-malformed-email.eml"
    )

    malformed_email.write_text(
        "This is not a valid email message.",
        encoding="utf-8",
    )

    try:
        with pytest.raises(
            ValueError,
            match="Unable to parse email",
        ):
            service.analyze_email(
                email_file=str(malformed_email),
                known_domain="supplier.com",
                known_display_name="Bob Supplier",
                known_participants=KNOWN_PARTICIPANTS,
                known_hosts=KNOWN_HOSTS,
                known_ip_addresses=KNOWN_IP_ADDRESSES,
                known_behavior=KNOWN_BEHAVIOR,
            )
    finally:
        malformed_email.unlink(missing_ok=True)


def test_analysis_service_accepts_injected_detection_engine():
    """Test that the service accepts an injected detection engine."""

    detection_engine = DetectionEngine()

    service = AnalysisService(
        detection_engine=detection_engine,
    )

    assert service.detection_engine is detection_engine


def test_analysis_service_accepts_injected_siem_service():
    """Test that the service accepts an injected SIEM service."""

    siem_service = Mock(spec=SIEMService)

    service = AnalysisService(
        siem_service=siem_service,
    )

    assert service.siem_service is siem_service


def test_analysis_service_without_siem_preserves_existing_behavior(
    service,
):
    """Test that analysis still works when SIEM is not configured."""

    assert service.siem_service is None

    result = service.analyze_email(
        email_file=str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        known_behavior=KNOWN_BEHAVIOR,
    )

    assert "email" in result
    assert "detections" in result


def test_analysis_service_dispatches_siem_events_without_database():
    """Test that SIEM dispatch occurs when no database is provided."""

    siem_service = Mock(spec=SIEMService)

    service = AnalysisService(
        siem_service=siem_service,
    )

    result = service.analyze_email(
        email_file=str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        known_behavior=KNOWN_BEHAVIOR,
    )

    siem_service.dispatch_detections.assert_called_once()

    call_kwargs = (
        siem_service.dispatch_detections.call_args.kwargs
    )

    assert call_kwargs["detections"] == result["detections"]
    assert call_kwargs["email"] == result["email"]
    assert (
        call_kwargs["authentication"]
        == result["authentication"]
    )
    assert (
        call_kwargs["infrastructure"]
        == result["infrastructure"]
    )
    assert call_kwargs["conversation"] is None


def test_analysis_service_dispatches_siem_events_after_persistence():
    """Test that SIEM dispatch occurs after database persistence."""

    siem_service = Mock(spec=SIEMService)

    service = AnalysisService(
        siem_service=siem_service,
    )

    db = Mock()

    db.scalars.return_value.all.return_value = []

    call_order = []

    def record_commit():
        call_order.append("commit")

    def record_dispatch(**kwargs):
        call_order.append("dispatch")

    db.commit.side_effect = record_commit
    siem_service.dispatch_detections.side_effect = record_dispatch

    service.analyze_email(
        email_file=str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        known_behavior=KNOWN_BEHAVIOR,
        db=db,
    )

    assert call_order == [
        "commit",
        "dispatch",
    ]

    db.add.assert_called_once()
    db.commit.assert_called_once()
    db.refresh.assert_called_once()
    siem_service.dispatch_detections.assert_called_once()


def test_analysis_service_passes_sender_history_to_detection_engine():
    """Test that sender history is passed to the detection engine."""

    detection_engine = Mock(spec=DetectionEngine)

    detection_engine.analyze.return_value = {
        "email": {
            "date": "Wed, 23 Sep 2026 10:30:00 +0000",
            "message_id": "<invoice-update-001@supplier.com>",
            "subject": "Test message",
        },
        "identity": {
            "email_address": "bob@supplier.com",
            "domain": "supplier.com",
        },
        "participants": KNOWN_PARTICIPANTS,
        "authentication": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        },
        "infrastructure": {},
        "detections": [],
    }

    repository = Mock(spec=AnalysisService().repository)

    historical_observations = [
        {
            "id": 1,
            "sender_email": "bob@supplier.com",
            "email_sent_at": "2026-09-20T09:30:00+00:00",
        },
        {
            "id": 2,
            "sender_email": "bob@supplier.com",
            "email_sent_at": "2026-09-21T10:30:00+00:00",
        },
        {
            "id": 3,
            "sender_email": "bob@supplier.com",
            "email_sent_at": "2026-09-22T14:00:00+00:00",
        },
    ]

    repository.list_sender_history.return_value = (
        historical_observations
    )

    service = AnalysisService(
        detection_engine=detection_engine,
        repository=repository,
    )

    db = Mock()

    service.analyze_email(
        email_file=str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        known_behavior=KNOWN_BEHAVIOR,
        db=db,
    )

    repository.list_sender_history.assert_called_once_with(
        db,
        sender_email="bob@supplier.com",
    )

    detection_engine.analyze.assert_called_once()

    call_kwargs = (
        detection_engine.analyze.call_args.kwargs
    )

    assert (
        call_kwargs["historical_observations"]
        == historical_observations
    )

    assert (
        call_kwargs["email_data"]["message_id"]
        == "<invoice-update-001@supplier.com>"
    )

    db.add.assert_called_once()
    db.commit.assert_called_once()
    db.refresh.assert_called_once()


def test_analysis_service_forwards_detection_context_to_siem():
    """Test that analysis context is forwarded to SIEM dispatch."""

    siem_service = Mock(spec=SIEMService)

    service = AnalysisService(
        siem_service=siem_service,
    )

    result = service.analyze_email(
        email_file=str(LEGITIMATE_EMAIL),
        known_domain="supplier.com",
        known_display_name="Bob Supplier",
        known_participants=KNOWN_PARTICIPANTS,
        known_hosts=KNOWN_HOSTS,
        known_ip_addresses=KNOWN_IP_ADDRESSES,
        known_behavior=KNOWN_BEHAVIOR,
    )

    call_kwargs = (
        siem_service.dispatch_detections.call_args.kwargs
    )

    assert call_kwargs["detections"] == result["detections"]
    assert call_kwargs["email"] == result["email"]
    assert (
        call_kwargs["authentication"]
        == result["authentication"]
    )
    assert (
        call_kwargs["infrastructure"]
        == result["infrastructure"]
    )
