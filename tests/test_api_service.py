from pathlib import Path

import pytest

from src.api.service import AnalysisService
from src.engine.detection_engine import DetectionEngine


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
