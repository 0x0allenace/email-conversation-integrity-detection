"""Tests for the FastAPI interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.app import app
from src.database.models import Base
from src.database.session import get_db


TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={
        "check_same_thread": False,
    },
    poolclass=StaticPool,
)

TestSessionLocal = sessionmaker(
    bind=test_engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def override_get_db():
    """Provide the SQLite test database session."""

    db = TestSessionLocal()

    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def reset_test_database():
    """Create a clean database schema for every API test."""

    Base.metadata.drop_all(
        bind=test_engine,
    )

    Base.metadata.create_all(
        bind=test_engine,
    )

    previous_override = app.dependency_overrides.get(
        get_db
    )

    app.dependency_overrides[get_db] = override_get_db

    yield

    if previous_override is None:
        app.dependency_overrides.pop(
            get_db,
            None,
        )
    else:
        app.dependency_overrides[get_db] = (
            previous_override
        )

    Base.metadata.drop_all(
        bind=test_engine,
    )


client = TestClient(app)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

LEGITIMATE_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "legitimate"
    / "normal-conversation.eml"
)

LOOKALIKE_DOMAIN_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "lookalike-domain"
    / "supplier-lookalike.eml"
)

REPLY_TO_MISMATCH_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "reply-to-manipulation"
    / "reply-to-mismatch.eml"
)

THREAD_PARTICIPANT_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "thread-hijacking"
    / "thread-hijacking.eml"
)

INFRASTRUCTURE_ANOMALY_EMAIL = (
    PROJECT_ROOT
    / "samples"
    / "thread-hijacking"
    / "infrastructure-anomaly.eml"
)


def _analysis_form_data(
    *,
    known_domain: str = "supplier.com",
    known_display_name: str = "Bob Supplier",
    known_participants: list[str] | None = None,
    known_hosts: list[str] | None = None,
    known_ip_addresses: list[str] | None = None,
    known_behavior: dict | None = None,
) -> dict:
    """Build form data for the analysis endpoint."""

    return {
        "known_domain": known_domain,
        "known_display_name": known_display_name,
        "known_participants": (
            known_participants
            if known_participants is not None
            else [
                "bob@supplier.com",
                "alice@company.com",
            ]
        ),
        "known_hosts": (
            known_hosts
            if known_hosts is not None
            else [
                "mail.supplier.com",
                "relay.supplier.com",
            ]
        ),
        "known_ip_addresses": (
            known_ip_addresses
            if known_ip_addresses is not None
            else [
                "192.0.2.10",
                "192.0.2.20",
            ]
        ),
        "known_behavior": json.dumps(
            known_behavior
            if known_behavior is not None
            else {}
        ),
    }


def _post_email(
    email_path: Path,
    *,
    filename: str | None = None,
    form_data: dict | None = None,
):
    """Post an email file to the analysis endpoint."""

    return client.post(
        "/analyze",
        files={
            "email_file": (
                filename or email_path.name,
                email_path.read_bytes(),
                "message/rfc822",
            )
        },
        data=form_data or _analysis_form_data(),
    )


def test_health_check() -> None:
    """Return a healthy API status."""

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "email-conversation-integrity-detection",
    }


def test_readiness_check() -> None:
    """Return a ready API status."""

    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "service": "email-conversation-integrity-detection",
    }


def test_analyze_legitimate_email() -> None:
    """Analyze a legitimate email successfully."""

    response = _post_email(
        LEGITIMATE_EMAIL
    )

    assert response.status_code == 200

    body = response.json()

    assert body["identity"]["email_address"] == (
        "bob@supplier.com"
    )

    assert body["identity"]["domain"] == (
        "supplier.com"
    )


def test_analyze_response_structure() -> None:
    """Return the expected top-level analysis response structure."""

    response = _post_email(
        LEGITIMATE_EMAIL
    )

    assert response.status_code == 200

    body = response.json()

    assert set(body.keys()) == {
        "email",
        "identity",
        "participants",
        "authentication",
        "infrastructure",
        "detections",
    }


def test_analyze_response_detection_structure() -> None:
    """Return the expected detection response structure."""

    response = _post_email(
        LEGITIMATE_EMAIL
    )

    assert response.status_code == 200

    detections = response.json()["detections"]

    assert len(detections) == 8

    for detection in detections:
        assert set(detection.keys()) >= {
            "rule_id",
            "rule_name",
            "severity",
            "matched",
            "risk_score",
            "indicators",
        }


def test_analyze_rejects_missing_domain() -> None:
    """Reject a request with a missing known domain."""

    form_data = _analysis_form_data()
    form_data.pop("known_domain")

    response = _post_email(
        LEGITIMATE_EMAIL,
        form_data=form_data,
    )

    assert response.status_code == 422


def test_analyze_rejects_empty_domain() -> None:
    """Reject an empty known domain."""

    form_data = _analysis_form_data(
        known_domain="",
    )

    response = _post_email(
        LEGITIMATE_EMAIL,
        form_data=form_data,
    )

    assert response.status_code == 422
    assert response.json()["detail"] == (
        "known_domain is required."
    )


def test_analyze_strips_surrounding_whitespace() -> None:
    """Normalize surrounding whitespace in required fields."""

    form_data = _analysis_form_data(
        known_domain="  supplier.com  ",
        known_display_name="  Bob Supplier  ",
    )

    response = _post_email(
        LEGITIMATE_EMAIL,
        form_data=form_data,
    )

    assert response.status_code == 200


def test_analyze_rejects_missing_display_name() -> None:
    """Reject a request with a missing known display name."""

    form_data = _analysis_form_data()
    form_data.pop("known_display_name")

    response = _post_email(
        LEGITIMATE_EMAIL,
        form_data=form_data,
    )

    assert response.status_code == 422


def test_analyze_rejects_empty_display_name() -> None:
    """Reject an empty known display name."""

    form_data = _analysis_form_data(
        known_display_name="",
    )

    response = _post_email(
        LEGITIMATE_EMAIL,
        form_data=form_data,
    )

    assert response.status_code == 422
    assert response.json()["detail"] == (
        "known_display_name is required."
    )


def test_analyze_rejects_missing_filename() -> None:
    """Reject an uploaded email without a filename."""

    response = client.post(
        "/analyze",
        files={
            "email_file": (
                "",
                LEGITIMATE_EMAIL.read_bytes(),
                "message/rfc822",
            )
        },
        data=_analysis_form_data(),
    )

    assert response.status_code == 422


def test_analyze_rejects_unsupported_file_extension() -> None:
    """Reject uploads that do not use the .eml extension."""

    response = client.post(
        "/analyze",
        files={
            "email_file": (
                "email.txt",
                LEGITIMATE_EMAIL.read_bytes(),
                "message/rfc822",
            )
        },
        data=_analysis_form_data(),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Unsupported email file type. "
        "Only .eml files are supported."
    )


def test_analyze_accepts_uppercase_eml_extension() -> None:
    """Accept an email filename with an uppercase extension."""

    response = _post_email(
        LEGITIMATE_EMAIL,
        filename="NORMAL-CONVERSATION.EML",
        form_data=_analysis_form_data(),
    )

    assert response.status_code == 200


def test_analyze_rejects_empty_email() -> None:
    """Reject an uploaded email file with no content."""

    response = client.post(
        "/analyze",
        files={
            "email_file": (
                "empty.eml",
                b"",
                "message/rfc822",
            )
        },
        data=_analysis_form_data(),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Uploaded email file is empty."
    )


def test_analyze_rejects_malformed_email() -> None:
    """Return a validation error for malformed email content."""

    response = client.post(
        "/analyze",
        files={
            "email_file": (
                "malformed.eml",
                b"this is not a valid email",
                "message/rfc822",
            )
        },
        data=_analysis_form_data(),
    )

    assert response.status_code == 400


def test_analyze_detects_bec_001_lookalike_domain() -> None:
    """Detect a lookalike sender domain."""

    response = _post_email(
        LOOKALIKE_DOMAIN_EMAIL,
        form_data=_analysis_form_data(
            known_domain="supplier.com",
            known_display_name="Bob Supplier",
        ),
    )

    assert response.status_code == 200

    detections = response.json()["detections"]

    bec_001 = next(
        detection
        for detection in detections
        if detection["rule_id"] == "BEC-001"
    )

    assert bec_001["matched"] is True


def test_analyze_detects_bec_002_reply_to_mismatch() -> None:
    """Detect a Reply-To domain mismatch."""

    response = _post_email(
        REPLY_TO_MISMATCH_EMAIL,
        form_data=_analysis_form_data(),
    )

    assert response.status_code == 200

    detections = response.json()["detections"]

    bec_002 = next(
        detection
        for detection in detections
        if detection["rule_id"] == "BEC-002"
    )

    assert bec_002["matched"] is True


def test_analyze_detects_bec_003_thread_participant_anomaly() -> None:
    """Detect an unexpected conversation participant."""

    response = _post_email(
        THREAD_PARTICIPANT_EMAIL,
        form_data=_analysis_form_data(),
    )

    assert response.status_code == 200

    detections = response.json()["detections"]

    bec_003 = next(
        detection
        for detection in detections
        if detection["rule_id"] == "BEC-003"
    )

    assert bec_003["matched"] is True


def test_analyze_detects_bec_004_authentication_anomaly() -> None:
    """Detect an authentication anomaly."""

    response = _post_email(
        LOOKALIKE_DOMAIN_EMAIL,
        form_data=_analysis_form_data(),
    )

    assert response.status_code == 200

    detections = response.json()["detections"]

    bec_004 = next(
        detection
        for detection in detections
        if detection["rule_id"] == "BEC-004"
    )

    assert bec_004["matched"] is True


def test_analyze_detects_bec_005_sender_infrastructure_anomaly() -> None:
    """Detect unexpected sender infrastructure."""

    response = _post_email(
        INFRASTRUCTURE_ANOMALY_EMAIL,
        form_data=_analysis_form_data(),
    )

    assert response.status_code == 200

    detections = response.json()["detections"]

    bec_005 = next(
        detection
        for detection in detections
        if detection["rule_id"] == "BEC-005"
    )

    assert bec_005["matched"] is True


def test_analyze_detects_bec_006_conversation_hijacking() -> None:
    """Detect conversation hijacking indicators."""

    response = _post_email(
        THREAD_PARTICIPANT_EMAIL,
        form_data=_analysis_form_data(),
    )

    assert response.status_code == 200

    detections = response.json()["detections"]

    bec_006 = next(
        detection
        for detection in detections
        if detection["rule_id"] == "BEC-006"
    )

    assert bec_006["matched"] is True


def test_analyze_rejects_invalid_behavior_json() -> None:
    """Reject malformed behavioral baseline JSON."""

    form_data = _analysis_form_data()

    form_data["known_behavior"] = (
        "{invalid-json}"
    )

    response = _post_email(
        LEGITIMATE_EMAIL,
        form_data=form_data,
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "known_behavior must contain valid JSON."
    )


def test_analyze_accepts_empty_behavior_json() -> None:
    """Accept an empty behavioral baseline JSON value."""

    form_data = _analysis_form_data()

    form_data["known_behavior"] = ""

    response = _post_email(
        LEGITIMATE_EMAIL,
        form_data=form_data,
    )

    assert response.status_code == 200


def test_analyze_handles_unexpected_internal_error(
    monkeypatch,
) -> None:
    """Return a generic 500 response for unexpected errors."""

    def raise_unexpected_error(*args, **kwargs):
        raise RuntimeError("unexpected failure")

    monkeypatch.setattr(
        "src.api.app.analysis_service.analyze_email",
        raise_unexpected_error,
    )

    response = _post_email(
        LEGITIMATE_EMAIL
    )

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "Internal server error."
    )
