"""Tests for persisted analysis retrieval API endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.app import app
from src.database.models import Analysis, Base, Detection
from src.database.session import get_db


TEST_DATABASE_URL = "sqlite://"

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
    """Provide the test database session."""

    with TestSessionLocal() as db:
        yield db


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_database():
    """Reset the database before every test."""

    Base.metadata.drop_all(
        bind=test_engine,
    )

    Base.metadata.create_all(
        bind=test_engine,
    )

    yield

    Base.metadata.drop_all(
        bind=test_engine,
    )


def teardown_module() -> None:
    """Remove application overrides and dispose of the test engine."""

    app.dependency_overrides.pop(
        get_db,
        None,
    )

    test_engine.dispose()


def _create_analysis(
    *,
    sender_email: str = "bob@supplier.com",
    subject: str = "Invoice update",
    risk_score: int = 0,
    analyzed_at: datetime | None = None,
    email_sent_at: datetime | None = None,
) -> int:
    """Create and persist a test analysis."""

    with TestSessionLocal() as db:
        analysis = Analysis(
            analyzed_at=(
                analyzed_at
                if analyzed_at is not None
                else datetime.now(timezone.utc)
            ),
            email_sent_at=email_sent_at,
            email_message_id="<api-test@example.com>",
            sender_email=sender_email,
            sender_domain="supplier.com",
            subject=subject,
            known_domain="supplier.com",
            known_display_name="Bob Supplier",
            risk_score=risk_score,
            result={
                "email": {
                    "subject": subject,
                },
                "detections": [],
            },
        )

        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        analysis_id = analysis.id

    return analysis_id


def _add_detection(
    analysis_id: int,
) -> None:
    """Add a persisted detection to an analysis."""

    with TestSessionLocal() as db:
        analysis = db.get(
            Analysis,
            analysis_id,
        )

        assert analysis is not None

        analysis.detections.append(
            Detection(
                rule_id="BEC-001",
                rule_name="Lookalike Domain",
                severity="high",
                matched=True,
                risk_score=50,
                indicators=[
                    "supplier-example.com"
                ],
                details={
                    "known_domain": "supplier.com",
                },
            )
        )

        db.commit()


def test_get_analysis_returns_persisted_analysis() -> None:
    """Return a persisted analysis by ID."""

    analysis_id = _create_analysis(
        subject="Retrieve this analysis",
        risk_score=50,
    )

    response = client.get(
        f"/analyses/{analysis_id}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == analysis_id
    assert data["sender_email"] == (
        "bob@supplier.com"
    )
    assert data["subject"] == (
        "Retrieve this analysis"
    )
    assert data["risk_score"] == 50
    assert data["known_domain"] == (
        "supplier.com"
    )
    assert "analyzed_at" in data


def test_get_analysis_returns_email_sent_at() -> None:
    """Return the original email timestamp with a persisted analysis."""

    email_sent_at = datetime(
        2026,
        9,
        23,
        10,
        30,
        tzinfo=timezone.utc,
    )

    analysis_id = _create_analysis(
        email_sent_at=email_sent_at,
    )

    response = client.get(
        f"/analyses/{analysis_id}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["email_sent_at"] == (
        "2026-09-23T10:30:00"
    )


def test_get_analysis_returns_detections() -> None:
    """Return persisted detections with an analysis."""

    analysis_id = _create_analysis(
        sender_email="attacker@supplier-example.com",
        subject="Suspicious request",
        risk_score=50,
    )

    _add_detection(analysis_id)

    response = client.get(
        f"/analyses/{analysis_id}"
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data["detections"]) == 1

    detection = data["detections"][0]

    assert detection["rule_id"] == "BEC-001"
    assert detection["rule_name"] == (
        "Lookalike Domain"
    )
    assert detection["severity"] == "high"
    assert detection["matched"] is True
    assert detection["risk_score"] == 50


def test_get_analysis_returns_404_for_unknown_id() -> None:
    """Return 404 when the requested analysis does not exist."""

    response = client.get(
        "/analyses/999999"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Analysis 999999 not found."
    )


def test_get_analysis_rejects_invalid_id() -> None:
    """Reject analysis IDs less than one."""

    response = client.get(
        "/analyses/0"
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "analysis_id must be greater than 0."
    )


def test_list_analyses_returns_recent_first() -> None:
    """Return persisted analyses from newest to oldest."""

    oldest_id = _create_analysis(
        sender_email="old@example.com",
        subject="Old analysis",
        analyzed_at=datetime(
            2026,
            9,
            25,
            10,
            0,
            tzinfo=timezone.utc,
        ),
    )

    newest_id = _create_analysis(
        sender_email="new@example.com",
        subject="New analysis",
        analyzed_at=datetime(
            2026,
            9,
            25,
            12,
            0,
            tzinfo=timezone.utc,
        ),
    )

    response = client.get(
        "/analyses"
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 2
    assert data[0]["id"] == newest_id
    assert data[1]["id"] == oldest_id

    assert data[0]["subject"] == (
        "New analysis"
    )
    assert data[1]["subject"] == (
        "Old analysis"
    )


def test_list_analyses_returns_email_sent_at() -> None:
    """Return the original email timestamp in analysis summaries."""

    oldest_email_sent_at = datetime(
        2026,
        9,
        23,
        9,
        30,
        tzinfo=timezone.utc,
    )

    newest_email_sent_at = datetime(
        2026,
        9,
        23,
        10,
        30,
        tzinfo=timezone.utc,
    )

    oldest_id = _create_analysis(
        sender_email="old@example.com",
        subject="Old analysis",
        email_sent_at=oldest_email_sent_at,
    )

    newest_id = _create_analysis(
        sender_email="new@example.com",
        subject="New analysis",
        email_sent_at=newest_email_sent_at,
    )

    response = client.get(
        "/analyses"
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 2

    results_by_id = {
        item["id"]: item
        for item in data
    }

    assert results_by_id[oldest_id]["email_sent_at"] == (
        "2026-09-23T09:30:00"
    )
    assert results_by_id[newest_id]["email_sent_at"] == (
        "2026-09-23T10:30:00"
    )


def test_list_analyses_respects_limit() -> None:
    """Limit the number of returned analyses."""

    for index in range(3):
        _create_analysis(
            sender_email=f"user{index}@example.com",
            subject=f"Analysis {index}",
        )

    response = client.get(
        "/analyses?limit=2"
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 2


@pytest.mark.parametrize(
    "limit",
    [
        0,
        101,
    ],
)
def test_list_analyses_rejects_invalid_limit(
    limit: int,
) -> None:
    """Reject limits outside the supported range."""

    response = client.get(
        f"/analyses?limit={limit}"
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "limit must be between 1 and 100."
    )
