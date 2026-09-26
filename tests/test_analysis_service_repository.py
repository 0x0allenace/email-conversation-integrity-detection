"""Tests for AnalysisService database retrieval operations."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.api.service import AnalysisService
from src.database.models import Analysis, Base, Detection


PROJECT_ROOT = Path(__file__).resolve().parents[1]

TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
)

TestSessionLocal = sessionmaker(
    bind=test_engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


service = AnalysisService()


def setup_module() -> None:
    """Create the test database schema."""

    Base.metadata.create_all(
        bind=test_engine,
    )


def teardown_module() -> None:
    """Remove the test database schema."""

    Base.metadata.drop_all(
        bind=test_engine,
    )

    test_engine.dispose()


def setup_function() -> None:
    """Reset database contents before each test."""

    Base.metadata.drop_all(
        bind=test_engine,
    )

    Base.metadata.create_all(
        bind=test_engine,
    )


def _create_analysis(
    db,
    *,
    sender_email: str = "bob@supplier.com",
    subject: str = "Invoice update",
    risk_score: int = 0,
) -> Analysis:
    """Create and persist a test analysis."""

    analysis = Analysis(
        analyzed_at=datetime.now(timezone.utc),
        email_message_id="<service-test@example.com>",
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

    return analysis


def test_get_analysis_returns_analysis() -> None:
    """Retrieve an existing analysis through the service."""

    with TestSessionLocal() as db:
        analysis = _create_analysis(
            db,
            subject="Service retrieval test",
            risk_score=50,
        )

        result = service.get_analysis(
            db=db,
            analysis_id=analysis.id,
        )

        assert result is not None
        assert result["id"] == analysis.id
        assert result["sender_email"] == (
            "bob@supplier.com"
        )
        assert result["subject"] == (
            "Service retrieval test"
        )
        assert result["risk_score"] == 50


def test_analysis_persists_email_sent_at() -> None:
    """Persist and retrieve the original email sent timestamp."""

    email_sent_at = datetime(
        2026,
        9,
        23,
        10,
        30,
        tzinfo=timezone.utc,
    )

    with TestSessionLocal() as db:
        analysis = Analysis(
            email_sent_at=email_sent_at,
            email_message_id="<timestamp-test@example.com>",
            sender_email="bob@supplier.com",
            sender_domain="supplier.com",
            subject="Timestamp persistence test",
            known_domain="supplier.com",
            known_display_name="Bob Supplier",
            risk_score=0,
            result={
                "email": {
                    "subject": "Timestamp persistence test",
                },
                "detections": [],
            },
        )

        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        assert analysis.email_sent_at is not None
        assert analysis.email_sent_at.replace(
            tzinfo=timezone.utc
        ) == email_sent_at


def test_analysis_service_persists_email_sent_at() -> None:
    """Persist the email Date header through AnalysisService."""

    email_file = (
        PROJECT_ROOT
        / "samples"
        / "legitimate"
        / "normal-conversation.eml"
    )

    known_participants = [
        "bob@supplier.com",
        "alice@company.com",
    ]

    known_hosts = [
        "mail.supplier.com",
        "relay.supplier.com",
    ]

    known_ip_addresses = [
        "192.0.2.10",
        "192.0.2.20",
    ]

    known_behavior = {
        "typical_hours": list(range(8, 18)),
    }

    with TestSessionLocal() as db:
        service.analyze_email(
            email_file=str(email_file),
            known_domain="supplier.com",
            known_display_name="Bob Supplier",
            known_participants=known_participants,
            known_hosts=known_hosts,
            known_ip_addresses=known_ip_addresses,
            known_behavior=known_behavior,
            db=db,
        )

        persisted_analysis = db.query(
            Analysis
        ).filter(
            Analysis.email_message_id
            == "<invoice-update-001@supplier.com>"
        ).one()

        assert persisted_analysis.email_sent_at is not None
        assert persisted_analysis.email_sent_at.year == 2026
        assert persisted_analysis.email_sent_at.month == 9
        assert persisted_analysis.email_sent_at.day == 23
        assert persisted_analysis.email_sent_at.hour == 10
        assert persisted_analysis.email_sent_at.minute == 30


def test_get_analysis_returns_detections() -> None:
    """Retrieve persisted detections through the service."""

    with TestSessionLocal() as db:
        analysis = _create_analysis(
            db,
            sender_email="attacker@supplier-example.com",
            subject="Suspicious request",
            risk_score=50,
        )

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

        result = service.get_analysis(
            db=db,
            analysis_id=analysis.id,
        )

        assert result is not None
        assert len(result["detections"]) == 1
        assert result["detections"][0]["rule_id"] == (
            "BEC-001"
        )


def test_get_analysis_returns_none_for_unknown_id() -> None:
    """Return None when the requested analysis does not exist."""

    with TestSessionLocal() as db:
        result = service.get_analysis(
            db=db,
            analysis_id=999999,
        )

        assert result is None


def test_list_analyses_returns_recent_first() -> None:
    """Retrieve recent analyses through the service."""

    with TestSessionLocal() as db:
        oldest = _create_analysis(
            db,
            sender_email="old@example.com",
            subject="Old analysis",
        )

        newest = _create_analysis(
            db,
            sender_email="new@example.com",
            subject="New analysis",
        )

        newest.analyzed_at = datetime(
            2026,
            9,
            25,
            12,
            0,
            tzinfo=timezone.utc,
        )

        oldest.analyzed_at = datetime(
            2026,
            9,
            25,
            10,
            0,
            tzinfo=timezone.utc,
        )

        db.commit()

        results = service.list_analyses(
            db=db,
        )

        assert len(results) == 2
        assert results[0]["id"] == newest.id
        assert results[1]["id"] == oldest.id


def test_list_analyses_respects_limit() -> None:
    """Limit the number of analyses returned by the service."""

    with TestSessionLocal() as db:
        for index in range(3):
            _create_analysis(
                db,
                sender_email=f"user{index}@example.com",
                subject=f"Analysis {index}",
            )

        results = service.list_analyses(
            db=db,
            limit=2,
        )

        assert len(results) == 2
