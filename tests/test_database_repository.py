"""Tests for the database analysis repository."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from src.database.models import Analysis, Base, Detection
from src.database.repository import AnalysisRepository


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


repository = AnalysisRepository()


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
    db: Session,
    *,
    sender_email: str = "bob@supplier.com",
    subject: str = "Invoice update",
    risk_score: int = 0,
) -> Analysis:
    """Create and persist a test analysis."""

    analysis = Analysis(
        analyzed_at=datetime.now(timezone.utc),
        email_message_id="<test-message@example.com>",
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


def test_get_analysis_returns_persisted_analysis() -> None:
    """Retrieve an existing analysis by ID."""

    with TestSessionLocal() as db:
        analysis = _create_analysis(
            db,
            subject="Retrieve this analysis",
        )

        result = repository.get_analysis(
            db,
            analysis.id,
        )

        assert result is not None
        assert result["id"] == analysis.id
        assert result["sender_email"] == (
            "bob@supplier.com"
        )
        assert result["subject"] == (
            "Retrieve this analysis"
        )
        assert result["risk_score"] == 0


def test_get_analysis_returns_persisted_detections() -> None:
    """Retrieve detections belonging to an analysis."""

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

        result = repository.get_analysis(
            db,
            analysis.id,
        )

        assert result is not None
        assert len(result["detections"]) == 1

        detection = result["detections"][0]

        assert detection["rule_id"] == "BEC-001"
        assert detection["rule_name"] == (
            "Lookalike Domain"
        )
        assert detection["severity"] == "high"
        assert detection["matched"] is True
        assert detection["risk_score"] == 50
        assert detection["indicators"] == [
            "supplier-example.com"
        ]


def test_get_analysis_returns_none_for_unknown_id() -> None:
    """Return None when an analysis does not exist."""

    with TestSessionLocal() as db:
        result = repository.get_analysis(
            db,
            999999,
        )

        assert result is None


def test_list_analyses_returns_recent_analyses_first() -> None:
    """Return analyses ordered from newest to oldest."""

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

        results = repository.list_analyses(
            db,
        )

        assert len(results) == 2
        assert results[0]["id"] == newest.id
        assert results[1]["id"] == oldest.id


def test_list_analyses_respects_limit() -> None:
    """Limit the number of returned analyses."""

    with TestSessionLocal() as db:
        for index in range(3):
            _create_analysis(
                db,
                sender_email=f"user{index}@example.com",
                subject=f"Analysis {index}",
            )

        results = repository.list_analyses(
            db,
            limit=2,
        )

        assert len(results) == 2
