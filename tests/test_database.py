"""Tests for the database models."""

from __future__ import annotations

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from src.database.models import Analysis, Base, Detection


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


def setup_module() -> None:
    """Create the test database schema."""

    Base.metadata.create_all(
        bind=test_engine,
    )


def teardown_module() -> None:
    """Dispose of the test database engine."""

    Base.metadata.drop_all(
        bind=test_engine,
    )

    test_engine.dispose()


def test_database_tables_exist() -> None:
    """Create both expected database tables."""

    inspector = inspect(test_engine)

    tables = set(
        inspector.get_table_names()
    )

    assert "analyses" in tables
    assert "detections" in tables


def test_analysis_can_be_persisted() -> None:
    """Persist and retrieve an analysis record."""

    with TestSessionLocal() as db:
        analysis = Analysis(
            sender_email="bob@supplier.com",
            sender_domain="supplier.com",
            subject="Invoice update",
            known_domain="supplier.com",
            known_display_name="Bob Supplier",
            risk_score=0,
            result={
                "email": {
                    "subject": "Invoice update",
                },
                "detections": [],
            },
        )

        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        assert analysis.id is not None
        assert analysis.sender_email == "bob@supplier.com"
        assert analysis.sender_domain == "supplier.com"
        assert analysis.risk_score == 0


def test_detection_can_be_persisted_with_analysis() -> None:
    """Persist a detection associated with an analysis."""

    with TestSessionLocal() as db:
        analysis = Analysis(
            sender_email="attacker@supplier-example.com",
            sender_domain="supplier-example.com",
            subject="Urgent payment request",
            known_domain="supplier.com",
            known_display_name="Bob Supplier",
            risk_score=50,
            result={
                "detections": [
                    {
                        "rule_id": "BEC-001",
                    }
                ]
            },
        )

        detection = Detection(
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

        analysis.detections.append(detection)

        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        assert analysis.id is not None
        assert len(analysis.detections) == 1

        saved_detection = analysis.detections[0]

        assert saved_detection.id is not None
        assert saved_detection.analysis_id == analysis.id
        assert saved_detection.rule_id == "BEC-001"
        assert saved_detection.matched is True
        assert saved_detection.risk_score == 50


def test_analysis_detection_relationship() -> None:
    """Load detections through the analysis relationship."""

    with TestSessionLocal() as db:
        analysis = Analysis(
            sender_email="sender@example.com",
            sender_domain="example.com",
            subject="Test message",
            known_domain="example.com",
            known_display_name="Test Sender",
            risk_score=20,
            result={
                "detections": [],
            },
        )

        analysis.detections.append(
            Detection(
                rule_id="BEC-007",
                rule_name="Behavioral Communication Anomaly",
                severity="medium",
                matched=True,
                risk_score=20,
                indicators=[
                    "outside_typical_hours"
                ],
                details={
                    "observed_hour": 2,
                    "typical_hours": list(
                        range(8, 18)
                    ),
                },
            )
        )

        db.add(analysis)
        db.commit()

        analysis_id = analysis.id

    with TestSessionLocal() as db:
        saved_analysis = db.get(
            Analysis,
            analysis_id,
        )

        assert saved_analysis is not None
        assert len(saved_analysis.detections) == 1

        saved_detection = saved_analysis.detections[0]

        assert saved_detection.rule_id == "BEC-007"
        assert saved_detection.rule_name == (
            "Behavioral Communication Anomaly"
        )


def test_deleting_analysis_deletes_detections() -> None:
    """Cascade deletion removes detections belonging to an analysis."""

    with TestSessionLocal() as db:
        analysis = Analysis(
            sender_email="sender@example.com",
            sender_domain="example.com",
            subject="Cascade test",
            known_domain="example.com",
            known_display_name="Test Sender",
            risk_score=30,
            result={
                "detections": [],
            },
        )

        analysis.detections.append(
            Detection(
                rule_id="BEC-003",
                rule_name="Thread Participant Anomaly",
                severity="medium",
                matched=True,
                risk_score=30,
                indicators=[
                    "unexpected participant"
                ],
                details={},
            )
        )

        db.add(analysis)
        db.commit()

        analysis_id = analysis.id

        assert len(analysis.detections) == 1

        detection_id = analysis.detections[0].id

        db.delete(analysis)
        db.commit()

        assert db.get(
            Analysis,
            analysis_id,
        ) is None

        assert db.get(
            Detection,
            detection_id,
        ) is None
