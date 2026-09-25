"""SQLAlchemy database models for Email Conversation Integrity Detection."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all database models."""


class Analysis(Base):
    """Store the result of an email analysis."""

    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    email_message_id: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    sender_email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
    )

    sender_domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    subject: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    known_domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    known_display_name: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    result: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )

    detections: Mapped[list["Detection"]] = relationship(
        back_populates="analysis",
        cascade="all, delete-orphan",
    )


class Detection(Base):
    """Store an individual detection result."""

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id"),
        nullable=False,
    )

    rule_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    rule_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    matched: Mapped[bool] = mapped_column(
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    indicators: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    details: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    analysis: Mapped["Analysis"] = relationship(
        back_populates="detections",
    )
