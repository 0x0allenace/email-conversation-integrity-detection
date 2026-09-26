"""Database repository for Email Conversation Integrity Detection."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.database.models import Analysis


class AnalysisRepository:
    """Provide database operations for persisted email analyses."""

    def get_analysis(
        self,
        db: Session,
        analysis_id: int,
    ) -> dict[str, Any] | None:
        """Retrieve one persisted analysis by ID."""

        analysis = db.get(
            Analysis,
            analysis_id,
        )

        if analysis is None:
            return None

        return self._to_dict(
            analysis
        )

    def list_analyses(
        self,
        db: Session,
        *,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Retrieve recent persisted analyses."""

        statement = (
            select(Analysis)
            .order_by(
                Analysis.analyzed_at.desc()
            )
            .limit(limit)
        )

        analyses = db.scalars(
            statement
        ).all()

        return [
            self._to_dict(analysis)
            for analysis in analyses
        ]

    @staticmethod
    def _to_dict(
        analysis: Analysis,
    ) -> dict[str, Any]:
        """Convert a database analysis into a serializable dictionary."""

        return {
            "id": analysis.id,
            "analyzed_at": analysis.analyzed_at,
            "email_sent_at": analysis.email_sent_at,
            "email_message_id": analysis.email_message_id,
            "sender_email": analysis.sender_email,
            "sender_domain": analysis.sender_domain,
            "subject": analysis.subject,
            "known_domain": analysis.known_domain,
            "known_display_name": analysis.known_display_name,
            "risk_score": analysis.risk_score,
            "result": analysis.result,
            "detections": [
                {
                    "id": detection.id,
                    "rule_id": detection.rule_id,
                    "rule_name": detection.rule_name,
                    "severity": detection.severity,
                    "matched": detection.matched,
                    "risk_score": detection.risk_score,
                    "indicators": detection.indicators,
                    "details": detection.details,
                }
                for detection in analysis.detections
            ],
        }
