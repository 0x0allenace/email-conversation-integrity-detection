"""API service layer for Email Conversation Integrity Detection."""

from __future__ import annotations

from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any

from sqlalchemy.orm import Session

from src.database.models import Analysis, Detection
from src.database.repository import AnalysisRepository
from src.engine.detection_engine import DetectionEngine
from src.identity.identity_analyzer import IdentityAnalyzer
from src.integrations.siem.service import SIEMService
from src.parser.email_parser import EmailParser


class AnalysisService:
    """Provide an API-facing interface to the detection engine."""

    def __init__(
        self,
        detection_engine: DetectionEngine | None = None,
        repository: AnalysisRepository | None = None,
        siem_service: SIEMService | None = None,
    ) -> None:
        """Initialize the analysis service."""

        self.detection_engine = (
            detection_engine
            if detection_engine is not None
            else DetectionEngine()
        )

        self.repository = (
            repository
            if repository is not None
            else AnalysisRepository()
        )

        self.email_parser = EmailParser()
        self.identity_analyzer = IdentityAnalyzer()

        self.siem_service = siem_service

    def analyze_email(
        self,
        *,
        email_file: str,
        known_domain: str,
        known_display_name: str,
        known_participants: list[str],
        known_hosts: list[str],
        known_ip_addresses: list[str],
        known_behavior: dict[str, Any],
        db: Session | None = None,
    ) -> dict[str, Any]:
        """Analyze an email and optionally persist the analysis result."""

        email_data = self.email_parser.parse_file(
            email_file
        )

        identity_data = self.identity_analyzer.analyze(
            email_data
        )

        historical_observations: list[dict[str, Any]] = []

        if db is not None:
            sender_email = identity_data.get(
                "email_address"
            )

            if sender_email:
                historical_observations = (
                    self.repository.list_sender_history(
                        db,
                        sender_email=sender_email,
                    )
                )

        result = self.detection_engine.analyze(
            file_path=email_file,
            known_domain=known_domain,
            known_display_name=known_display_name,
            known_participants=known_participants,
            known_hosts=known_hosts,
            known_ip_addresses=known_ip_addresses,
            known_behavior=known_behavior,
            historical_observations=historical_observations,
            email_data=email_data,
        )

        if db is None:
            self._dispatch_siem_events(result)

            return result

        email_data = result["email"]
        identity_data = result["identity"]
        detections_data = result["detections"]

        email_sent_at = self._parse_email_date(
            email_data.get("date", "")
        )

        analysis = Analysis(
            email_sent_at=email_sent_at,
            email_message_id=email_data.get("message_id"),
            sender_email=identity_data["email_address"],
            sender_domain=identity_data["domain"],
            subject=email_data.get("subject"),
            known_domain=known_domain,
            known_display_name=known_display_name,
            risk_score=sum(
                detection["risk_score"]
                for detection in detections_data
                if detection["matched"]
            ),
            result=result,
        )

        for detection_data in detections_data:
            detection = Detection(
                rule_id=detection_data["rule_id"],
                rule_name=detection_data["rule_name"],
                severity=detection_data["severity"],
                matched=detection_data["matched"],
                risk_score=detection_data["risk_score"],
                indicators=detection_data.get(
                    "indicators",
                    [],
                ),
                details=detection_data.get(
                    "details",
                    {},
                ),
            )

            analysis.detections.append(
                detection
            )

        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        self._dispatch_siem_events(result)

        return result

    @staticmethod
    def _parse_email_date(
        email_date: str,
    ) -> datetime | None:
        """Parse an email Date header into a datetime value."""

        if not email_date:
            return None

        try:
            parsed_date = parsedate_to_datetime(
                email_date
            )
        except (TypeError, ValueError, IndexError):
            return None

        if not isinstance(parsed_date, datetime):
            return None

        return parsed_date

    def _dispatch_siem_events(
        self,
        result: dict[str, Any],
    ) -> None:
        """Dispatch matched detection events when SIEM is configured."""

        if self.siem_service is None:
            return

        self.siem_service.dispatch_detections(
            detections=result["detections"],
            email=result["email"],
            authentication=result.get(
                "authentication"
            ),
            infrastructure=result.get(
                "infrastructure"
            ),
            conversation=result.get(
                "conversation"
            ),
        )

    def get_analysis(
        self,
        *,
        db: Session,
        analysis_id: int,
    ) -> dict[str, Any] | None:
        """Retrieve one persisted analysis by ID."""

        return self.repository.get_analysis(
            db,
            analysis_id,
        )

    def list_analyses(
        self,
        *,
        db: Session,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Retrieve recent persisted analyses."""

        return self.repository.list_analyses(
            db,
            limit=limit,
        )
