"""Detection engine for Email Conversation Integrity Detection."""

from __future__ import annotations

from typing import Any

from src.authentication.authentication_analyzer import (
    AuthenticationAnalyzer,
)
from src.conversation.participant_analyzer import ParticipantAnalyzer
from src.detection.result import DetectionResult
from src.engine.detection_context import DetectionContext
from src.engine.detection_rule import DetectionRule
from src.engine.rule_registry import RuleRegistry
from src.identity.identity_analyzer import IdentityAnalyzer
from src.infrastructure.infrastructure_analyzer import (
    InfrastructureAnalyzer,
)
from src.parser.email_parser import EmailParser
from src.scoring.risk_scorer import RiskScorer


class DetectionEngine:
    """Coordinate email parsing, analysis, detection, and scoring."""

    def __init__(self) -> None:
        """Initialize the detection engine."""

        self.parser = EmailParser()
        self.identity_analyzer = IdentityAnalyzer()
        self.participant_analyzer = ParticipantAnalyzer()
        self.authentication_analyzer = AuthenticationAnalyzer()
        self.infrastructure_analyzer = InfrastructureAnalyzer()

        self.rule_registry = RuleRegistry()
        self.rules: list[DetectionRule] = (
            self.rule_registry.get_rules()
        )

        self.risk_scorer = RiskScorer()

    def analyze(
        self,
        file_path: str,
        known_domain: str,
        known_display_name: str,
        known_participants: list[str],
        known_hosts: list[str],
        known_ip_addresses: list[str],
        known_behavior: dict[str, Any] | None = None,
        historical_observations: list[dict[str, Any]] | None = None,
        email_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Analyze an email and return detection results."""

        if email_data is None:
            email_data = self.parser.parse_file(
                file_path
            )

        identity = self.identity_analyzer.analyze(
            email_data
        )

        current_participants = (
            self.participant_analyzer.extract_participants(
                email_data
            )
        )

        current_recipients = (
            email_data.get("to", [])
            + email_data.get("cc", [])
        )

        authentication_results = (
            self.authentication_analyzer.analyze(
                email_data
            )
        )

        infrastructure = (
            self.infrastructure_analyzer.analyze(
                email_data
            )
        )

        context = DetectionContext(
            email_data=email_data,
            identity=identity,
            participants=current_participants,
            recipients=current_recipients,
            attachments=email_data.get("attachments", []),
            authentication=authentication_results,
            infrastructure=infrastructure,
            known_domain=known_domain,
            known_display_name=known_display_name,
            known_participants=known_participants,
            known_hosts=known_hosts,
            known_ip_addresses=known_ip_addresses,
            known_behavior=known_behavior or {},
            historical_observations=historical_observations or [],
        )

        detection_results: list[dict[str, Any]] = []

        authentication_failure = any(
            result in {
                "fail",
                "softfail",
                "permerror",
                "temperror",
            }
            for result in authentication_results.values()
        )

        for rule in self.rules:
            detection = rule.evaluate(
                context=context,
            )

            risk_score = self.risk_scorer.score_detection(
                detection=detection,
                authentication_failure=authentication_failure,
            )

            details = {
                key: value
                for key, value in detection.items()
                if key
                not in {
                    "rule_id",
                    "rule_name",
                    "severity",
                    "matched",
                    "indicators",
                }
            }

            result = DetectionResult(
                rule_id=detection["rule_id"],
                rule_name=detection["rule_name"],
                severity=detection["severity"],
                matched=detection["matched"],
                risk_score=risk_score,
                indicators=detection["indicators"],
                details=details,
            )

            detection_results.append(
                result.to_dict()
            )

        return {
            "email": email_data,
            "identity": identity,
            "participants": current_participants,
            "recipients": current_recipients,
            "authentication": authentication_results,
            "infrastructure": infrastructure,
            "detections": detection_results,
        }
