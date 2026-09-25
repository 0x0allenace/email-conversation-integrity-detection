"""BEC-007: Behavioral Communication Anomaly detection."""

from __future__ import annotations

from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any

from src.engine.detection_context import DetectionContext
from src.engine.detection_rule import DetectionRule


class BehavioralCommunicationAnomalyRule(DetectionRule):
    """Detect unusual communication timing against a known baseline."""

    rule_id = "BEC-007"
    rule_name = "Behavioral Communication Anomaly"
    severity = "MEDIUM"

    def evaluate(
        self,
        context: DetectionContext,
    ) -> dict[str, Any]:
        """Evaluate message timing against established behavior."""

        email_date = context.email_data.get("date", "")

        typical_hours = context.known_behavior.get(
            "typical_hours",
            [],
        )

        indicators: list[str] = []

        observed_hour = self._extract_hour(email_date)

        if observed_hour is None:
            return self._build_result(
                matched=False,
                indicators=indicators,
                observed_hour=None,
                typical_hours=typical_hours,
            )

        if not typical_hours:
            return self._build_result(
                matched=False,
                indicators=indicators,
                observed_hour=observed_hour,
                typical_hours=typical_hours,
            )

        if observed_hour not in typical_hours:
            indicators.append(
                "Message sent outside established communication hours"
            )

        matched = bool(indicators)

        return self._build_result(
            matched=matched,
            indicators=indicators,
            observed_hour=observed_hour,
            typical_hours=typical_hours,
        )

    @staticmethod
    def _extract_hour(
        email_date: str,
    ) -> int | None:
        """Extract the local sending hour from an email Date header."""

        if not email_date:
            return None

        try:
            parsed_date = parsedate_to_datetime(email_date)
        except (TypeError, ValueError, IndexError):
            return None

        if not isinstance(parsed_date, datetime):
            return None

        return parsed_date.hour

    def _build_result(
        self,
        *,
        matched: bool,
        indicators: list[str],
        observed_hour: int | None,
        typical_hours: list[int],
    ) -> dict[str, Any]:
        """Build the standardized BEC-007 detection result."""

        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched": matched,
            "indicators": indicators,
            "observed_hour": observed_hour,
            "typical_hours": typical_hours,
        }
