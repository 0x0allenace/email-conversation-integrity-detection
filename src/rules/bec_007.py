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

        typical_hours = self._normalize_hours(
            context.known_behavior.get(
                "typical_hours",
                [],
            )
        )

        typical_days = self._normalize_days(
            context.known_behavior.get(
                "typical_days",
                [],
            )
        )

        typical_timezone_offsets = self._normalize_timezone_offsets(
            context.known_behavior.get(
                "typical_timezone_offsets",
                [],
            )
        )

        indicators: list[str] = []

        parsed_date = self._parse_date(email_date)

        if parsed_date is None:
            return self._build_result(
                matched=False,
                indicators=indicators,
                observed_hour=None,
                typical_hours=typical_hours,
                observed_weekday=None,
                typical_days=typical_days,
                observed_timezone_offset=None,
                typical_timezone_offsets=typical_timezone_offsets,
            )

        observed_hour = parsed_date.hour
        observed_weekday = parsed_date.weekday()
        observed_timezone_offset = self._extract_timezone_offset(
            parsed_date
        )

        if typical_hours and observed_hour not in typical_hours:
            indicators.append(
                "Message sent outside established communication hours"
            )

        if typical_days and observed_weekday not in typical_days:
            indicators.append(
                "Message sent outside established communication days"
            )

        if (
            typical_timezone_offsets
            and observed_timezone_offset is not None
            and observed_timezone_offset not in typical_timezone_offsets
        ):
            indicators.append(
                "Message sent from an unexpected timezone offset"
            )

        matched = bool(indicators)

        return self._build_result(
            matched=matched,
            indicators=indicators,
            observed_hour=observed_hour,
            typical_hours=typical_hours,
            observed_weekday=observed_weekday,
            typical_days=typical_days,
            observed_timezone_offset=observed_timezone_offset,
            typical_timezone_offsets=typical_timezone_offsets,
        )

    @staticmethod
    def _parse_date(
        email_date: str,
    ) -> datetime | None:
        """Parse an email Date header into a datetime value."""

        if not email_date:
            return None

        try:
            parsed_date = parsedate_to_datetime(email_date)
        except (TypeError, ValueError, IndexError):
            return None

        if not isinstance(parsed_date, datetime):
            return None

        return parsed_date

    @staticmethod
    def _extract_hour(
        email_date: str,
    ) -> int | None:
        """Extract the local sending hour from an email Date header."""

        parsed_date = BehavioralCommunicationAnomalyRule._parse_date(
            email_date
        )

        if parsed_date is None:
            return None

        return parsed_date.hour

    @staticmethod
    def _extract_timezone_offset(
        parsed_date: datetime,
    ) -> int | None:
        """Extract the UTC offset from a parsed email Date header."""

        utc_offset = parsed_date.utcoffset()

        if utc_offset is None:
            return None

        return int(utc_offset.total_seconds() // 60)

    @staticmethod
    def _normalize_hours(
        values: Any,
    ) -> list[int]:
        """Return valid communication hours from a baseline."""

        if not isinstance(values, list):
            return []

        return [
            value
            for value in values
            if isinstance(value, int) and not isinstance(value, bool)
            and 0 <= value <= 23
        ]

    @staticmethod
    def _normalize_days(
        values: Any,
    ) -> list[int]:
        """Return valid weekday values from a baseline."""

        if not isinstance(values, list):
            return []

        return [
            value
            for value in values
            if isinstance(value, int) and not isinstance(value, bool)
            and 0 <= value <= 6
        ]

    @staticmethod
    def _normalize_timezone_offsets(
        values: Any,
    ) -> list[int]:
        """Return valid UTC-minute offsets from a baseline."""

        if not isinstance(values, list):
            return []

        return [
            value
            for value in values
            if isinstance(value, int) and not isinstance(value, bool)
            and -840 <= value <= 840
        ]

    def _build_result(
        self,
        *,
        matched: bool,
        indicators: list[str],
        observed_hour: int | None,
        typical_hours: list[int],
        observed_weekday: int | None,
        typical_days: list[int],
        observed_timezone_offset: int | None,
        typical_timezone_offsets: list[int],
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
            "observed_weekday": observed_weekday,
            "typical_days": typical_days,
            "observed_timezone_offset": observed_timezone_offset,
            "typical_timezone_offsets": typical_timezone_offsets,
        }
