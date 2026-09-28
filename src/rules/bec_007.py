"""BEC-007: Behavioral Communication Anomaly detection."""

from __future__ import annotations

from datetime import datetime
from email.utils import parsedate_to_datetime
from statistics import median
from typing import Any

from src.engine.detection_context import DetectionContext
from src.engine.detection_rule import DetectionRule


class BehavioralCommunicationAnomalyRule(DetectionRule):
    """Detect unusual communication timing against known baselines."""

    rule_id = "BEC-007"
    rule_name = "Behavioral Communication Anomaly"
    severity = "MEDIUM"
    MIN_HISTORICAL_OBSERVATIONS = 3
    MIN_FREQUENCY_INTERVAL_MINUTES = 1
    FREQUENCY_ANOMALY_RATIO = 0.25
    RECIPIENT_FREQUENCY_THRESHOLD = 0.10

    def evaluate(
        self,
        context: DetectionContext,
    ) -> dict[str, Any]:
        """Evaluate message timing, recipient behavior, and frequency."""

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

        historical_hours = self._extract_historical_hours(
            context.historical_observations
        )

        historical_hour_range = self._build_historical_hour_range(
            historical_hours
        )

        historical_recipients = (
            self._extract_historical_recipients(
                context.historical_observations
            )
        )

        unusual_recipients = self._find_unusual_recipients(
            context.recipients,
            historical_recipients,
            context.historical_observations,
        )

        historical_recipient_frequencies = (
            self._build_historical_recipient_frequencies(
                context.historical_observations
            )
        )

        infrequent_recipients = (
            self._find_infrequent_recipients(
                context.recipients,
                historical_recipient_frequencies,
            )
        )

        historical_timestamps = (
            self._extract_historical_timestamps(
                context.historical_observations
            )
        )

        historical_frequency_interval = (
            self._build_historical_frequency_interval(
                historical_timestamps
            )
        )

        indicators: list[str] = []

        parsed_date = self._parse_date(email_date)

        if parsed_date is None:
            if unusual_recipients:
                indicators.append(
                    "Message sent to a previously unseen recipient"
                )

            if infrequent_recipients:
                indicators.append(
                    "Message sent to a historically infrequent recipient"
                )

            return self._build_result(
                matched=bool(indicators),
                indicators=indicators,
                observed_hour=None,
                typical_hours=typical_hours,
                observed_weekday=None,
                typical_days=typical_days,
                observed_timezone_offset=None,
                typical_timezone_offsets=typical_timezone_offsets,
                historical_hours=historical_hours,
                historical_hour_range=historical_hour_range,
                historical_recipients=historical_recipients,
                unusual_recipients=unusual_recipients,
                historical_recipient_frequencies=(
                    historical_recipient_frequencies
                ),
                infrequent_recipients=infrequent_recipients,
                historical_frequency_interval=(
                    historical_frequency_interval
                ),
                current_frequency_interval=None,
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

        if (
            historical_hour_range is not None
            and (
                observed_hour < historical_hour_range[0]
                or observed_hour > historical_hour_range[1]
            )
        ):
            indicators.append(
                "Message sent outside historically observed communication hours"
            )

        if unusual_recipients:
            indicators.append(
                "Message sent to a previously unseen recipient"
            )

        if infrequent_recipients:
            indicators.append(
                "Message sent to a historically infrequent recipient"
            )

        current_frequency_interval = (
            self._calculate_current_frequency_interval(
                parsed_date,
                historical_timestamps,
            )
        )

        if self._is_frequency_anomaly(
            current_frequency_interval,
            historical_frequency_interval,
        ):
            indicators.append(
                "Message sent at an unusually high communication frequency"
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
            historical_hours=historical_hours,
            historical_hour_range=historical_hour_range,
            historical_recipients=historical_recipients,
            unusual_recipients=unusual_recipients,
            historical_recipient_frequencies=(
                historical_recipient_frequencies
            ),
            infrequent_recipients=infrequent_recipients,
            historical_frequency_interval=(
                historical_frequency_interval
            ),
            current_frequency_interval=(
                current_frequency_interval
            ),
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

    @classmethod
    def _extract_historical_hours(
        cls,
        observations: list[dict[str, Any]],
    ) -> list[int]:
        """Extract valid local sending hours from historical observations."""

        historical_hours: list[int] = []

        for observation in observations:
            email_sent_at = observation.get(
                "email_sent_at"
            )

            if isinstance(email_sent_at, datetime):
                historical_hours.append(
                    email_sent_at.hour
                )
                continue

            if isinstance(email_sent_at, str):
                parsed_timestamp = cls._parse_historical_timestamp(
                    email_sent_at
                )

                if parsed_timestamp is not None:
                    historical_hours.append(
                        parsed_timestamp.hour
                    )

        return historical_hours

    @classmethod
    def _extract_historical_recipients(
        cls,
        observations: list[dict[str, Any]],
    ) -> set[str]:
        """Extract recipients observed across qualifying sender history."""

        if len(observations) < cls.MIN_HISTORICAL_OBSERVATIONS:
            return set()

        historical_recipients: set[str] = set()

        valid_observations = 0

        for observation in observations:
            if not isinstance(observation, dict):
                continue

            result = observation.get("result")

            if not isinstance(result, dict):
                continue

            email = result.get("email")

            if not isinstance(email, dict):
                continue

            to_recipients = cls._normalize_recipients(
                email.get("to", [])
            )

            cc_recipients = cls._normalize_recipients(
                email.get("cc", [])
            )

            observation_recipients = (
                to_recipients + cc_recipients
            )

            if not observation_recipients:
                continue

            valid_observations += 1
            historical_recipients.update(
                observation_recipients
            )

        if valid_observations < cls.MIN_HISTORICAL_OBSERVATIONS:
            return set()

        return historical_recipients

    @classmethod
    def _build_historical_recipient_frequencies(
        cls,
        observations: list[dict[str, Any]],
    ) -> dict[str, float]:
        """Build historical recipient frequencies."""

        if len(observations) < cls.MIN_HISTORICAL_OBSERVATIONS:
            return {}

        recipient_counts: dict[str, int] = {}
        valid_observations = 0

        for observation in observations:
            if not isinstance(observation, dict):
                continue

            result = observation.get("result")

            if not isinstance(result, dict):
                continue

            email = result.get("email")

            if not isinstance(email, dict):
                continue

            recipients = (
                cls._normalize_recipients(
                    email.get("to", [])
                )
                + cls._normalize_recipients(
                    email.get("cc", [])
                )
            )

            if not recipients:
                continue

            valid_observations += 1

            for recipient in set(recipients):
                recipient_counts[recipient] = (
                    recipient_counts.get(recipient, 0) + 1
                )

        if valid_observations < cls.MIN_HISTORICAL_OBSERVATIONS:
            return {}

        return {
            recipient: count / valid_observations
            for recipient, count in recipient_counts.items()
        }

    @classmethod
    def _find_unusual_recipients(
        cls,
        current_recipients: list[str],
        historical_recipients: set[str],
        observations: list[dict[str, Any]],
    ) -> list[str]:
        """Find current recipients absent from sufficient sender history."""

        if len(observations) < cls.MIN_HISTORICAL_OBSERVATIONS:
            return []

        if not historical_recipients:
            return []

        normalized_current_recipients = cls._normalize_recipients(
            current_recipients
        )

        return [
            recipient
            for recipient in normalized_current_recipients
            if recipient not in historical_recipients
        ]

    @classmethod
    def _find_infrequent_recipients(
        cls,
        current_recipients: list[str],
        historical_frequencies: dict[str, float],
    ) -> list[str]:
        """Find recipients with unusually low historical frequency."""

        if not historical_frequencies:
            return []

        normalized_current_recipients = cls._normalize_recipients(
            current_recipients
        )

        return [
            recipient
            for recipient in normalized_current_recipients
            if (
                recipient in historical_frequencies
                and historical_frequencies[recipient]
                <= cls.RECIPIENT_FREQUENCY_THRESHOLD
            )
        ]

    @staticmethod
    def _normalize_recipients(
        values: Any,
    ) -> list[str]:
        """Return normalized recipient email addresses from a value."""

        if not isinstance(values, list):
            return []

        normalized: list[str] = []

        for value in values:
            if not isinstance(value, str):
                continue

            recipient = value.strip().lower()

            if recipient and recipient not in normalized:
                normalized.append(recipient)

        return normalized

    @staticmethod
    def _parse_historical_timestamp(
        timestamp: str,
    ) -> datetime | None:
        """Parse a persisted historical email timestamp."""

        if not timestamp:
            return None

        try:
            parsed_timestamp = datetime.fromisoformat(
                timestamp
            )
        except (TypeError, ValueError):
            return None

        if not isinstance(parsed_timestamp, datetime):
            return None

        return parsed_timestamp

    @classmethod
    def _extract_historical_timestamps(
        cls,
        observations: list[dict[str, Any]],
    ) -> list[datetime]:
        """Extract valid historical email timestamps."""

        historical_timestamps: list[datetime] = []

        for observation in observations:
            if not isinstance(observation, dict):
                continue

            email_sent_at = observation.get(
                "email_sent_at"
            )

            if isinstance(email_sent_at, datetime):
                historical_timestamps.append(
                    email_sent_at
                )
                continue

            if isinstance(email_sent_at, str):
                parsed_timestamp = cls._parse_historical_timestamp(
                    email_sent_at
                )

                if parsed_timestamp is not None:
                    historical_timestamps.append(
                        parsed_timestamp
                    )

        return sorted(
            historical_timestamps
        )

    @classmethod
    def _build_historical_frequency_interval(
        cls,
        timestamps: list[datetime],
    ) -> float | None:
        """Build the median historical interval between messages."""

        if len(timestamps) < cls.MIN_HISTORICAL_OBSERVATIONS:
            return None

        intervals: list[float] = []

        for previous, current in zip(
            timestamps,
            timestamps[1:],
        ):
            interval_minutes = (
                current - previous
            ).total_seconds() / 60

            if (
                interval_minutes
                >= cls.MIN_FREQUENCY_INTERVAL_MINUTES
            ):
                intervals.append(
                    interval_minutes
                )

        if len(intervals) < 2:
            return None

        return float(
            median(intervals)
        )

    @classmethod
    def _calculate_current_frequency_interval(
        cls,
        parsed_date: datetime,
        historical_timestamps: list[datetime],
    ) -> float | None:
        """Calculate the interval since the most recent historical message."""

        if not historical_timestamps:
            return None

        previous_timestamp = historical_timestamps[-1]

        if (
            parsed_date.tzinfo is not None
            and previous_timestamp.tzinfo is None
        ):
            previous_timestamp = previous_timestamp.replace(
                tzinfo=parsed_date.tzinfo
            )

        elif (
            parsed_date.tzinfo is None
            and previous_timestamp.tzinfo is not None
        ):
            parsed_date = parsed_date.replace(
                tzinfo=previous_timestamp.tzinfo
            )

        interval_minutes = (
            parsed_date - previous_timestamp
        ).total_seconds() / 60

        if (
            interval_minutes
            < cls.MIN_FREQUENCY_INTERVAL_MINUTES
        ):
            return None

        return interval_minutes

    @classmethod
    def _is_frequency_anomaly(
        cls,
        current_interval: float | None,
        historical_interval: float | None,
    ) -> bool:
        """Determine whether current sending frequency is unusually high."""

        if (
            current_interval is None
            or historical_interval is None
            or historical_interval <= 0
        ):
            return False

        return (
            current_interval
            < historical_interval
            * cls.FREQUENCY_ANOMALY_RATIO
        )

    @classmethod
    def _build_historical_hour_range(
        cls,
        historical_hours: list[int],
    ) -> tuple[int, int] | None:
        """Build a historical observed-hour range when enough data exists."""

        if len(historical_hours) < cls.MIN_HISTORICAL_OBSERVATIONS:
            return None

        return (
            min(historical_hours),
            max(historical_hours),
        )

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
            if isinstance(value, int)
            and not isinstance(value, bool)
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
            if isinstance(value, int)
            and not isinstance(value, bool)
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
            if isinstance(value, int)
            and not isinstance(value, bool)
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
        historical_hours: list[int],
        historical_hour_range: tuple[int, int] | None,
        historical_recipients: set[str],
        unusual_recipients: list[str],
        historical_recipient_frequencies: dict[str, float],
        infrequent_recipients: list[str],
        historical_frequency_interval: float | None,
        current_frequency_interval: float | None,
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
            "historical_hours": historical_hours,
            "historical_hour_range": historical_hour_range,
            "historical_recipients": sorted(
                historical_recipients
            ),
            "unusual_recipients": unusual_recipients,
            "historical_recipient_frequencies": (
                historical_recipient_frequencies
            ),
            "infrequent_recipients": infrequent_recipients,
            "historical_frequency_interval": (
                historical_frequency_interval
            ),
            "current_frequency_interval": (
                current_frequency_interval
            ),
        }
