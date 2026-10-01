"""BEC-007: Behavioral Communication Anomaly detection."""

from __future__ import annotations

from datetime import datetime
from email.utils import parsedate_to_datetime
from itertools import combinations
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
    RECIPIENT_RECENCY_ANOMALY_RATIO = 4.0
    RECIPIENT_FREQUENCY_THRESHOLD = 0.10
    RECIPIENT_COOCCURRENCE_THRESHOLD = 0.10
    RECIPIENT_ROLE_THRESHOLD = 0.10
    INDIVIDUAL_RECIPIENT_ROLE_THRESHOLD = 0.10
    RECIPIENT_TRANSITION_THRESHOLD = 0.10

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

        historical_recipient_cooccurrences = (
            self._build_historical_recipient_cooccurrences(
                context.historical_observations
            )
        )

        unusual_recipient_pairs = (
            self._find_unusual_recipient_pairs(
                context.recipients,
                historical_recipients,
                historical_recipient_cooccurrences,
            )
        )

        historical_recipient_role_frequencies = (
            self._build_historical_recipient_role_frequencies(
                context.historical_observations
            )
        )

        historical_individual_recipient_role_frequencies = (
            self._build_historical_individual_recipient_role_frequencies(
                context.historical_observations
            )
        )

        unusual_recipient_roles = (
            self._find_unusual_recipient_roles(
                context.email_data,
                historical_individual_recipient_role_frequencies,
            )
        )

        unusual_recipient_role_pairs = (
            self._find_unusual_recipient_role_pairs(
                context.email_data,
                historical_recipients,
                historical_recipient_cooccurrences,
                historical_recipient_role_frequencies,
            )
        )

        historical_recipient_group_frequencies = (
            self._build_historical_recipient_group_frequencies(
                context.historical_observations
            )
        )

        unusual_recipient_groups = (
            self._find_unusual_recipient_groups(
                context.recipients,
                historical_recipient_group_frequencies,
            )
        )

        historical_recipient_transition_frequencies = (
            self._build_historical_recipient_transition_frequencies(
                context.historical_observations
            )
        )

        current_recipient_transition = (
            self._calculate_current_recipient_transition(
                context.historical_observations,
                context.recipients,
            )
        )

        unusual_recipient_transitions = (
            self._find_unusual_recipient_transitions(
                historical_recipient_transition_frequencies,
                current_recipient_transition,
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

        historical_recipient_timestamps = (
            self._build_historical_recipient_timestamps(
                context.historical_observations
            )
        )

        historical_recipient_interval_statistics = (
            self._build_historical_recipient_interval_statistics(
                historical_recipient_timestamps
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

            if unusual_recipient_pairs:
                indicators.append(
                    "Message contains a historically unusual recipient relationship"
                )

            if unusual_recipient_role_pairs:
                indicators.append(
                    "Message contains a historically unusual recipient role relationship"
                )

            if unusual_recipient_roles:
                indicators.append(
                    "Message contains a historically unusual individual recipient role"
                )

            if unusual_recipient_groups:
                indicators.append(
                    "Message contains a historically unusual recipient group"
                )

            if unusual_recipient_transitions:
                indicators.append(
                    "Message follows an unusual recipient communication sequence"
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
                historical_recipient_cooccurrences=(
                    historical_recipient_cooccurrences
                ),
                unusual_recipient_pairs=(
                    unusual_recipient_pairs
                ),
                historical_recipient_role_frequencies=(
                    historical_recipient_role_frequencies
                ),
                historical_individual_recipient_role_frequencies=(
                    historical_individual_recipient_role_frequencies
                ),
                unusual_recipient_roles=(
                    unusual_recipient_roles
                ),
                unusual_recipient_role_pairs=(
                    unusual_recipient_role_pairs
                ),
                historical_recipient_group_frequencies=(
                    historical_recipient_group_frequencies
                ),
                unusual_recipient_groups=(
                    unusual_recipient_groups
                ),
                historical_recipient_transition_frequencies=(
                    historical_recipient_transition_frequencies
                ),
                current_recipient_transition=(
                    current_recipient_transition
                ),
                unusual_recipient_transitions=(
                    unusual_recipient_transitions
                ),
                historical_recipient_interval_statistics=(
                    historical_recipient_interval_statistics
                ),
                current_recipient_intervals={},
                unusual_recipient_recency=[],
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

        if unusual_recipient_pairs:
            indicators.append(
                "Message contains a historically unusual recipient relationship"
            )

        if unusual_recipient_role_pairs:
            indicators.append(
                "Message contains a historically unusual recipient role relationship"
            )

        if unusual_recipient_roles:
            indicators.append(
                "Message contains a historically unusual individual recipient role"
            )

        if unusual_recipient_groups:
            indicators.append(
                "Message contains a historically unusual recipient group"
            )

        if unusual_recipient_transitions:
            indicators.append(
                "Message follows an unusual recipient communication sequence"
            )

        current_recipient_intervals = (
            self._calculate_current_recipient_intervals(
                parsed_date,
                historical_recipient_timestamps,
                context.recipients,
            )
        )

        unusual_recipient_recency = (
            self._find_unusual_recipient_recency(
                context.recipients,
                historical_recipients,
                historical_recipient_interval_statistics,
                current_recipient_intervals,
            )
        )

        if unusual_recipient_recency:
            indicators.append(
                "Message sent after an unusually long recipient communication gap"
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
            historical_recipient_cooccurrences=(
                historical_recipient_cooccurrences
            ),
            unusual_recipient_pairs=(
                unusual_recipient_pairs
            ),
            historical_recipient_role_frequencies=(
                historical_recipient_role_frequencies
            ),
            historical_individual_recipient_role_frequencies=(
                historical_individual_recipient_role_frequencies
            ),
            unusual_recipient_roles=(
                unusual_recipient_roles
            ),
            unusual_recipient_role_pairs=(
                unusual_recipient_role_pairs
            ),
            historical_recipient_group_frequencies=(
                historical_recipient_group_frequencies
            ),
            unusual_recipient_groups=(
                unusual_recipient_groups
            ),
            historical_recipient_transition_frequencies=(
                historical_recipient_transition_frequencies
            ),
            current_recipient_transition=(
                current_recipient_transition
            ),
            unusual_recipient_transitions=(
                unusual_recipient_transitions
            ),
            historical_recipient_interval_statistics=(
                historical_recipient_interval_statistics
            ),
            current_recipient_intervals=(
                current_recipient_intervals
            ),
            unusual_recipient_recency=(
                unusual_recipient_recency
            ),
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
    def _build_historical_recipient_group_frequencies(
        cls,
        observations: list[dict[str, Any]],
    ) -> dict[tuple[str, ...], float]:
        """Build historical frequencies for complete recipient groups."""

        if len(observations) < cls.MIN_HISTORICAL_OBSERVATIONS:
            return {}

        recipient_group_counts: dict[
            tuple[str, ...],
            int,
        ] = {}

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

            recipients = cls._normalize_recipients(
                recipients
            )

            if not recipients:
                continue

            valid_observations += 1

            recipient_group = tuple(
                sorted(recipients)
            )

            recipient_group_counts[
                recipient_group
            ] = (
                recipient_group_counts.get(
                    recipient_group,
                    0,
                )
                + 1
            )

        if valid_observations < cls.MIN_HISTORICAL_OBSERVATIONS:
            return {}

        return {
            recipient_group: count / valid_observations
            for recipient_group, count in sorted(
                recipient_group_counts.items()
            )
        }

    @classmethod
    def _find_unusual_recipient_transitions(
        cls,
        historical_transition_frequencies: dict[
            tuple[tuple[str, ...], tuple[str, ...]],
            float,
        ],
        current_transition: tuple[
            tuple[str, ...],
            tuple[str, ...],
        ] | None,
    ) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
        """Identify current recipient transitions that are historically unusual."""

        if current_transition is None:
            return []

        frequency = historical_transition_frequencies.get(
            current_transition,
            0.0,
        )

        if frequency <= cls.RECIPIENT_TRANSITION_THRESHOLD:
            return [current_transition]

        return []

    @classmethod
    def _calculate_current_recipient_transition(
        cls,
        observations: list[dict[str, Any]],
        current_recipients: list[str],
    ) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
        """Return the latest historical recipient group to current group transition."""

        if len(observations) < cls.MIN_HISTORICAL_OBSERVATIONS:
            return None

        current_group = tuple(
            sorted(
                cls._normalize_recipients(
                    current_recipients
                )
            )
        )

        if not current_group:
            return None

        historical_groups: list[tuple[str, ...]] = []

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

            recipients = cls._normalize_recipients(
                recipients
            )

            if not recipients:
                continue

            historical_groups.append(
                tuple(sorted(recipients))
            )

        if not historical_groups:
            return None

        return (
            historical_groups[-1],
            current_group,
        )

    @classmethod
    def _build_historical_recipient_transition_frequencies(
        cls,
        observations: list[dict[str, Any]],
    ) -> dict[
        tuple[tuple[str, ...], tuple[str, ...]],
        float,
    ]:
        """Build historical frequencies for adjacent recipient-group transitions."""

        if len(observations) < cls.MIN_HISTORICAL_OBSERVATIONS:
            return {}

        transition_counts: dict[
            tuple[tuple[str, ...], tuple[str, ...]],
            int,
        ] = {}

        previous_group: tuple[str, ...] | None = None

        for observation in observations:
            if not isinstance(observation, dict):
                previous_group = None
                continue

            result = observation.get("result")

            if not isinstance(result, dict):
                previous_group = None
                continue

            email = result.get("email")

            if not isinstance(email, dict):
                previous_group = None
                continue

            recipients = (
                cls._normalize_recipients(
                    email.get("to", [])
                )
                + cls._normalize_recipients(
                    email.get("cc", [])
                )
            )

            recipients = cls._normalize_recipients(
                recipients
            )

            if not recipients:
                previous_group = None
                continue

            current_group = tuple(
                sorted(recipients)
            )

            if previous_group is not None:
                transition = (
                    previous_group,
                    current_group,
                )

                transition_counts[transition] = (
                    transition_counts.get(
                        transition,
                        0,
                    )
                    + 1
                )

            previous_group = current_group

        valid_transitions = sum(
            transition_counts.values()
        )

        if not valid_transitions:
            return {}

        return {
            transition: count / valid_transitions
            for transition, count in sorted(
                transition_counts.items()
            )
        }

    @classmethod
    def _find_unusual_recipient_groups(
        cls,
        current_recipients: list[str],
        historical_group_frequencies: dict[
            tuple[str, ...],
            float,
        ],
    ) -> list[tuple[str, ...]]:
        """Find current complete recipient groups absent from history."""

        if not historical_group_frequencies:
            return []

        normalized_current_recipients = cls._normalize_recipients(
            current_recipients
        )

        if not normalized_current_recipients:
            return []

        current_group = tuple(
            sorted(normalized_current_recipients)
        )

        if current_group not in historical_group_frequencies:
            return [current_group]

        return []

    @classmethod
    def _build_historical_recipient_cooccurrences(
        cls,
        observations: list[dict[str, Any]],
    ) -> dict[tuple[str, str], float]:
        """Build historical recipient-pair co-occurrence frequencies."""

        if len(observations) < cls.MIN_HISTORICAL_OBSERVATIONS:
            return {}

        pair_counts: dict[tuple[str, str], int] = {}
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

            recipients = cls._normalize_recipients(
                recipients
            )

            if not recipients:
                continue

            valid_observations += 1

            for pair in combinations(
                sorted(recipients),
                2,
            ):
                pair_counts[pair] = (
                    pair_counts.get(pair, 0) + 1
                )

        if valid_observations < cls.MIN_HISTORICAL_OBSERVATIONS:
            return {}

        return {
            pair: count / valid_observations
            for pair, count in sorted(
                pair_counts.items()
            )
        }

    @classmethod
    def _build_historical_recipient_role_frequencies(
        cls,
        observations: list[dict[str, Any]],
    ) -> dict[
        tuple[str, str, str, str],
        float,
    ]:
        """Build historical To/CC role frequencies for recipient pairs."""

        if len(observations) < cls.MIN_HISTORICAL_OBSERVATIONS:
            return {}

        pair_counts: dict[tuple[str, str], int] = {}

        role_pair_counts: dict[
            tuple[str, str, str, str],
            int,
        ] = {}

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

            recipient_roles = cls._extract_recipient_roles(
                email
            )

            if not recipient_roles:
                continue

            valid_observations += 1

            recipients = sorted(
                recipient_roles
            )

            for pair in combinations(
                recipients,
                2,
            ):
                pair_counts[pair] = (
                    pair_counts.get(pair, 0) + 1
                )

                role_pair = cls._build_recipient_role_pair(
                    pair,
                    recipient_roles,
                )

                role_pair_counts[role_pair] = (
                    role_pair_counts.get(role_pair, 0) + 1
                )

        if valid_observations < cls.MIN_HISTORICAL_OBSERVATIONS:
            return {}

        historical_role_frequencies: dict[
            tuple[str, str, str, str],
            float,
        ] = {}

        for role_pair, count in sorted(
            role_pair_counts.items()
        ):
            recipient_pair = (
                role_pair[0],
                role_pair[2],
            )

            pair_count = pair_counts.get(
                recipient_pair,
                0,
            )

            if pair_count <= 0:
                continue

            historical_role_frequencies[role_pair] = (
                count / pair_count
            )

        return historical_role_frequencies

    @classmethod
    def _build_historical_individual_recipient_role_frequencies(
        cls,
        observations: list[dict[str, Any]],
    ) -> dict[
        tuple[str, str],
        float,
    ]:
        """Build historical To/Cc role frequencies for each recipient."""

        if len(observations) < cls.MIN_HISTORICAL_OBSERVATIONS:
            return {}

        role_counts: dict[
            tuple[str, str],
            int,
        ] = {}

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

            recipient_roles = cls._extract_recipient_roles(
                email
            )

            if not recipient_roles:
                continue

            valid_observations += 1

            for recipient, role in recipient_roles.items():
                recipient_counts[recipient] = (
                    recipient_counts.get(
                        recipient,
                        0,
                    )
                    + 1
                )

                role_key = (
                    recipient,
                    role,
                )

                role_counts[role_key] = (
                    role_counts.get(
                        role_key,
                        0,
                    )
                    + 1
                )

        if valid_observations < cls.MIN_HISTORICAL_OBSERVATIONS:
            return {}

        return {
            role_key: count / recipient_counts[role_key[0]]
            for role_key, count in sorted(
                role_counts.items()
            )
            if recipient_counts.get(
                role_key[0],
                0,
            ) > 0
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

    @classmethod
    def _find_unusual_recipient_pairs(
        cls,
        current_recipients: list[str],
        historical_recipients: set[str],
        historical_cooccurrences: dict[tuple[str, str], float],
    ) -> list[tuple[str, str]]:
        """Find historically unusual relationships between known recipients."""

        if len(historical_recipients) < 2:
            return []

        normalized_current_recipients = cls._normalize_recipients(
            current_recipients
        )

        known_current_recipients = [
            recipient
            for recipient in normalized_current_recipients
            if recipient in historical_recipients
        ]

        if len(known_current_recipients) < 2:
            return []

        unusual_pairs: list[tuple[str, str]] = []

        for pair in combinations(
            sorted(known_current_recipients),
            2,
        ):
            frequency = historical_cooccurrences.get(
                pair,
                0.0,
            )

            if frequency <= cls.RECIPIENT_COOCCURRENCE_THRESHOLD:
                unusual_pairs.append(
                    pair
                )

        return unusual_pairs

    @classmethod
    def _find_unusual_recipient_roles(
        cls,
        current_email: dict[str, Any],
        historical_role_frequencies: dict[
            tuple[str, str],
            float,
        ],
    ) -> list[tuple[str, str]]:
        """Find known recipients using an historically unusual To/Cc role."""

        if not historical_role_frequencies:
            return []

        current_recipient_roles = cls._extract_recipient_roles(
            current_email
        )

        if not current_recipient_roles:
            return []

        historical_recipients = {
            recipient
            for recipient, _ in historical_role_frequencies
        }

        known_current_recipients = [
            recipient
            for recipient in current_recipient_roles
            if recipient in historical_recipients
        ]

        unusual_roles: list[tuple[str, str]] = []

        for recipient in sorted(
            known_current_recipients
        ):
            role = current_recipient_roles[recipient]

            role_frequency = historical_role_frequencies.get(
                (
                    recipient,
                    role,
                ),
                0.0,
            )

            if (
                role_frequency
                <= cls.INDIVIDUAL_RECIPIENT_ROLE_THRESHOLD
            ):
                unusual_roles.append(
                    (
                        recipient,
                        role,
                    )
                )

        return unusual_roles

    @classmethod
    def _find_unusual_recipient_role_pairs(
        cls,
        current_email: dict[str, Any],
        historical_recipients: set[str],
        historical_cooccurrences: dict[tuple[str, str], float],
        historical_role_frequencies: dict[
            tuple[str, str, str, str],
            float,
        ],
    ) -> list[tuple[str, str, str, str]]:
        """Find established recipient pairs using unusual To/CC roles."""

        if len(historical_recipients) < 2:
            return []

        if not historical_cooccurrences:
            return []

        if not historical_role_frequencies:
            return []

        current_recipient_roles = cls._extract_recipient_roles(
            current_email
        )

        if len(current_recipient_roles) < 2:
            return []

        known_current_recipients = [
            recipient
            for recipient in current_recipient_roles
            if recipient in historical_recipients
        ]

        if len(known_current_recipients) < 2:
            return []

        unusual_role_pairs: list[
            tuple[str, str, str, str]
        ] = []

        for pair in combinations(
            sorted(known_current_recipients),
            2,
        ):
            cooccurrence_frequency = (
                historical_cooccurrences.get(
                    pair,
                    0.0,
                )
            )

            # Role analysis applies only to an established recipient
            # relationship. A completely unseen pair belongs to the
            # co-occurrence detector instead.
            if (
                cooccurrence_frequency
                <= cls.RECIPIENT_COOCCURRENCE_THRESHOLD
            ):
                continue

            current_role_pair = cls._build_recipient_role_pair(
                pair,
                current_recipient_roles,
            )

            role_frequency = historical_role_frequencies.get(
                current_role_pair,
                0.0,
            )

            if role_frequency <= cls.RECIPIENT_ROLE_THRESHOLD:
                unusual_role_pairs.append(
                    current_role_pair
                )

        return unusual_role_pairs

    @staticmethod
    def _extract_recipient_roles(
        email: dict[str, Any],
    ) -> dict[str, str]:
        """Extract each current recipient's To or Cc role."""

        to_recipients = BehavioralCommunicationAnomalyRule._normalize_recipients(
            email.get("to", [])
        )

        cc_recipients = BehavioralCommunicationAnomalyRule._normalize_recipients(
            email.get("cc", [])
        )

        recipient_roles: dict[str, str] = {
            recipient: "to"
            for recipient in to_recipients
        }

        # If a recipient appears in both To and Cc, To takes precedence
        # so that each recipient has one deterministic role.
        for recipient in cc_recipients:
            if recipient not in recipient_roles:
                recipient_roles[recipient] = "cc"

        return recipient_roles

    @staticmethod
    def _build_recipient_role_pair(
        pair: tuple[str, str],
        recipient_roles: dict[str, str],
    ) -> tuple[str, str, str, str]:
        """Build a canonical recipient-role pair."""

        first_recipient, second_recipient = pair

        return (
            first_recipient,
            recipient_roles[first_recipient],
            second_recipient,
            recipient_roles[second_recipient],
        )

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
    def _build_historical_recipient_timestamps(
        cls,
        observations: list[dict[str, Any]],
    ) -> dict[str, list[datetime]]:
        """Build recipient-specific historical email timestamps."""

        recipient_timestamps: dict[str, list[datetime]] = {}

        for observation in observations:
            if not isinstance(observation, dict):
                continue

            email_sent_at = observation.get(
                "email_sent_at"
            )

            if isinstance(email_sent_at, datetime):
                parsed_timestamp = email_sent_at
            elif isinstance(email_sent_at, str):
                parsed_timestamp = cls._parse_historical_timestamp(
                    email_sent_at
                )
            else:
                parsed_timestamp = None

            if parsed_timestamp is None:
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

            for recipient in dict.fromkeys(recipients):
                recipient_timestamps.setdefault(
                    recipient,
                    [],
                ).append(parsed_timestamp)

        for recipient in recipient_timestamps:
            recipient_timestamps[recipient].sort()

        return recipient_timestamps

    @classmethod
    def _build_historical_recipient_interval_statistics(
        cls,
        recipient_timestamps: dict[str, list[datetime]],
    ) -> dict[str, dict[str, float | int]]:
        """Build recipient-specific median communication intervals."""

        statistics: dict[str, dict[str, float | int]] = {}

        for recipient, timestamps in recipient_timestamps.items():
            if len(timestamps) < cls.MIN_HISTORICAL_OBSERVATIONS:
                continue

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
                continue

            statistics[recipient] = {
                "median_interval_minutes": float(
                    median(intervals)
                ),
                "interval_count": len(intervals),
            }

        return statistics

    @classmethod
    def _calculate_current_recipient_intervals(
        cls,
        parsed_date: datetime,
        recipient_timestamps: dict[str, list[datetime]],
        current_recipients: list[str],
    ) -> dict[str, float]:
        """Calculate current communication gaps for known recipients."""

        current_intervals: dict[str, float] = {}

        for recipient in cls._normalize_recipients(
            current_recipients
        ):
            timestamps = recipient_timestamps.get(
                recipient,
                [],
            )

            if not timestamps:
                continue

            previous_timestamp = timestamps[-1]
            comparison_date = parsed_date

            if (
                comparison_date.tzinfo is not None
                and previous_timestamp.tzinfo is None
            ):
                previous_timestamp = previous_timestamp.replace(
                    tzinfo=comparison_date.tzinfo
                )

            elif (
                comparison_date.tzinfo is None
                and previous_timestamp.tzinfo is not None
            ):
                comparison_date = comparison_date.replace(
                    tzinfo=previous_timestamp.tzinfo
                )

            interval_minutes = (
                comparison_date - previous_timestamp
            ).total_seconds() / 60

            if (
                interval_minutes
                < cls.MIN_FREQUENCY_INTERVAL_MINUTES
            ):
                continue

            current_intervals[recipient] = interval_minutes

        return current_intervals

    @classmethod
    def _find_unusual_recipient_recency(
        cls,
        current_recipients: list[str],
        historical_recipients: set[str],
        historical_interval_statistics: dict[
            str,
            dict[str, float | int],
        ],
        current_recipient_intervals: dict[str, float],
    ) -> list[str]:
        """Find known recipients returning after an unusually long gap."""

        unusual_recipients: list[str] = []

        for recipient in cls._normalize_recipients(
            current_recipients
        ):
            if recipient not in historical_recipients:
                continue

            statistics = historical_interval_statistics.get(
                recipient
            )

            if not statistics:
                continue

            historical_interval = statistics.get(
                "median_interval_minutes"
            )

            current_interval = current_recipient_intervals.get(
                recipient
            )

            if not isinstance(historical_interval, (int, float)):
                continue

            if not isinstance(current_interval, (int, float)):
                continue

            if historical_interval <= 0:
                continue

            if (
                current_interval
                >= historical_interval
                * cls.RECIPIENT_RECENCY_ANOMALY_RATIO
            ):
                unusual_recipients.append(
                    recipient
                )

        return unusual_recipients

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

    @staticmethod
    def _build_behavioral_metrics(
        *,
        historical_recipient_interval_statistics: dict[
            str,
            dict[str, float | int],
        ],
        current_recipient_intervals: dict[str, float],
        historical_frequency_interval: float | None,
        current_frequency_interval: float | None,
    ) -> dict[str, Any]:
        """Build continuous behavioral deviation metrics."""

        metrics: dict[str, Any] = {
            "frequency_interval_ratio": None,
            "recipient_recency_ratios": {},
        }

        if (
            historical_frequency_interval is not None
            and current_frequency_interval is not None
            and historical_frequency_interval > 0
        ):
            metrics["frequency_interval_ratio"] = (
                current_frequency_interval
                / historical_frequency_interval
            )

        recipient_recency_ratios: dict[str, float] = {}

        for recipient, current_interval in (
            current_recipient_intervals.items()
        ):
            statistics = (
                historical_recipient_interval_statistics.get(
                    recipient
                )
            )

            if not statistics:
                continue

            historical_interval = statistics.get(
                "median_interval_minutes"
            )

            if not isinstance(
                historical_interval,
                (int, float),
            ):
                continue

            if historical_interval <= 0:
                continue

            recipient_recency_ratios[recipient] = (
                current_interval
                / historical_interval
            )

        metrics["recipient_recency_ratios"] = (
            recipient_recency_ratios
        )

        return metrics

    def _build_behavioral_features(
        *,
        observed_hour: int | None,
        typical_hours: list[int],
        observed_weekday: int | None,
        typical_days: list[int],
        observed_timezone_offset: int | None,
        typical_timezone_offsets: list[int],
        historical_hour_range: tuple[int, int] | None,
        unusual_recipients: list[str],
        infrequent_recipients: list[str],
        unusual_recipient_pairs: list[tuple[str, str]],
        unusual_recipient_roles: list[tuple[str, str]],
        unusual_recipient_role_pairs: list[tuple[str, str, str, str]],
        unusual_recipient_groups: list[tuple[str, ...]],
        unusual_recipient_recency: list[str],
        unusual_recipient_transitions: list[
            tuple[tuple[str, ...], tuple[str, ...]]
        ],
        current_frequency_interval: float | None,
        historical_frequency_interval: float | None,
        frequency_anomaly_detected: bool,
    ) -> dict[str, int]:
        # Build normalized behavioral anomaly features from existing evidence.
        sending_hour_anomaly = int(
            observed_hour is not None
            and bool(typical_hours)
            and observed_hour not in typical_hours
        )

        sending_day_anomaly = int(
            observed_weekday is not None
            and bool(typical_days)
            and observed_weekday not in typical_days
        )

        timezone_anomaly = int(
            observed_timezone_offset is not None
            and bool(typical_timezone_offsets)
            and observed_timezone_offset not in typical_timezone_offsets
        )

        historical_hour_anomaly = int(
            historical_hour_range is not None
            and observed_hour is not None
            and not (
                historical_hour_range[0]
                <= observed_hour
                <= historical_hour_range[1]
            )
        )

        frequency_anomaly = int(frequency_anomaly_detected)

        behavioral_features = {
            "sending_hour_anomaly": sending_hour_anomaly,
            "sending_day_anomaly": sending_day_anomaly,
            "timezone_anomaly": timezone_anomaly,
            "historical_hour_anomaly": historical_hour_anomaly,
            "frequency_anomaly": frequency_anomaly,
            "recipient_novelty": int(bool(unusual_recipients)),
            "recipient_frequency_anomaly": int(bool(infrequent_recipients)),
            "recipient_relationship_anomaly": int(bool(unusual_recipient_pairs)),
            "recipient_role_anomaly": int(
                bool(
                    unusual_recipient_roles
                    or unusual_recipient_role_pairs
                )
            ),
            "recipient_group_anomaly": int(bool(unusual_recipient_groups)),
            "recipient_recency_anomaly": int(bool(unusual_recipient_recency)),
            "recipient_sequence_anomaly": int(bool(unusual_recipient_transitions)),
        }

        return behavioral_features

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
        historical_recipient_cooccurrences: dict[
            tuple[str, str],
            float,
        ],
        unusual_recipient_pairs: list[
            tuple[str, str]
        ],
        historical_recipient_role_frequencies: dict[
            tuple[str, str, str, str],
            float,
        ],
        historical_individual_recipient_role_frequencies: dict[
            tuple[str, str],
            float,
        ],
        unusual_recipient_roles: list[
            tuple[str, str]
        ],
        unusual_recipient_role_pairs: list[
            tuple[str, str, str, str]
        ],
        historical_recipient_group_frequencies: dict[
            tuple[str, ...],
            float,
        ],
        unusual_recipient_groups: list[
            tuple[str, ...]
        ],
        historical_recipient_transition_frequencies: dict[
            tuple[tuple[str, ...], tuple[str, ...]],
            float,
        ],
        current_recipient_transition: tuple[
            tuple[str, ...],
            tuple[str, ...],
        ] | None,
        unusual_recipient_transitions: list[
            tuple[tuple[str, ...], tuple[str, ...]]
        ],
        historical_recipient_interval_statistics: dict[
            str,
            dict[str, float | int],
        ],
        current_recipient_intervals: dict[str, float],
        unusual_recipient_recency: list[str],
        historical_frequency_interval: float | None,
        current_frequency_interval: float | None,
    ) -> dict[str, Any]:
        """Build the standardized BEC-007 detection result."""

        frequency_anomaly = self._is_frequency_anomaly(
            current_frequency_interval,
            historical_frequency_interval,
        )

        behavioral_metrics = self._build_behavioral_metrics(
            historical_recipient_interval_statistics=(
                historical_recipient_interval_statistics
            ),
            current_recipient_intervals=(
                current_recipient_intervals
            ),
            historical_frequency_interval=(
                historical_frequency_interval
            ),
            current_frequency_interval=(
                current_frequency_interval
            ),
        )

        behavioral_features = (
            BehavioralCommunicationAnomalyRule._build_behavioral_features(
            observed_hour=observed_hour,
            typical_hours=typical_hours,
            observed_weekday=observed_weekday,
            typical_days=typical_days,
            observed_timezone_offset=observed_timezone_offset,
            typical_timezone_offsets=typical_timezone_offsets,
            historical_hour_range=historical_hour_range,
            unusual_recipients=unusual_recipients,
            infrequent_recipients=infrequent_recipients,
            unusual_recipient_pairs=unusual_recipient_pairs,
            unusual_recipient_roles=unusual_recipient_roles,
            unusual_recipient_role_pairs=unusual_recipient_role_pairs,
            unusual_recipient_groups=unusual_recipient_groups,
            unusual_recipient_recency=unusual_recipient_recency,
            unusual_recipient_transitions=unusual_recipient_transitions,
            current_frequency_interval=current_frequency_interval,
            historical_frequency_interval=historical_frequency_interval,
            frequency_anomaly_detected=frequency_anomaly,
        )

        anomalous_behavioral_features = [
            feature_name
            for feature_name, value in behavioral_features.items()
            if value == 1
        ]

        behavioral_anomaly_count = len(
            anomalous_behavioral_features
        )

        behavioral_anomaly_ratio = (
            behavioral_anomaly_count
            / len(behavioral_features)
        )

        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "matched": matched,
            "indicators": indicators,
            "behavioral_features": behavioral_features,
            "behavioral_metrics": behavioral_metrics,
            "behavioral_anomaly_count": behavioral_anomaly_count,
            "behavioral_anomaly_ratio": behavioral_anomaly_ratio,
            "anomalous_behavioral_features": (
                anomalous_behavioral_features
            ),
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
            "historical_recipient_cooccurrences": (
                historical_recipient_cooccurrences
            ),
            "unusual_recipient_pairs": (
                unusual_recipient_pairs
            ),
            "historical_recipient_role_frequencies": (
                historical_recipient_role_frequencies
            ),
            "historical_individual_recipient_role_frequencies": (
                historical_individual_recipient_role_frequencies
            ),
            "unusual_recipient_roles": (
                unusual_recipient_roles
            ),
            "unusual_recipient_role_pairs": (
                unusual_recipient_role_pairs
            ),
            "historical_recipient_group_frequencies": (
                historical_recipient_group_frequencies
            ),
            "unusual_recipient_groups": (
                unusual_recipient_groups
            ),
            "historical_recipient_transition_frequencies": (
                historical_recipient_transition_frequencies
            ),
            "current_recipient_transition": (
                current_recipient_transition
            ),
            "unusual_recipient_transitions": (
                unusual_recipient_transitions
            ),
            "historical_recipient_interval_statistics": (
                historical_recipient_interval_statistics
            ),
            "unusual_recipient_recency": (
                unusual_recipient_recency
            ),
            "historical_frequency_interval": (
                historical_frequency_interval
            ),
            "current_frequency_interval": (
                current_frequency_interval
            ),
        }
