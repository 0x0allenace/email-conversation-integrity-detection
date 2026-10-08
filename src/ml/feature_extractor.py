"""Extract stable numeric features from BEC-007 behavioral results."""

from __future__ import annotations

from typing import Any


SCALAR_FEATURE_NAMES = (
    "frequency_interval_ratio",
    "recipient_count",
    "historical_recipient_count_median",
    "recipient_count_ratio",
    "cc_count",
    "historical_cc_count_median",
    "cc_count_ratio",
    "attachment_present",
    "historical_attachment_usage_rate",
)

BEHAVIORAL_FEATURE_NAMES = (
    "sending_hour_anomaly",
    "sending_day_anomaly",
    "timezone_anomaly",
    "historical_hour_anomaly",
    "frequency_anomaly",
    "recipient_novelty",
    "recipient_frequency_anomaly",
    "recipient_relationship_anomaly",
    "recipient_role_anomaly",
    "recipient_group_anomaly",
    "recipient_count_anomaly",
    "cc_count_anomaly",
    "attachment_usage_anomaly",
    "recipient_recency_anomaly",
    "recipient_sequence_anomaly",
)


def extract_bec_007_features(
    result: dict[str, Any],
) -> dict[str, float | int | None]:
    """Extract fixed-width numeric features from a BEC-007 result."""

    behavioral_metrics = result.get("behavioral_metrics", {})
    behavioral_features = result.get("behavioral_features", {})

    features: dict[str, float | int | None] = {}

    for feature_name in SCALAR_FEATURE_NAMES:
        value = behavioral_metrics.get(feature_name)

        if value is not None and not isinstance(
            value,
            (int, float),
        ):
            raise TypeError(
                f"Expected numeric value for {feature_name}, "
                f"got {type(value).__name__}"
            )

        features[feature_name] = value

    for feature_name in BEHAVIORAL_FEATURE_NAMES:
        value = behavioral_features.get(feature_name, 0)

        if not isinstance(value, int):
            raise TypeError(
                f"Expected integer value for {feature_name}, "
                f"got {type(value).__name__}"
            )

        features[feature_name] = value

    return features
