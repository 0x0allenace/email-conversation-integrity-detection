import pytest

from src.ml.feature_extractor import (
    BEHAVIORAL_FEATURE_NAMES,
    SCALAR_FEATURE_NAMES,
    extract_bec_007_features,
)


def build_result() -> dict:
    return {
        "behavioral_metrics": {
            name: 1.0
            for name in SCALAR_FEATURE_NAMES
        },
        "behavioral_features": {
            name: 0
            for name in BEHAVIORAL_FEATURE_NAMES
        },
    }


def test_extract_bec_007_features_returns_expected_feature_count():
    result = build_result()

    features = extract_bec_007_features(result)

    assert len(features) == 24
    assert set(features) == (
        set(SCALAR_FEATURE_NAMES)
        | set(BEHAVIORAL_FEATURE_NAMES)
    )


def test_extract_bec_007_features_preserves_scalar_values():
    result = build_result()
    result["behavioral_metrics"].update(
        {
            "frequency_interval_ratio": 2.5,
            "recipient_count": 3,
            "recipient_count_ratio": 1.5,
            "cc_count": 2,
            "attachment_present": 1,
        }
    )

    features = extract_bec_007_features(result)

    assert features["frequency_interval_ratio"] == 2.5
    assert features["recipient_count"] == 3
    assert features["recipient_count_ratio"] == 1.5
    assert features["cc_count"] == 2
    assert features["attachment_present"] == 1


def test_extract_bec_007_features_preserves_behavioral_flags():
    result = build_result()
    result["behavioral_features"].update(
        {
            "sending_hour_anomaly": 1,
            "recipient_novelty": 1,
            "attachment_usage_anomaly": 1,
            "recipient_sequence_anomaly": 1,
        }
    )

    features = extract_bec_007_features(result)

    assert features["sending_hour_anomaly"] == 1
    assert features["recipient_novelty"] == 1
    assert features["attachment_usage_anomaly"] == 1
    assert features["recipient_sequence_anomaly"] == 1


def test_extract_bec_007_features_preserves_missing_scalar_values_as_none():
    result = build_result()
    result["behavioral_metrics"]["cc_count_ratio"] = None
    result["behavioral_metrics"]["historical_attachment_usage_rate"] = None

    features = extract_bec_007_features(result)

    assert features["cc_count_ratio"] is None
    assert features["historical_attachment_usage_rate"] is None


def test_extract_bec_007_features_rejects_non_numeric_scalar_values():
    result = build_result()
    result["behavioral_metrics"]["recipient_count_ratio"] = "invalid"

    with pytest.raises(
        TypeError,
        match="Expected numeric value for recipient_count_ratio",
    ):
        extract_bec_007_features(result)


def test_extract_bec_007_features_rejects_non_integer_behavioral_flags():
    result = build_result()
    result["behavioral_features"]["sending_hour_anomaly"] = 1.0

    with pytest.raises(
        TypeError,
        match="Expected integer value for sending_hour_anomaly",
    ):
        extract_bec_007_features(result)
