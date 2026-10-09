import math

import pytest

from src.ml.feature_extractor import (
    BEHAVIORAL_FEATURE_NAMES,
    SCALAR_FEATURE_NAMES,
)
from src.ml.preprocessing import (
    ALLOWED_MISSING_FEATURE_NAMES,
    validate_bec_007_features,
)


def build_features() -> dict[str, float | int | None]:
    return {
        **{
            name: 1.0
            for name in SCALAR_FEATURE_NAMES
        },
        **{
            name: 0
            for name in BEHAVIORAL_FEATURE_NAMES
        },
    }


def test_validate_bec_007_features_accepts_complete_features():
    features = build_features()

    validate_bec_007_features(features)


@pytest.mark.parametrize(
    "feature_name",
    ALLOWED_MISSING_FEATURE_NAMES,
)
def test_validate_bec_007_features_allows_permitted_missing_values(
    feature_name,
):
    features = build_features()
    features[feature_name] = None

    validate_bec_007_features(features)


def test_validate_bec_007_features_rejects_missing_required_feature():
    features = build_features()
    features["recipient_count"] = None

    with pytest.raises(
        ValueError,
        match="Missing value for required feature: recipient_count",
    ):
        validate_bec_007_features(features)


def test_validate_bec_007_features_rejects_missing_feature_name():
    features = build_features()
    del features["recipient_count"]

    with pytest.raises(
        ValueError,
        match="Feature names do not match the expected schema",
    ):
        validate_bec_007_features(features)


def test_validate_bec_007_features_rejects_unexpected_feature_name():
    features = build_features()
    features["unexpected_feature"] = 1.0

    with pytest.raises(
        ValueError,
        match="Feature names do not match the expected schema",
    ):
        validate_bec_007_features(features)


def test_validate_bec_007_features_rejects_non_numeric_values():
    features = build_features()
    features["recipient_count"] = "invalid"

    with pytest.raises(
        TypeError,
        match="Expected numeric value for recipient_count",
    ):
        validate_bec_007_features(features)


def test_validate_bec_007_features_rejects_boolean_as_numeric():
    features = build_features()
    features["recipient_count"] = True

    with pytest.raises(
        TypeError,
        match="Expected numeric value for recipient_count",
    ):
        validate_bec_007_features(features)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_validate_bec_007_features_rejects_non_finite_values(value):
    features = build_features()
    features["frequency_interval_ratio"] = value

    with pytest.raises(ValueError):
        validate_bec_007_features(features)


@pytest.mark.parametrize(
    ("feature_name", "value"),
    [
        ("sending_hour_anomaly", 2),
        ("sending_day_anomaly", -1),
        ("timezone_anomaly", 0.5),
        ("historical_hour_anomaly", True),
    ],
)
def test_validate_bec_007_features_rejects_invalid_binary_flags(
    feature_name,
    value,
):
    features = build_features()
    features[feature_name] = value

    with pytest.raises((TypeError, ValueError)):
        validate_bec_007_features(features)


def test_extract_missingness_indicators_returns_six_indicators():
    from src.ml.preprocessing import (
        MISSINGNESS_INDICATOR_NAMES,
        extract_missingness_indicators,
    )

    features = build_features()

    indicators = extract_missingness_indicators(features)

    assert tuple(indicators) == MISSINGNESS_INDICATOR_NAMES
    assert len(indicators) == 6
    assert all(value == 0 for value in indicators.values())


def test_extract_missingness_indicators_marks_missing_values():
    from src.ml.preprocessing import (
        extract_missingness_indicators,
    )

    features = build_features()
    features["frequency_interval_ratio"] = None
    features["recipient_count_ratio"] = None
    features["historical_attachment_usage_rate"] = None

    indicators = extract_missingness_indicators(features)

    assert indicators == {
        "frequency_interval_ratio_missing": 1,
        "historical_recipient_count_median_missing": 0,
        "recipient_count_ratio_missing": 1,
        "historical_cc_count_median_missing": 0,
        "cc_count_ratio_missing": 0,
        "historical_attachment_usage_rate_missing": 1,
    }


def test_extract_missingness_indicators_does_not_modify_input():
    from copy import deepcopy

    from src.ml.preprocessing import (
        extract_missingness_indicators,
    )

    features = build_features()
    features["cc_count_ratio"] = None
    original_features = deepcopy(features)

    extract_missingness_indicators(features)

    assert features == original_features


def test_extract_missingness_indicators_rejects_invalid_features():
    from src.ml.preprocessing import (
        extract_missingness_indicators,
    )

    features = build_features()
    features["recipient_count"] = None

    with pytest.raises(
        ValueError,
        match="Missing value for required feature: recipient_count",
    ):
        extract_missingness_indicators(features)


def test_preprocessor_requires_fit_before_transform():
    from src.ml.preprocessing import BEC007Preprocessor

    preprocessor = BEC007Preprocessor()

    with pytest.raises(
        RuntimeError,
        match="must be fitted",
    ):
        preprocessor.transform([build_features()])


def test_preprocessor_rejects_empty_training_data():
    from src.ml.preprocessing import BEC007Preprocessor

    preprocessor = BEC007Preprocessor()

    with pytest.raises(
        ValueError,
        match="at least one training observation",
    ):
        preprocessor.fit([])


def test_preprocessor_fits_medians_from_training_data():
    from src.ml.preprocessing import BEC007Preprocessor

    preprocessor = BEC007Preprocessor()

    first = build_features()
    second = build_features()
    third = build_features()

    first["historical_recipient_count_median"] = 2.0
    second["historical_recipient_count_median"] = None
    third["historical_recipient_count_median"] = 8.0

    preprocessor.fit([first, second, third])

    assert (
        preprocessor.imputation_values[
            "historical_recipient_count_median"
        ]
        == 5.0
    )


def test_preprocessor_rejects_feature_missing_entirely_in_training():
    from src.ml.preprocessing import BEC007Preprocessor

    preprocessor = BEC007Preprocessor()
    training_features = build_features()

    training_features["cc_count_ratio"] = None

    with pytest.raises(
        ValueError,
        match="No observed training values for cc_count_ratio",
    ):
        preprocessor.fit([training_features])


def test_preprocessor_imputes_using_training_medians():
    from src.ml.preprocessing import BEC007Preprocessor

    preprocessor = BEC007Preprocessor()

    first = build_features()
    second = build_features()
    third = build_features()

    first["historical_recipient_count_median"] = 2.0
    second["historical_recipient_count_median"] = None
    third["historical_recipient_count_median"] = 8.0

    preprocessor.fit([first, second, third])

    transformed = preprocessor.transform([second])

    assert (
        transformed[0]["historical_recipient_count_median"]
        == 5.0
    )
    assert (
        transformed[0]["historical_recipient_count_median_missing"]
        == 1
    )


def test_preprocessor_reuses_training_values_for_new_data():
    from src.ml.preprocessing import BEC007Preprocessor

    preprocessor = BEC007Preprocessor()

    first = build_features()
    second = build_features()

    first["historical_recipient_count_median"] = 2.0
    second["historical_recipient_count_median"] = 8.0

    preprocessor.fit([first, second])

    fitted_median = preprocessor.imputation_values[
        "historical_recipient_count_median"
    ]

    inference_features = build_features()
    inference_features["historical_recipient_count_median"] = None

    transformed = preprocessor.transform([inference_features])

    assert (
        transformed[0]["historical_recipient_count_median"]
        == fitted_median
    )
    assert (
        preprocessor.imputation_values[
            "historical_recipient_count_median"
        ]
        == fitted_median
    )


def test_preprocessor_does_not_modify_input_features():
    from copy import deepcopy

    from src.ml.preprocessing import BEC007Preprocessor

    preprocessor = BEC007Preprocessor()

    training_features_missing = build_features()
    training_features_missing["cc_count_ratio"] = None

    training_features_observed = build_features()
    training_features_observed["cc_count_ratio"] = 2.0

    training_data = [
        training_features_missing,
        training_features_observed,
    ]
    original_training_data = deepcopy(training_data)

    preprocessor.fit(training_data)

    assert training_data == original_training_data


def test_preprocessor_calculates_large_finite_median_without_overflow():
    from src.ml.preprocessing import BEC007Preprocessor

    preprocessor = BEC007Preprocessor()

    first = build_features()
    second = build_features()

    first["historical_recipient_count_median"] = 1.0e308
    second["historical_recipient_count_median"] = 1.0e308

    preprocessor.fit([first, second])

    median = preprocessor.imputation_values[
        "historical_recipient_count_median"
    ]

    assert median == 1.0e308
    assert math.isfinite(median)
