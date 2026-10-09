"""Validate and prepare behavioral features for ML preprocessing."""

from __future__ import annotations

import math
from typing import Any

from src.ml.feature_extractor import (
    BEHAVIORAL_FEATURE_NAMES,
    SCALAR_FEATURE_NAMES,
)


ALLOWED_MISSING_FEATURE_NAMES = (
    "frequency_interval_ratio",
    "historical_recipient_count_median",
    "recipient_count_ratio",
    "historical_cc_count_median",
    "cc_count_ratio",
    "historical_attachment_usage_rate",
)

EXPECTED_FEATURE_NAMES = (
    SCALAR_FEATURE_NAMES + BEHAVIORAL_FEATURE_NAMES
)

ALLOWED_MISSING_FEATURE_SET = frozenset(
    ALLOWED_MISSING_FEATURE_NAMES
)

EXPECTED_FEATURE_SET = frozenset(EXPECTED_FEATURE_NAMES)

BINARY_FEATURE_NAMES = (
    "attachment_present",
) + BEHAVIORAL_FEATURE_NAMES


def validate_bec_007_features(
    features: dict[str, Any],
) -> None:
    """Validate feature names, values, and permitted missingness.

    This function validates the original extracted feature dictionary.
    It does not impute values or modify the input.

    None is permitted only for the six features listed in
    ALLOWED_MISSING_FEATURE_NAMES.
    """

    actual_names = set(features)

    missing_names = EXPECTED_FEATURE_SET - actual_names
    unexpected_names = actual_names - EXPECTED_FEATURE_SET

    if missing_names or unexpected_names:
        raise ValueError(
            "Feature names do not match the expected schema. "
            f"Missing: {sorted(missing_names)}; "
            f"unexpected: {sorted(unexpected_names)}"
        )

    for feature_name in EXPECTED_FEATURE_NAMES:
        value = features[feature_name]

        if value is None:
            if feature_name not in ALLOWED_MISSING_FEATURE_SET:
                raise ValueError(
                    f"Missing value for required feature: "
                    f"{feature_name}"
                )
            continue

        if isinstance(value, bool) or not isinstance(
            value,
            (int, float),
        ):
            raise TypeError(
                f"Expected numeric value for {feature_name}, "
                f"got {type(value).__name__}"
            )

        if not math.isfinite(value):
            raise ValueError(
                f"Expected a finite numeric value for {feature_name}"
            )

        if feature_name in BINARY_FEATURE_NAMES and value not in (0, 1):
            raise ValueError(
                f"Expected binary value (0 or 1) for {feature_name}, "
                f"got {value}"
            )


MISSINGNESS_INDICATOR_NAMES = tuple(
    f"{feature_name}_missing"
    for feature_name in ALLOWED_MISSING_FEATURE_NAMES
)


def extract_missingness_indicators(
    features: dict[str, Any],
) -> dict[str, int]:
    """Return ordered missingness indicators for approved features.

    Each indicator reflects whether its original feature was None.
    The input is validated but never modified.
    """

    validate_bec_007_features(features)

    return {
        f"{feature_name}_missing": int(
            features[feature_name] is None
        )
        for feature_name in ALLOWED_MISSING_FEATURE_NAMES
    }


class BEC007Preprocessor:
    """Fit training-only imputation values and transform BEC-007 features."""

    def __init__(self) -> None:
        self.imputation_values: dict[str, float] = {}
        self._is_fitted = False

    def fit(
        self,
        training_features: list[dict[str, Any]],
    ) -> BEC007Preprocessor:
        """Learn median imputation values from training data only."""

        if not training_features:
            raise ValueError(
                "Expected at least one training observation"
            )

        for features in training_features:
            validate_bec_007_features(features)

        imputation_values: dict[str, float] = {}

        for feature_name in ALLOWED_MISSING_FEATURE_NAMES:
            observed_values = [
                float(features[feature_name])
                for features in training_features
                if features[feature_name] is not None
            ]

            if not observed_values:
                raise ValueError(
                    "No observed training values for "
                    f"{feature_name}"
                )

            observed_values.sort()
            middle = len(observed_values) // 2

            if len(observed_values) % 2:
                median = observed_values[middle]
            else:
                lower_middle = observed_values[middle - 1]
                upper_middle = observed_values[middle]

                # Divide before adding to avoid overflow for large,
                # finite floating-point values.
                median = (
                    lower_middle / 2.0
                    + upper_middle / 2.0
                )

            imputation_values[feature_name] = median

        self.imputation_values = imputation_values
        self._is_fitted = True

        return self

    def transform(
        self,
        features_list: list[dict[str, Any]],
    ) -> list[dict[str, float | int]]:
        """Impute approved missing values using previously fitted medians."""

        if not self._is_fitted:
            raise RuntimeError(
                "BEC007Preprocessor must be fitted before transform"
            )

        transformed_rows: list[dict[str, float | int]] = []

        for features in features_list:
            validate_bec_007_features(features)

            indicators = extract_missingness_indicators(features)

            transformed: dict[str, float | int] = {}

            for feature_name in EXPECTED_FEATURE_NAMES:
                value = features[feature_name]

                if value is None:
                    value = self.imputation_values[feature_name]

                transformed[feature_name] = value

            transformed.update(indicators)
            transformed_rows.append(transformed)

        return transformed_rows
