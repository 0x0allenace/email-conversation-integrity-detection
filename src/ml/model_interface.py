"""Shared interface and contracts for ML anomaly-detection models."""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Any

from src.ml.feature_extractor import (
    BEHAVIORAL_FEATURE_NAMES,
    SCALAR_FEATURE_NAMES,
)
from src.ml.preprocessing import (
    MISSINGNESS_INDICATOR_NAMES,
)


MODEL_FEATURE_NAMES = (
    SCALAR_FEATURE_NAMES
    + BEHAVIORAL_FEATURE_NAMES
    + MISSINGNESS_INDICATOR_NAMES
)


class AnomalyModel(ABC):
    """Base contract for models that detect anomalous behavior.

    Subclasses implement model fitting and raw scoring. The base class
    standardizes input validation, fitted-state checks, score validation,
    and Boolean prediction semantics.

    Subclass fitting must return a finite threshold learned from training
    data or supplied through an explicitly documented fixed configuration.

    Higher scores indicate greater anomalousness. Scores equal to or above
    the threshold are classified as anomalies.
    """

    def __init__(self) -> None:
        self._is_fitted = False
        self._threshold: float | None = None

    @property
    def is_fitted(self) -> bool:
        """Whether the model has completed a successful fit."""
        return self._is_fitted

    @property
    def threshold(self) -> float:
        """Return the fitted decision threshold."""
        if not self._is_fitted or self._threshold is None:
            raise RuntimeError(
                "AnomalyModel must be fitted before accessing its threshold"
            )

        return self._threshold

    @staticmethod
    def _validate_batch(
        data: Sequence[Mapping[str, Any]],
        *,
        require_nonempty: bool,
    ) -> list[list[float]]:
        """Validate transformed observations and return ordered vectors."""

        if isinstance(data, (str, bytes)) or not isinstance(data, Sequence):
            raise TypeError(
                "Expected a sequence of transformed feature dictionaries"
            )

        if require_nonempty and not data:
            raise ValueError(
                "Expected at least one training observation"
            )

        matrix: list[list[float]] = []
        expected_names = set(MODEL_FEATURE_NAMES)

        for index, row in enumerate(data):
            if not isinstance(row, Mapping):
                raise TypeError(
                    f"Observation {index} must be a feature dictionary"
                )

            actual_names = set(row)
            missing_names = expected_names - actual_names
            unexpected_names = actual_names - expected_names

            if missing_names or unexpected_names:
                raise ValueError(
                    f"Observation {index} has an invalid feature schema. "
                    f"Missing: {sorted(missing_names)}; "
                    f"unexpected: {sorted(unexpected_names)}"
                )

            vector: list[float] = []

            for feature_name in MODEL_FEATURE_NAMES:
                value = row[feature_name]

                if isinstance(value, bool) or not isinstance(
                    value, (int, float)
                ):
                    raise TypeError(
                        f"Expected numeric value for {feature_name}, "
                        f"got {type(value).__name__}"
                    )

                try:
                    numeric_value = float(value)
                except (OverflowError, ValueError) as exc:
                    raise ValueError(
                        f"Expected a finite numeric value for "
                        f"{feature_name}"
                    ) from exc

                if not math.isfinite(numeric_value):
                    raise ValueError(
                        f"Expected a finite numeric value for "
                        f"{feature_name}"
                    )

                vector.append(numeric_value)

            matrix.append(vector)

        return matrix

    @staticmethod
    def _validate_scores(
        scores: Any,
        expected_count: int,
    ) -> list[float]:
        """Validate and normalize sequence or array-like anomaly scores."""

        if isinstance(scores, (str, bytes, Mapping)):
            raise TypeError("Model scoring must return a sequence of scores")

        # Support common array-like outputs without importing NumPy.
        tolist = getattr(scores, "tolist", None)
        if callable(tolist):
            scores = tolist()

        if not isinstance(scores, Sequence):
            raise TypeError("Model scoring must return a sequence of scores")

        if len(scores) != expected_count:
            raise ValueError(
                "Model returned an unexpected number of scores: "
                f"expected {expected_count}, got {len(scores)}"
            )

        validated: list[float] = []

        for index, score in enumerate(scores):
            if isinstance(score, bool) or not isinstance(
                score, (int, float)
            ):
                raise TypeError(
                    f"Score at index {index} must be numeric"
                )

            try:
                numeric_score = float(score)
            except (OverflowError, ValueError) as exc:
                raise ValueError(
                    f"Score at index {index} must be finite"
                ) from exc

            if not math.isfinite(numeric_score):
                raise ValueError(
                    f"Score at index {index} must be finite"
                )

            validated.append(numeric_score)

        return validated

    @staticmethod
    def _validate_threshold(threshold: Any) -> float:
        """Require a finite numeric decision threshold."""

        if isinstance(threshold, bool) or not isinstance(
            threshold, (int, float)
        ):
            raise TypeError("Decision threshold must be numeric")

        try:
            numeric_threshold = float(threshold)
        except (OverflowError, ValueError) as exc:
            raise ValueError(
                "Decision threshold must be finite"
            ) from exc

        if not math.isfinite(numeric_threshold):
            raise ValueError("Decision threshold must be finite")

        return numeric_threshold

    def fit(
        self,
        training_data: Sequence[Mapping[str, Any]],
    ) -> AnomalyModel:
        """Fit on validated training observations."""

        # A failed fit or refit must not leave the adapter marked
        # as successfully fitted.
        self._is_fitted = False
        self._threshold = None

        matrix = self._validate_batch(
            training_data,
            require_nonempty=True,
        )

        threshold = self._fit_model(matrix)
        validated_threshold = self._validate_threshold(threshold)

        self._threshold = validated_threshold
        self._is_fitted = True

        return self

    def score_samples(
        self,
        data: Sequence[Mapping[str, Any]],
    ) -> list[float]:
        """Return finite anomaly scores without refitting the model."""

        if not self._is_fitted:
            raise RuntimeError(
                "AnomalyModel must be fitted before scoring"
            )

        matrix = self._validate_batch(
            data,
            require_nonempty=False,
        )

        scores = self._score_model(matrix)

        return self._validate_scores(scores, len(matrix))

    def predict(
        self,
        data: Sequence[Mapping[str, Any]],
    ) -> list[bool]:
        """Return True for anomalies and False for normal observations."""

        scores = self.score_samples(data)
        threshold = self.threshold

        return [
            score >= threshold
            for score in scores
        ]

    @abstractmethod
    def _fit_model(
        self,
        training_matrix: list[list[float]],
    ) -> float:
        """Fit the underlying model and return its decision threshold."""

    @abstractmethod
    def _score_model(
        self,
        matrix: list[list[float]],
    ) -> Sequence[float]:
        """Return anomaly scores, with higher values indicating anomalies."""
