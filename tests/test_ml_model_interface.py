"""Tests for the shared ML anomaly-model interface."""

from collections.abc import Sequence
from typing import Any

import pytest

from src.ml.feature_extractor import (
    BEHAVIORAL_FEATURE_NAMES,
    SCALAR_FEATURE_NAMES,
)
from src.ml.model_interface import (
    MODEL_FEATURE_NAMES,
    AnomalyModel,
)
from src.ml.preprocessing import MISSINGNESS_INDICATOR_NAMES


class DummyAnomalyModel(AnomalyModel):
    """Small deterministic model for testing the shared interface."""

    def __init__(
        self,
        *,
        threshold: float = 0.5,
        scores: Sequence[float] | None = None,
    ) -> None:
        super().__init__()
        self.configured_threshold = threshold
        self.configured_scores = scores
        self.received_training_matrix: list[list[float]] | None = None

    def _fit_model(
        self,
        training_matrix: list[list[float]],
    ) -> float:
        self.received_training_matrix = training_matrix
        return self.configured_threshold

    def _score_model(
        self,
        matrix: list[list[float]],
    ) -> Sequence[float]:
        if self.configured_scores is not None:
            return self.configured_scores

        return [float(index) for index in range(len(matrix))]


def make_observation(**overrides: Any) -> dict[str, int | float]:
    """Build a valid transformed observation with all 30 features."""

    observation: dict[str, int | float] = {
        name: 0 for name in MODEL_FEATURE_NAMES
    }
    observation.update(overrides)
    return observation


def make_batch(
    count: int = 2,
) -> list[dict[str, int | float]]:
    """Build a batch of valid transformed observations."""

    return [make_observation() for _ in range(count)]


def test_model_feature_schema_contains_30_features() -> None:
    assert len(SCALAR_FEATURE_NAMES) == 9
    assert len(BEHAVIORAL_FEATURE_NAMES) == 15
    assert len(MISSINGNESS_INDICATOR_NAMES) == 6
    assert len(MODEL_FEATURE_NAMES) == 30
    assert len(set(MODEL_FEATURE_NAMES)) == 30


def test_fit_sets_fitted_state_and_threshold() -> None:
    model = DummyAnomalyModel(threshold=0.75)

    returned_model = model.fit(make_batch())

    assert returned_model is model
    assert model.is_fitted is True
    assert model.threshold == pytest.approx(0.75)
    assert model.received_training_matrix is not None
    assert len(model.received_training_matrix) == 2
    assert len(model.received_training_matrix[0]) == 30


def test_threshold_access_before_fit_raises() -> None:
    model = DummyAnomalyModel()

    with pytest.raises(RuntimeError, match="fitted"):
        _ = model.threshold


def test_scoring_before_fit_raises() -> None:
    model = DummyAnomalyModel()

    with pytest.raises(RuntimeError, match="fitted"):
        model.score_samples(make_batch())


def test_prediction_before_fit_raises() -> None:
    model = DummyAnomalyModel()

    with pytest.raises(RuntimeError, match="fitted"):
        model.predict(make_batch())


def test_prediction_uses_threshold_and_anomaly_score_direction() -> None:
    model = DummyAnomalyModel(
        threshold=0.5,
        scores=[0.1, 0.5, 0.9],
    )
    model.fit(make_batch())

    assert model.score_samples(make_batch(3)) == [0.1, 0.5, 0.9]
    assert model.predict(make_batch(3)) == [False, True, True]


def test_empty_inference_batch_returns_empty_results() -> None:
    model = DummyAnomalyModel()
    model.fit(make_batch())

    assert model.score_samples([]) == []
    assert model.predict([]) == []


def test_empty_training_batch_is_rejected() -> None:
    model = DummyAnomalyModel()

    with pytest.raises(ValueError, match="at least one"):
        model.fit([])

    assert model.is_fitted is False


def test_missing_feature_is_rejected() -> None:
    observation = make_observation()
    observation.pop(MODEL_FEATURE_NAMES[0])

    model = DummyAnomalyModel()

    with pytest.raises(ValueError, match="invalid feature schema"):
        model.fit([observation])


def test_unexpected_feature_is_rejected() -> None:
    observation = make_observation()
    observation["unexpected_feature"] = 1

    model = DummyAnomalyModel()

    with pytest.raises(ValueError, match="invalid feature schema"):
        model.fit([observation])


@pytest.mark.parametrize("invalid_value", [True, "1", None])
def test_invalid_feature_types_are_rejected(
    invalid_value: Any,
) -> None:
    observation = make_observation()
    observation[MODEL_FEATURE_NAMES[0]] = invalid_value

    model = DummyAnomalyModel()

    with pytest.raises(TypeError, match="Expected numeric value"):
        model.fit([observation])


@pytest.mark.parametrize("invalid_value", [float("nan"), float("inf"), -float("inf")])
def test_non_finite_feature_values_are_rejected(
    invalid_value: float,
) -> None:
    observation = make_observation()
    observation[MODEL_FEATURE_NAMES[0]] = invalid_value

    model = DummyAnomalyModel()

    with pytest.raises(ValueError, match="finite"):
        model.fit([observation])


@pytest.mark.parametrize("invalid_threshold", [True, "0.5", None])
def test_invalid_threshold_types_are_rejected(
    invalid_threshold: Any,
) -> None:
    model = DummyAnomalyModel(threshold=invalid_threshold)

    with pytest.raises(TypeError, match="threshold must be numeric"):
        model.fit(make_batch())

    assert model.is_fitted is False


@pytest.mark.parametrize("invalid_threshold", [float("nan"), float("inf"), -float("inf")])
def test_non_finite_threshold_is_rejected(
    invalid_threshold: float,
) -> None:
    model = DummyAnomalyModel(threshold=invalid_threshold)

    with pytest.raises(ValueError, match="threshold must be finite"):
        model.fit(make_batch())

    assert model.is_fitted is False


def test_overflowing_integer_threshold_is_rejected() -> None:
    model = DummyAnomalyModel(threshold=10**10000)

    with pytest.raises(ValueError, match="threshold must be finite"):
        model.fit(make_batch())

    assert model.is_fitted is False


def test_array_like_scores_are_supported() -> None:
    class ArrayLikeScores:
        """Simulate an array-like result without requiring NumPy."""

        def tolist(self) -> list[float]:
            return [0.1, 0.9]

    model = DummyAnomalyModel(scores=ArrayLikeScores())  # type: ignore[arg-type]
    model.fit(make_batch(2))

    assert model.score_samples(make_batch(2)) == [0.1, 0.9]
    assert model.predict(make_batch(2)) == [False, True]


def test_wrong_number_of_scores_is_rejected() -> None:
    model = DummyAnomalyModel(scores=[0.1])
    model.fit(make_batch(2))

    with pytest.raises(ValueError, match="unexpected number of scores"):
        model.score_samples(make_batch(2))


@pytest.mark.parametrize("invalid_score", [True, "0.5", None])
def test_invalid_score_types_are_rejected(
    invalid_score: Any,
) -> None:
    model = DummyAnomalyModel(scores=[invalid_score])
    model.fit(make_batch(1))

    with pytest.raises(TypeError, match="must be numeric"):
        model.score_samples(make_batch(1))


@pytest.mark.parametrize("invalid_score", [float("nan"), float("inf"), -float("inf")])
def test_non_finite_scores_are_rejected(
    invalid_score: float,
) -> None:
    model = DummyAnomalyModel(scores=[invalid_score])
    model.fit(make_batch(1))

    with pytest.raises(ValueError, match="must be finite"):
        model.score_samples(make_batch(1))


def test_failed_refit_clears_fitted_state() -> None:
    model = DummyAnomalyModel()
    model.fit(make_batch())

    assert model.is_fitted is True

    with pytest.raises(ValueError, match="invalid feature schema"):
        model.fit([{"unexpected_feature": 1}])

    assert model.is_fitted is False

    with pytest.raises(RuntimeError, match="fitted"):
        _ = model.threshold


def test_non_sequence_training_data_is_rejected() -> None:
    model = DummyAnomalyModel()

    with pytest.raises(TypeError, match="sequence"):
        model.fit("not a batch")  # type: ignore[arg-type]


def test_non_mapping_observation_is_rejected() -> None:
    model = DummyAnomalyModel()

    with pytest.raises(TypeError, match="feature dictionary"):
        model.fit([123])  # type: ignore[list-item]
