"""Tests for the Isolation Forest anomaly-model adapter."""

import math

import pytest

from src.ml.feature_extractor import SCALAR_FEATURE_NAMES
from src.ml.model_interface import MODEL_FEATURE_NAMES
from src.ml.isolation_forest import IsolationForestAdapter


def make_observation(index: int) -> dict[str, float]:
    """Create a valid, deterministic 30-feature observation."""

    observation = {name: 0.0 for name in MODEL_FEATURE_NAMES}

    # Scalar features with plausible, varying values.
    observation["frequency_interval_ratio"] = 0.8 + (index % 5) * 0.1
    observation["recipient_count"] = float(1 + index % 4)
    observation["historical_recipient_count_median"] = 2.0
    observation["recipient_count_ratio"] = (1 + index % 4) / 2.0
    observation["cc_count"] = float(index % 3)
    observation["historical_cc_count_median"] = 1.0
    observation["cc_count_ratio"] = float(index % 3)
    observation["attachment_present"] = float(index % 2)
    observation["historical_attachment_usage_rate"] = 0.25 + (
        index % 4
    ) * 0.1

    # Behavioral and missingness indicators remain binary.
    for name in MODEL_FEATURE_NAMES:
        if name not in SCALAR_FEATURE_NAMES:
            observation[name] = float((index + len(name)) % 2)

    return observation


def make_training_data(count: int = 40) -> list[dict[str, float]]:
    """Create a deterministic training batch."""

    return [make_observation(index) for index in range(count)]


def test_fit_returns_adapter_and_sets_finite_threshold() -> None:
    adapter = IsolationForestAdapter(random_state=42)

    result = adapter.fit(make_training_data())

    assert result is adapter
    assert adapter.is_fitted
    assert math.isfinite(adapter.threshold)


def test_score_samples_returns_finite_scores() -> None:
    adapter = IsolationForestAdapter(random_state=42)
    adapter.fit(make_training_data())

    scores = adapter.score_samples(make_training_data(5))

    assert len(scores) == 5
    assert all(math.isfinite(score) for score in scores)


def test_adapter_scores_are_negated_sklearn_scores() -> None:
    adapter = IsolationForestAdapter(random_state=42)
    adapter.fit(make_training_data())

    observations = make_training_data(8)
    vectors = adapter._validate_batch(
        observations,
        require_nonempty=False,
    )

    adapter_scores = adapter.score_samples(observations)
    sklearn_scores = adapter._model.score_samples(vectors)

    assert adapter._model is not None
    assert adapter_scores == pytest.approx(
        [-float(score) for score in sklearn_scores]
    )


def test_predictions_match_sklearn_decision_boundary() -> None:
    adapter = IsolationForestAdapter(
        contamination=0.1,
        random_state=42,
    )
    adapter.fit(make_training_data())

    observations = make_training_data(12)
    vectors = adapter._validate_batch(
        observations,
        require_nonempty=False,
    )

    expected = [
        prediction == -1
        for prediction in adapter._model.predict(vectors)
    ]

    assert adapter._model is not None
    assert adapter.predict(observations) == expected


def test_empty_inference_batch_returns_empty_results() -> None:
    adapter = IsolationForestAdapter(random_state=42)
    adapter.fit(make_training_data())

    assert adapter.score_samples([]) == []
    assert adapter.predict([]) == []


def test_same_random_seed_produces_same_scores() -> None:
    training_data = make_training_data()
    observations = make_training_data(10)

    first = IsolationForestAdapter(random_state=42)
    second = IsolationForestAdapter(random_state=42)

    first.fit(training_data)
    second.fit(training_data)

    assert first.score_samples(observations) == pytest.approx(
        second.score_samples(observations)
    )


def test_invalid_feature_schema_is_rejected() -> None:
    adapter = IsolationForestAdapter(random_state=42)
    adapter.fit(make_training_data())

    invalid_observation = make_observation(0)
    invalid_observation.pop(MODEL_FEATURE_NAMES[0])

    with pytest.raises(ValueError, match="invalid feature schema"):
        adapter.score_samples([invalid_observation])


def test_scoring_before_fit_is_rejected() -> None:
    adapter = IsolationForestAdapter()

    with pytest.raises(RuntimeError, match="must be fitted"):
        adapter.score_samples(make_training_data(1))


def test_failed_fit_does_not_mark_adapter_fitted() -> None:
    adapter = IsolationForestAdapter()

    with pytest.raises(ValueError, match="at least one"):
        adapter.fit([])

    assert not adapter.is_fitted

    with pytest.raises(RuntimeError, match="must be fitted"):
        _ = adapter.threshold
