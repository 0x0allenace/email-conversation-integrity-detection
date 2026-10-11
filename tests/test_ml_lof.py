"""Tests for the Local Outlier Factor anomaly-model adapter."""

import math

import pytest

from src.ml.feature_extractor import SCALAR_FEATURE_NAMES
from src.ml.model_interface import MODEL_FEATURE_NAMES
from src.ml.lof import LOFAdapter


def make_observation(index: int) -> dict[str, float]:
    """Create a valid, deterministic 30-feature observation."""

    observation = {name: 0.0 for name in MODEL_FEATURE_NAMES}

    observation["frequency_interval_ratio"] = (
        0.8 + (index % 5) * 0.1
    )
    observation["recipient_count"] = float(1 + index % 4)
    observation["historical_recipient_count_median"] = 2.0
    observation["recipient_count_ratio"] = (1 + index % 4) / 2.0
    observation["cc_count"] = float(index % 3)
    observation["historical_cc_count_median"] = 1.0
    observation["cc_count_ratio"] = float(index % 3)
    observation["attachment_present"] = float(index % 2)
    observation["historical_attachment_usage_rate"] = (
        0.25 + (index % 4) * 0.1
    )

    for name in MODEL_FEATURE_NAMES:
        if name not in SCALAR_FEATURE_NAMES:
            observation[name] = float((index + len(name)) % 2)

    return observation


def make_training_data(count: int = 40) -> list[dict[str, float]]:
    """Create a deterministic training batch."""

    return [make_observation(index) for index in range(count)]


def test_fit_returns_adapter_and_sets_finite_threshold() -> None:
    adapter = LOFAdapter(n_neighbors=10)

    result = adapter.fit(make_training_data())

    assert result is adapter
    assert adapter.is_fitted
    assert math.isfinite(adapter.threshold)
    assert adapter._scaler is not None
    assert adapter._model is not None
    assert adapter._model.novelty is True


def test_score_samples_returns_finite_scores() -> None:
    adapter = LOFAdapter(n_neighbors=10)
    adapter.fit(make_training_data())

    scores = adapter.score_samples(make_training_data(5))

    assert len(scores) == 5
    assert all(math.isfinite(score) for score in scores)


def test_adapter_scores_are_negated_sklearn_scores() -> None:
    adapter = LOFAdapter(n_neighbors=10)
    adapter.fit(make_training_data())

    observations = make_training_data(8)
    vectors = adapter._validate_batch(
        observations,
        require_nonempty=False,
    )

    assert adapter._scaler is not None
    assert adapter._model is not None

    scaled_vectors = adapter._scaler.transform(vectors)
    native_scores = adapter._model.score_samples(scaled_vectors)
    adapter_scores = adapter.score_samples(observations)

    assert adapter_scores == pytest.approx(
        [-float(score) for score in native_scores]
    )


def test_predictions_match_sklearn_decision_boundary() -> None:
    adapter = LOFAdapter(
        n_neighbors=10,
        contamination=0.1,
    )
    adapter.fit(make_training_data())

    observations = make_training_data(12)
    vectors = adapter._validate_batch(
        observations,
        require_nonempty=False,
    )

    assert adapter._scaler is not None
    assert adapter._model is not None

    scaled_vectors = adapter._scaler.transform(vectors)
    expected = [
        prediction == -1
        for prediction in adapter._model.predict(scaled_vectors)
    ]

    assert adapter.predict(observations) == expected


def test_empty_inference_batch_returns_empty_results() -> None:
    adapter = LOFAdapter(n_neighbors=10)
    adapter.fit(make_training_data())

    assert adapter.score_samples([]) == []
    assert adapter.predict([]) == []


def test_inference_does_not_refit_scaler_or_model() -> None:
    adapter = LOFAdapter(n_neighbors=10)
    adapter.fit(make_training_data())

    assert adapter._scaler is not None
    assert adapter._model is not None

    scaler = adapter._scaler
    model = adapter._model
    scaler_mean = adapter._scaler.mean_.copy()
    training_samples = adapter._model.n_samples_fit_

    adapter.score_samples(make_training_data(5))
    adapter.predict(make_training_data(5))

    assert adapter._scaler is scaler
    assert adapter._model is model
    assert adapter._scaler.mean_.tolist() == scaler_mean.tolist()
    assert adapter._model.n_samples_fit_ == training_samples


def test_scaler_is_fitted_using_training_data_only() -> None:
    training_data = make_training_data()
    adapter = LOFAdapter(n_neighbors=10)
    adapter.fit(training_data)

    vectors = adapter._validate_batch(
        training_data,
        require_nonempty=True,
    )

    assert adapter._scaler is not None
    expected_scaler = adapter._scaler.__class__().fit(vectors)

    assert adapter._scaler.mean_.tolist() == pytest.approx(
        expected_scaler.mean_.tolist()
    )


def test_invalid_feature_schema_is_rejected() -> None:
    adapter = LOFAdapter(n_neighbors=10)
    adapter.fit(make_training_data())

    invalid_observation = make_observation(0)
    invalid_observation.pop(MODEL_FEATURE_NAMES[0])

    with pytest.raises(ValueError, match="invalid feature schema"):
        adapter.score_samples([invalid_observation])


def test_scoring_before_fit_is_rejected() -> None:
    adapter = LOFAdapter(n_neighbors=10)

    with pytest.raises(RuntimeError, match="must be fitted"):
        adapter.score_samples(make_training_data(1))


def test_failed_fit_does_not_mark_adapter_fitted() -> None:
    adapter = LOFAdapter(n_neighbors=10)

    with pytest.raises(ValueError, match="at least one"):
        adapter.fit([])

    assert not adapter.is_fitted

    with pytest.raises(RuntimeError, match="must be fitted"):
        _ = adapter.threshold


@pytest.mark.parametrize(
    "kwargs",
    [
        {"n_neighbors": 0},
        {"n_neighbors": -1},
        {"contamination": 0.0},
        {"contamination": 0.6},
        {"leaf_size": 0},
        {"metric": "not-a-real-metric"},
        {"p": 0},
    ],
)
def test_invalid_model_configuration_is_rejected(
    kwargs: dict[str, object],
) -> None:
    adapter = LOFAdapter(**kwargs)
    training_data = make_training_data()

    with pytest.raises((ValueError, TypeError)):
        adapter.fit(training_data)

    assert not adapter.is_fitted


def test_too_few_training_samples_for_neighbors_is_rejected() -> None:
    adapter = LOFAdapter(n_neighbors=20)

    with pytest.raises(ValueError):
        adapter.fit(make_training_data(5))

    assert not adapter.is_fitted
