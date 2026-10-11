"""Tests for the One-Class SVM anomaly-model adapter."""

import math

import pytest

from src.ml.feature_extractor import SCALAR_FEATURE_NAMES
from src.ml.model_interface import MODEL_FEATURE_NAMES
from src.ml.one_class_svm import OneClassSVMAdapter


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


def make_training_data(
    count: int = 40,
) -> list[dict[str, float]]:
    """Create a deterministic training batch."""

    return [make_observation(index) for index in range(count)]


def test_fit_returns_adapter_and_sets_finite_threshold() -> None:
    adapter = OneClassSVMAdapter()

    result = adapter.fit(make_training_data())

    assert result is adapter
    assert adapter.is_fitted
    assert math.isfinite(adapter.threshold)
    assert adapter._scaler is not None
    assert adapter._model is not None


def test_score_samples_returns_finite_scores() -> None:
    adapter = OneClassSVMAdapter()
    adapter.fit(make_training_data())

    scores = adapter.score_samples(make_training_data(8))

    assert len(scores) == 8
    assert all(math.isfinite(score) for score in scores)


def test_adapter_scores_are_negated_sklearn_scores() -> None:
    adapter = OneClassSVMAdapter()
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


def test_predictions_match_sklearn_native_boundary() -> None:
    adapter = OneClassSVMAdapter()
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
    adapter = OneClassSVMAdapter()
    adapter.fit(make_training_data())

    assert adapter.score_samples([]) == []
    assert adapter.predict([]) == []


def test_inference_does_not_refit_scaler_or_model() -> None:
    adapter = OneClassSVMAdapter()
    adapter.fit(make_training_data())

    assert adapter._scaler is not None
    assert adapter._model is not None

    scaler = adapter._scaler
    model = adapter._model
    scaler_mean = scaler.mean_.copy()
    training_samples = model.shape_fit_[0]

    adapter.score_samples(make_training_data(5))
    adapter.predict(make_training_data(5))

    assert adapter._scaler is scaler
    assert adapter._model is model
    assert adapter._scaler.mean_.tolist() == scaler_mean.tolist()
    assert adapter._model.shape_fit_[0] == training_samples


def test_scaler_is_fitted_using_training_data_only() -> None:
    training_data = make_training_data()
    adapter = OneClassSVMAdapter()
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
    adapter = OneClassSVMAdapter()
    adapter.fit(make_training_data())

    invalid_observation = make_observation(0)
    invalid_observation.pop(MODEL_FEATURE_NAMES[0])

    with pytest.raises(ValueError, match="invalid feature schema"):
        adapter.score_samples([invalid_observation])


def test_scoring_before_fit_is_rejected() -> None:
    adapter = OneClassSVMAdapter()

    with pytest.raises(RuntimeError, match="must be fitted"):
        adapter.score_samples(make_training_data(1))


def test_failed_fit_does_not_mark_adapter_fitted() -> None:
    adapter = OneClassSVMAdapter()

    with pytest.raises(ValueError, match="at least one"):
        adapter.fit([])

    assert not adapter.is_fitted


@pytest.mark.parametrize(
    "configuration",
    [
        {"nu": 0.0},
        {"nu": 1.1},
        {"nu": -0.1},
        {"kernel": "invalid-kernel"},
        {"gamma": 0.0},
        {"degree": 0},
        {"tol": 0.0},
        {"cache_size": 0.0},
        {"max_iter": 0},
    ],
)
def test_invalid_configuration_is_rejected(
    configuration: dict[str, object],
) -> None:
    """Reject invalid One-Class SVM settings during initialization."""
    with pytest.raises((TypeError, ValueError, OverflowError)):
        OneClassSVMAdapter(**configuration)


def test_refit_failure_clears_fitted_state() -> None:
    adapter = OneClassSVMAdapter()
    adapter.fit(make_training_data())

    with pytest.raises(ValueError, match="at least one"):
        adapter.fit([])

    assert not adapter.is_fitted

    with pytest.raises(RuntimeError, match="must be fitted"):
        adapter.score_samples(make_training_data(1))
