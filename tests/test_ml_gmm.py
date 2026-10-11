"""Tests for the Gaussian Mixture Model anomaly adapter."""

import math

import pytest

from src.ml.feature_extractor import SCALAR_FEATURE_NAMES
from src.ml.gmm import GaussianMixtureAdapter
from src.ml.model_interface import MODEL_FEATURE_NAMES


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
    adapter = GaussianMixtureAdapter()

    result = adapter.fit(make_training_data())

    assert result is adapter
    assert adapter.is_fitted
    assert math.isfinite(adapter.threshold)
    assert adapter._scaler is not None
    assert adapter._model is not None


def test_score_samples_returns_finite_scores() -> None:
    adapter = GaussianMixtureAdapter()
    adapter.fit(make_training_data())

    scores = adapter.score_samples(make_training_data(8))

    assert len(scores) == 8
    assert all(math.isfinite(score) for score in scores)


def test_adapter_scores_are_negative_log_likelihoods() -> None:
    adapter = GaussianMixtureAdapter()
    adapter.fit(make_training_data())

    observations = make_training_data(8)
    vectors = adapter._validate_batch(
        observations,
        require_nonempty=False,
    )

    assert adapter._scaler is not None
    assert adapter._model is not None

    scaled_vectors = adapter._scaler.transform(vectors)
    expected = -adapter._model.score_samples(scaled_vectors)

    assert adapter.score_samples(observations) == pytest.approx(expected)


def test_empty_inference_batch_returns_empty_results() -> None:
    adapter = GaussianMixtureAdapter()
    adapter.fit(make_training_data())

    assert adapter.score_samples([]) == []
    assert adapter.predict([]) == []


def test_inference_does_not_refit_scaler_or_model() -> None:
    adapter = GaussianMixtureAdapter()
    adapter.fit(make_training_data())

    assert adapter._scaler is not None
    assert adapter._model is not None

    scaler = adapter._scaler
    model = adapter._model

    scaler_mean = scaler.mean_.copy()
    model_means = model.means_.copy()
    model_weights = model.weights_.copy()
    model_covariances = model.covariances_.copy()

    observations = make_training_data(5)

    adapter.score_samples(observations)
    adapter.predict(observations)

    assert adapter._scaler is scaler
    assert adapter._model is model
    assert (scaler.mean_ == scaler_mean).all()
    assert (model.means_ == model_means).all()
    assert (model.weights_ == model_weights).all()
    assert (model.covariances_ == model_covariances).all()


def test_invalid_feature_schema_is_rejected() -> None:
    adapter = GaussianMixtureAdapter()
    adapter.fit(make_training_data())

    observation = make_observation(0)
    observation.pop(MODEL_FEATURE_NAMES[0])

    with pytest.raises(ValueError, match="invalid feature schema"):
        adapter.score_samples([observation])


def test_scoring_before_fit_is_rejected() -> None:
    adapter = GaussianMixtureAdapter()

    with pytest.raises(RuntimeError, match="must be fitted"):
        adapter.score_samples(make_training_data(1))


def test_failed_fit_does_not_mark_adapter_fitted() -> None:
    adapter = GaussianMixtureAdapter()

    with pytest.raises(ValueError, match="at least one"):
        adapter.fit([])

    assert not adapter.is_fitted


@pytest.mark.parametrize(
    "configuration",
    [
        {"n_components": 0},
        {"n_components": True},
        {"covariance_type": "invalid"},
        {"covariance_type": None},
        {"covariance_type": []},
        {"tol": 0.0},
        {"reg_covar": -1.0},
        {"max_iter": 0},
        {"n_init": 0},
        {"init_params": "invalid"},
        {"random_state": True},
    ],
)
def test_invalid_configuration_is_rejected(
    configuration: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        GaussianMixtureAdapter(**configuration)


def test_training_batch_must_have_enough_observations() -> None:
    adapter = GaussianMixtureAdapter(n_components=3)

    with pytest.raises(ValueError, match="n_components observations"):
        adapter.fit(make_training_data(2))


def test_refit_failure_clears_fitted_state() -> None:
    adapter = GaussianMixtureAdapter()
    adapter.fit(make_training_data())

    with pytest.raises(ValueError, match="at least one"):
        adapter.fit([])

    assert not adapter.is_fitted

    with pytest.raises(RuntimeError, match="must be fitted"):
        adapter.score_samples(make_training_data(1))


def test_threshold_uses_training_score_quantile() -> None:
    import numpy as np

    contamination = 0.10
    training_data = make_training_data(40)
    adapter = GaussianMixtureAdapter(contamination=contamination)

    adapter.fit(training_data)

    assert adapter._scaler is not None
    assert adapter._model is not None

    training_vectors = adapter._validate_batch(
        training_data,
        require_nonempty=True,
    )
    scaled_training = adapter._scaler.transform(training_vectors)
    training_scores = -adapter._model.score_samples(scaled_training)
    expected_threshold = float(
        np.quantile(training_scores, 1.0 - contamination)
    )

    assert adapter.threshold == pytest.approx(expected_threshold)


def test_non_converged_gmm_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.ml import gmm as gmm_module

    original_fit = gmm_module.GaussianMixture.fit

    def fit_without_convergence(self, X, y=None):
        original_fit(self, X, y)
        self.converged_ = False
        return self

    monkeypatch.setattr(
        gmm_module.GaussianMixture,
        "fit",
        fit_without_convergence,
    )

    adapter = GaussianMixtureAdapter()

    with pytest.raises(RuntimeError, match="failed to converge"):
        adapter.fit(make_training_data())

    assert not adapter.is_fitted


@pytest.mark.parametrize(
    "contamination",
    [
        0,
        0.5,
        -0.1,
        True,
        float("nan"),
        float("inf"),
    ],
)
def test_invalid_contamination_is_rejected(
    contamination: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        GaussianMixtureAdapter(contamination=contamination)
