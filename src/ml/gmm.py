"""Gaussian Mixture Model adapter for BEC-007 behavioral anomalies."""

from __future__ import annotations

import math
from collections.abc import Sequence

import numpy as np
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler

from src.ml.model_interface import AnomalyModel


class GaussianMixtureAdapter(AnomalyModel):
    """Detect unusual behavior using negative log-likelihood scores.

    The decision threshold is calibrated using the configured upper quantile
    of training anomaly scores. Scaling and threshold calibration use training
    observations only.

    Higher scores indicate observations with lower likelihood under the
    fitted Gaussian mixture distribution.
    """

    def __init__(
        self,
        *,
        n_components: int = 2,
        covariance_type: str = "full",
        tol: float = 1e-3,
        reg_covar: float = 1e-6,
        max_iter: int = 100,
        n_init: int = 1,
        init_params: str = "kmeans",
        random_state: int | None = 42,
        contamination: float = 0.05,
    ) -> None:
        super().__init__()

        self._validate_configuration(
            n_components=n_components,
            covariance_type=covariance_type,
            tol=tol,
            reg_covar=reg_covar,
            max_iter=max_iter,
            n_init=n_init,
            init_params=init_params,
            random_state=random_state,
            contamination=contamination,
        )

        self.n_components = n_components
        self.covariance_type = covariance_type
        self.tol = float(tol)
        self.reg_covar = float(reg_covar)
        self.max_iter = max_iter
        self.n_init = n_init
        self.init_params = init_params
        self.random_state = random_state
        self.contamination = float(contamination)

        self._scaler: StandardScaler | None = None
        self._model: GaussianMixture | None = None

    @staticmethod
    def _validate_configuration(
        *,
        n_components: int,
        covariance_type: str,
        tol: float,
        reg_covar: float,
        max_iter: int,
        n_init: int,
        init_params: str,
        random_state: int | None,
        contamination: float,
    ) -> None:
        """Validate configuration before fitting."""

        def finite_number(name: str, value: object) -> float:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be numeric")

            try:
                converted = float(value)
            except OverflowError as exc:
                raise ValueError(f"{name} must be finite") from exc

            if not math.isfinite(converted):
                raise ValueError(f"{name} must be finite")

            return converted

        if isinstance(n_components, bool) or not isinstance(n_components, int):
            raise TypeError("n_components must be an integer")
        if n_components < 1:
            raise ValueError("n_components must be at least 1")

        if not isinstance(covariance_type, str) or covariance_type not in {
            "full",
            "tied",
            "diag",
            "spherical",
        }:
            raise ValueError(
                "covariance_type must be full, tied, diag, or spherical"
            )

        if finite_number("tol", tol) <= 0:
            raise ValueError("tol must be greater than 0")

        if finite_number("reg_covar", reg_covar) < 0:
            raise ValueError("reg_covar must be non-negative")

        if isinstance(max_iter, bool) or not isinstance(max_iter, int):
            raise TypeError("max_iter must be an integer")
        if max_iter < 1:
            raise ValueError("max_iter must be at least 1")

        if isinstance(n_init, bool) or not isinstance(n_init, int):
            raise TypeError("n_init must be an integer")
        if n_init < 1:
            raise ValueError("n_init must be at least 1")

        if not isinstance(init_params, str) or init_params not in {
            "kmeans",
            "k-means++",
            "random",
            "random_from_data",
        }:
            raise ValueError("Unsupported init_params value")

        if random_state is not None and (
            isinstance(random_state, bool)
            or not isinstance(random_state, int)
        ):
            raise TypeError("random_state must be an integer or None")

        contamination_value = finite_number("contamination", contamination)
        if not 0.0 < contamination_value < 0.5:
            raise ValueError(
                "contamination must be greater than 0 and less than 0.5"
            )

    def _fit_model(
        self,
        training_matrix: list[list[float]],
    ) -> float:
        """Fit scaling and GMM, then calibrate a training-score threshold."""

        if len(training_matrix) < self.n_components:
            raise ValueError(
                "Training data must contain at least n_components observations"
            )

        candidate_scaler = StandardScaler()
        scaled_training = candidate_scaler.fit_transform(training_matrix)

        candidate_model = GaussianMixture(
            n_components=self.n_components,
            covariance_type=self.covariance_type,
            tol=self.tol,
            reg_covar=self.reg_covar,
            max_iter=self.max_iter,
            n_init=self.n_init,
            init_params=self.init_params,
            random_state=self.random_state,
        )
        candidate_model.fit(scaled_training)

        if not candidate_model.converged_:
            raise RuntimeError(
                "GaussianMixture failed to converge within max_iter"
            )

        training_scores = -candidate_model.score_samples(scaled_training)

        if not np.isfinite(training_scores).all():
            raise ValueError(
                "GaussianMixture produced non-finite training anomaly scores"
            )

        threshold = float(
            np.quantile(training_scores, 1.0 - self.contamination)
        )

        if not math.isfinite(threshold):
            raise ValueError(
                "GaussianMixture produced a non-finite decision threshold"
            )

        self._scaler = candidate_scaler
        self._model = candidate_model

        return threshold

    def _score_model(
        self,
        matrix: list[list[float]],
    ) -> Sequence[float]:
        """Return negative log-likelihood scores for unseen observations."""

        if self._model is None or self._scaler is None:
            raise RuntimeError(
                "GaussianMixtureAdapter has no fitted model"
            )

        if not matrix:
            return []

        scaled_matrix = self._scaler.transform(matrix)

        return (-self._model.score_samples(scaled_matrix)).tolist()
