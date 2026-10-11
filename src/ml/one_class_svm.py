"""One-Class SVM adapter for BEC-007 behavioral anomaly detection."""

from __future__ import annotations

import math
from collections.abc import Sequence

from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from src.ml.model_interface import AnomalyModel


class OneClassSVMAdapter(AnomalyModel):
    """Detect behavioral anomalies using a One-Class SVM.

    Input features must already have been processed by the shared
    BEC007Preprocessor. This adapter fits its own StandardScaler using
    training data only.

    The adapter negates scikit-learn's native scores so higher values
    indicate greater anomalousness.

    The threshold preserves the fitted model's native decision boundary.
    It is derived from the fitted model's offset, not from validation or
    test observations.
    """

    def __init__(
        self,
        *,
        nu: float = 0.05,
        kernel: str = "rbf",
        degree: int = 3,
        gamma: str | float = "scale",
        coef0: float = 0.0,
        tol: float = 1e-3,
        shrinking: bool = True,
        cache_size: float = 200,
        max_iter: int = -1,
    ) -> None:
        super().__init__()

        self._validate_configuration(
            nu=nu,
            kernel=kernel,
            degree=degree,
            gamma=gamma,
            coef0=coef0,
            tol=tol,
            shrinking=shrinking,
            cache_size=cache_size,
            max_iter=max_iter,
        )

        self.nu = nu
        self.kernel = kernel
        self.degree = degree
        self.gamma = gamma
        self.coef0 = coef0
        self.tol = tol
        self.shrinking = shrinking
        self.cache_size = cache_size
        self.max_iter = max_iter

        self._scaler: StandardScaler | None = None
        self._model: OneClassSVM | None = None

    @staticmethod
    def _validate_configuration(
        *,
        nu: float,
        kernel: str,
        degree: int,
        gamma: str | float,
        coef0: float,
        tol: float,
        shrinking: bool,
        cache_size: float,
        max_iter: int,
    ) -> None:
        """Reject invalid model parameters before fitting."""

        def require_finite_number(name: str, value: object) -> float:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be a numeric value")

            try:
                converted = float(value)
            except OverflowError as exc:
                raise ValueError(f"{name} must be finite") from exc

            if not math.isfinite(converted):
                raise ValueError(f"{name} must be finite")

            return converted

        nu_value = require_finite_number("nu", nu)
        if not 0.0 < nu_value <= 1.0:
            raise ValueError("nu must be greater than 0 and at most 1")

        if not isinstance(kernel, str) or kernel not in {
            "linear",
            "poly",
            "rbf",
            "sigmoid",
        }:
            raise ValueError(
                "kernel must be 'linear', 'poly', 'rbf', or 'sigmoid'"
            )

        if isinstance(degree, bool) or not isinstance(degree, int):
            raise TypeError("degree must be an integer")
        if degree < 1:
            raise ValueError("degree must be at least 1")

        if isinstance(gamma, str):
            if gamma not in {"scale", "auto"}:
                raise ValueError(
                    "gamma must be 'scale', 'auto', or a positive number"
                )
        else:
            gamma_value = require_finite_number("gamma", gamma)
            if gamma_value <= 0.0:
                raise ValueError("numeric gamma must be greater than 0")

        require_finite_number("coef0", coef0)

        tol_value = require_finite_number("tol", tol)
        if tol_value <= 0.0:
            raise ValueError("tol must be greater than 0")

        if not isinstance(shrinking, bool):
            raise TypeError("shrinking must be a boolean")

        cache_size_value = require_finite_number("cache_size", cache_size)
        if cache_size_value <= 0.0:
            raise ValueError("cache_size must be greater than 0")

        if isinstance(max_iter, bool) or not isinstance(max_iter, int):
            raise TypeError("max_iter must be an integer")
        if max_iter != -1 and max_iter < 1:
            raise ValueError("max_iter must be -1 or a positive integer")

    def _fit_model(
        self,
        training_matrix: list[list[float]],
    ) -> float:
        """Fit scaling and One-Class SVM using training data only."""

        candidate_scaler = StandardScaler()
        scaled_training = candidate_scaler.fit_transform(training_matrix)

        candidate_model = OneClassSVM(
            nu=self.nu,
            kernel=self.kernel,
            degree=self.degree,
            gamma=self.gamma,
            coef0=self.coef0,
            tol=self.tol,
            shrinking=self.shrinking,
            cache_size=self.cache_size,
            max_iter=self.max_iter,
        )
        candidate_model.fit(scaled_training)

        # sklearn defines:
        # decision_function(X) = score_samples(X) - offset_
        #
        # Native prediction is anomalous when decision_function < 0.
        # Since this adapter negates score_samples, its equivalent
        # threshold is just above -offset_. This preserves the native
        # strict boundary with the shared interface's score >= threshold
        # convention.
        offset_values = candidate_model.offset_.tolist()
        if len(offset_values) != 1:
            raise ValueError(
                "One-Class SVM must expose exactly one decision offset"
            )

        threshold = math.nextafter(
            -float(offset_values[0]),
            math.inf,
        )

        # Publish fitted state only after scaling and model fitting succeed.
        self._scaler = candidate_scaler
        self._model = candidate_model

        return threshold

    def _score_model(
        self,
        matrix: list[list[float]],
    ) -> Sequence[float]:
        """Score observations without refitting the scaler or model."""

        if self._model is None or self._scaler is None:
            raise RuntimeError("OneClassSVMAdapter has no fitted model")

        if not matrix:
            return []

        scaled_matrix = self._scaler.transform(matrix)

        # Negate native scores so higher values mean more anomalous.
        return (-self._model.score_samples(scaled_matrix)).tolist()
