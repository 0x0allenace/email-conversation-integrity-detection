"""Isolation Forest adapter for BEC-007 behavioral anomaly detection."""

from __future__ import annotations

from collections.abc import Sequence
import math

from sklearn.ensemble import IsolationForest

from src.ml.model_interface import AnomalyModel


class IsolationForestAdapter(AnomalyModel):
    """Detect behavioral anomalies using scikit-learn's Isolation Forest.

    The adapter accepts the shared, preprocessed 30-feature schema defined
    by AnomalyModel. Missing-value imputation must happen before this adapter
    receives observations.

    The underlying scikit-learn model assigns lower score_samples values
    to more anomalous observations. This adapter negates those scores so
    that higher scores consistently indicate greater anomalousness.

    The decision threshold is derived from the fitted model's offset_,
    preserving the underlying Isolation Forest decision boundary.
    """

    def __init__(
        self,
        *,
        n_estimators: int = 100,
        max_samples: str | int | float = "auto",
        contamination: str | float = "auto",
        max_features: int | float = 1.0,
        bootstrap: bool = False,
        random_state: int | None = 42,
        n_jobs: int | None = None,
    ) -> None:
        super().__init__()

        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.max_features = max_features
        self.bootstrap = bootstrap
        self.random_state = random_state
        self.n_jobs = n_jobs

        self._model: IsolationForest | None = None

    def _fit_model(
        self,
        training_matrix: list[list[float]],
    ) -> float:
        """Fit Isolation Forest and return its anomaly-score threshold."""

        model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            max_features=self.max_features,
            bootstrap=self.bootstrap,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
        )

        model.fit(training_matrix)

        # sklearn uses lower scores for more anomalous observations.
        # Negating offset_ gives the equivalent threshold in our
        # higher-is-more-anomalous score convention.
        threshold = math.nextafter(
            -float(model.offset_),
            math.inf,
        )

        self._model = model

        return threshold

    def _score_model(
        self,
        matrix: list[list[float]],
    ) -> Sequence[float]:
        """Return anomaly scores, with higher values indicating anomalies."""

        if self._model is None:
            raise RuntimeError(
                "IsolationForestAdapter has no fitted underlying model"
            )

        # The shared interface permits empty inference batches. Avoid
        # passing an empty matrix to scikit-learn.
        if not matrix:
            return []

        return (-self._model.score_samples(matrix)).tolist()
