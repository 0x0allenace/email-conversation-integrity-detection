"""Local Outlier Factor adapter for BEC-007 behavioral anomalies."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

from src.ml.model_interface import AnomalyModel


class LOFAdapter(AnomalyModel):
    """Detect behavioral anomalies using LOF novelty detection.

    Input features must already have been processed by the shared
    BEC007Preprocessor. This adapter fits its own StandardScaler using
    training data only.

    The adapter negates sklearn's native scores so higher values indicate
    greater anomalousness, matching the shared AnomalyModel contract.
    """

    def __init__(
        self,
        *,
        n_neighbors: int = 20,
        contamination: str | float = "auto",
        leaf_size: int = 30,
        metric: str = "minkowski",
        p: float = 2,
        n_jobs: int | None = None,
    ) -> None:
        super().__init__()

        self.n_neighbors = n_neighbors
        self.contamination = contamination
        self.leaf_size = leaf_size
        self.metric = metric
        self.p = p
        self.n_jobs = n_jobs

        self._scaler: StandardScaler | None = None
        self._model: LocalOutlierFactor | None = None

    def _fit_model(
        self,
        training_matrix: list[list[float]],
    ) -> float:
        """Fit scaling and LOF using the training partition only."""

        if len(training_matrix) <= self.n_neighbors:
            raise ValueError(
                "Training data must contain at least "
                "n_neighbors + 1 observations"
            )

        candidate_scaler = StandardScaler()
        scaled_training = candidate_scaler.fit_transform(training_matrix)

        candidate_model = LocalOutlierFactor(
            n_neighbors=self.n_neighbors,
            contamination=self.contamination,
            novelty=True,
            leaf_size=self.leaf_size,
            metric=self.metric,
            p=self.p,
            n_jobs=self.n_jobs,
        )
        candidate_model.fit(scaled_training)

        # sklearn flags an observation as anomalous when its native
        # decision_function is strictly negative:
        #
        #     score_samples(X) - offset_ < 0
        #
        # Our shared interface flags anomalies when the negated score
        # is greater than or equal to the threshold. Moving the negated
        # offset by one representable float preserves that boundary.
        threshold = math.nextafter(
            -float(candidate_model.offset_),
            math.inf,
        )

        # Publish fitted state only after both operations succeed.
        self._scaler = candidate_scaler
        self._model = candidate_model

        return threshold

    def _score_model(
        self,
        matrix: list[list[float]],
    ) -> Sequence[float]:
        """Score unseen observations without refitting either component."""

        if self._model is None or self._scaler is None:
            raise RuntimeError("LOFAdapter has no fitted model")

        if not matrix:
            return []

        scaled_matrix = self._scaler.transform(matrix)

        # sklearn's native score_samples assigns lower scores to more
        # anomalous observations. Negate them to follow our shared
        # higher-is-more-anomalous convention.
        native_scores = self._model.score_samples(scaled_matrix)

        return (-native_scores).tolist()
