"""Evaluation metrics for binary anomaly-detection experiments."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

from sklearn.metrics import average_precision_score


def _validate_binary_labels(
    values: Sequence[Any],
    *,
    name: str,
) -> list[int]:
    """Validate binary labels and normalize them to integers."""

    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise TypeError(f"{name} must be a sequence of binary labels")

    validated: list[int] = []

    for index, value in enumerate(values):
        if isinstance(value, bool):
            validated.append(int(value))
        elif type(value) is int and value in (0, 1):
            validated.append(value)
        else:
            raise ValueError(
                f"{name}[{index}] must be a binary label (0 or 1)"
            )

    return validated


def _validate_scores(
    scores: Sequence[Any],
    *,
    expected_count: int,
) -> list[float]:
    """Validate continuous anomaly scores."""

    if isinstance(scores, (str, bytes)) or not isinstance(scores, Sequence):
        raise TypeError("anomaly_scores must be a sequence of numeric scores")

    if len(scores) != expected_count:
        raise ValueError(
            "anomaly_scores length must match y_true and y_pred"
        )

    validated: list[float] = []

    for index, score in enumerate(scores):
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise TypeError(
                f"anomaly_scores[{index}] must be numeric"
            )

        try:
            numeric_score = float(score)
        except (OverflowError, ValueError) as exc:
            raise ValueError(
                f"anomaly_scores[{index}] must be finite"
            ) from exc

        if not math.isfinite(numeric_score):
            raise ValueError(
                f"anomaly_scores[{index}] must be finite"
            )

        validated.append(numeric_score)

    return validated


def calculate_evaluation_metrics(
    y_true: Sequence[Any],
    y_pred: Sequence[Any],
    anomaly_scores: Sequence[Any] | None = None,
) -> dict[str, int | float | None]:
    """Calculate binary classification and optional ranking metrics.

    Labels use 0 for normal observations and 1 for anomalies.
    Predictions accept booleans or integer labels 0 and 1.
    Higher anomaly scores indicate greater anomalousness.

    Undefined precision, recall, and false-positive rates are represented
    by None when their denominators are zero. F1 uses a zero-division
    policy of 0.0. Average precision is None when scores are omitted or
    the evaluation labels contain only one class.
    """

    true_labels = _validate_binary_labels(y_true, name="y_true")
    predicted_labels = _validate_binary_labels(y_pred, name="y_pred")

    if len(true_labels) != len(predicted_labels):
        raise ValueError("y_true and y_pred must have the same length")

    if not true_labels:
        raise ValueError("Evaluation data must contain at least one observation")

    true_positives = sum(
        truth == 1 and prediction == 1
        for truth, prediction in zip(true_labels, predicted_labels)
    )
    false_positives = sum(
        truth == 0 and prediction == 1
        for truth, prediction in zip(true_labels, predicted_labels)
    )
    true_negatives = sum(
        truth == 0 and prediction == 0
        for truth, prediction in zip(true_labels, predicted_labels)
    )
    false_negatives = sum(
        truth == 1 and prediction == 0
        for truth, prediction in zip(true_labels, predicted_labels)
    )

    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    fpr_denominator = false_positives + true_negatives

    precision = (
        true_positives / precision_denominator
        if precision_denominator
        else None
    )
    recall = (
        true_positives / recall_denominator
        if recall_denominator
        else None
    )
    f1_denominator = 2 * true_positives + false_positives + false_negatives
    f1 = (
        2 * true_positives / f1_denominator
        if f1_denominator
        else 0.0
    )
    false_positive_rate = (
        false_positives / fpr_denominator
        if fpr_denominator
        else None
    )

    average_precision: float | None = None

    if anomaly_scores is not None:
        validated_scores = _validate_scores(
            anomaly_scores,
            expected_count=len(true_labels),
        )

        if len(set(true_labels)) == 2:
            average_precision = float(
                average_precision_score(true_labels, validated_scores)
            )

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "false_negatives": false_negatives,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": false_positive_rate,
        "average_precision": average_precision,
    }
