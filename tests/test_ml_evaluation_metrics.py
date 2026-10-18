"""Tests for binary anomaly-detection evaluation metrics."""

import pytest

from src.ml.evaluation_metrics import calculate_evaluation_metrics


def test_calculates_confusion_matrix_and_classification_metrics() -> None:
    result = calculate_evaluation_metrics(
        y_true=[0, 0, 1, 1],
        y_pred=[0, 1, 1, 1],
        anomaly_scores=[0.1, 0.8, 0.7, 0.9],
    )

    assert result["true_positives"] == 2
    assert result["false_positives"] == 1
    assert result["true_negatives"] == 1
    assert result["false_negatives"] == 0
    assert result["precision"] == pytest.approx(2 / 3)
    assert result["recall"] == pytest.approx(1.0)
    assert result["f1"] == pytest.approx(0.8)
    assert result["false_positive_rate"] == pytest.approx(0.5)
    assert result["average_precision"] == pytest.approx(5 / 6)


def test_accepts_boolean_predictions() -> None:
    result = calculate_evaluation_metrics(
        y_true=[0, 1, 1],
        y_pred=[False, True, False],
    )

    assert result["true_positives"] == 1
    assert result["false_negatives"] == 1
    assert result["true_negatives"] == 1
    assert result["false_positives"] == 0
    assert result["precision"] == pytest.approx(1.0)
    assert result["recall"] == pytest.approx(0.5)
    assert result["f1"] == pytest.approx(2 / 3)
    assert result["false_positive_rate"] == pytest.approx(0.0)
    assert result["average_precision"] is None


def test_returns_none_for_undefined_precision_and_recall() -> None:
    result = calculate_evaluation_metrics(
        y_true=[0, 0],
        y_pred=[0, 0],
    )

    assert result["precision"] is None
    assert result["recall"] is None
    assert result["f1"] == 0.0
    assert result["false_positive_rate"] == pytest.approx(0.0)
    assert result["average_precision"] is None


def test_returns_none_for_undefined_false_positive_rate() -> None:
    result = calculate_evaluation_metrics(
        y_true=[1, 1],
        y_pred=[1, 0],
    )

    assert result["precision"] == pytest.approx(1.0)
    assert result["recall"] == pytest.approx(0.5)
    assert result["false_positive_rate"] is None
    assert result["average_precision"] is None


def test_average_precision_requires_both_classes() -> None:
    result = calculate_evaluation_metrics(
        y_true=[1, 1, 1],
        y_pred=[1, 0, 1],
        anomaly_scores=[0.9, 0.2, 0.8],
    )

    assert result["average_precision"] is None


def test_average_precision_uses_continuous_scores() -> None:
    result = calculate_evaluation_metrics(
        y_true=[0, 1, 0, 1],
        y_pred=[0, 1, 0, 1],
        anomaly_scores=[0.1, 0.9, 0.4, 0.8],
    )

    assert result["average_precision"] == pytest.approx(1.0)


def test_rejects_empty_evaluation_data() -> None:
    with pytest.raises(ValueError, match="at least one"):
        calculate_evaluation_metrics([], [])


def test_rejects_mismatched_prediction_lengths() -> None:
    with pytest.raises(ValueError, match="same length"):
        calculate_evaluation_metrics(
            y_true=[0, 1],
            y_pred=[1],
        )


@pytest.mark.parametrize(
    "invalid_label",
    [2, -1, 0.0, 1.0, "1", None],
)
def test_rejects_invalid_ground_truth_labels(
    invalid_label: object,
) -> None:
    with pytest.raises(ValueError, match="binary label"):
        calculate_evaluation_metrics(
            y_true=[invalid_label],
            y_pred=[0],
        )


@pytest.mark.parametrize(
    "invalid_prediction",
    [2, -1, 0.0, 1.0, "1", None],
)
def test_rejects_invalid_predictions(
    invalid_prediction: object,
) -> None:
    with pytest.raises(ValueError, match="binary label"):
        calculate_evaluation_metrics(
            y_true=[0],
            y_pred=[invalid_prediction],
        )


@pytest.mark.parametrize(
    "invalid_score",
    [True, "0.5", None],
)
def test_rejects_invalid_score_types(
    invalid_score: object,
) -> None:
    with pytest.raises(TypeError, match="must be numeric"):
        calculate_evaluation_metrics(
            y_true=[0, 1],
            y_pred=[0, 1],
            anomaly_scores=[0.1, invalid_score],
        )


@pytest.mark.parametrize(
    "invalid_score",
    [float("nan"), float("inf"), -float("inf")],
)
def test_rejects_non_finite_scores(
    invalid_score: float,
) -> None:
    with pytest.raises(ValueError, match="must be finite"):
        calculate_evaluation_metrics(
            y_true=[0, 1],
            y_pred=[0, 1],
            anomaly_scores=[0.1, invalid_score],
        )


def test_rejects_score_length_mismatch() -> None:
    with pytest.raises(ValueError, match="length must match"):
        calculate_evaluation_metrics(
            y_true=[0, 1],
            y_pred=[0, 1],
            anomaly_scores=[0.1],
        )


def test_rejects_non_sequence_labels() -> None:
    with pytest.raises(TypeError, match="sequence"):
        calculate_evaluation_metrics(
            y_true="01",
            y_pred=[0, 1],
        )


def test_metrics_do_not_mutate_inputs() -> None:
    y_true = [0, 1, 0, 1]
    y_pred = [False, True, False, True]
    scores = [0.1, 0.9, 0.2, 0.8]

    original_true = y_true.copy()
    original_pred = y_pred.copy()
    original_scores = scores.copy()

    calculate_evaluation_metrics(y_true, y_pred, scores)

    assert y_true == original_true
    assert y_pred == original_pred
    assert scores == original_scores
