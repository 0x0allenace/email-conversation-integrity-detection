"""Integration tests for the real BEC-007 anomaly-model evaluation pipeline."""

import math

from src.ml.dataset_split import DatasetRecord
from src.ml.evaluation_runner import evaluate_models
from src.ml.feature_extractor import (
    BEHAVIORAL_FEATURE_NAMES,
    SCALAR_FEATURE_NAMES,
)
from src.ml.gmm import GaussianMixtureAdapter
from src.ml.isolation_forest import IsolationForestAdapter
from src.ml.lof import LOFAdapter
from src.ml.one_class_svm import OneClassSVMAdapter


def build_features(index: int, label: int) -> dict[str, float | int | None]:
    """Build valid, varied BEC-007 features without passing labels to models."""

    features: dict[str, float | int | None] = {
        "frequency_interval_ratio": 0.5 + (index % 9) * 0.2,
        "recipient_count": 1 + (index % 5),
        "historical_recipient_count_median": 1 + (index % 3),
        "recipient_count_ratio": 0.5 + (index % 7) * 0.3,
        "cc_count": index % 4,
        "historical_cc_count_median": 1 + (index % 2),
        "cc_count_ratio": 0.25 + (index % 6) * 0.2,
        "attachment_present": index % 2,
        "historical_attachment_usage_rate": 0.1 + (index % 8) * 0.1,
    }

    for position, name in enumerate(BEHAVIORAL_FEATURE_NAMES):
        # Vary the behavioral flags across observations. The label is used
        # only to generate test data, never supplied to the model adapters.
        features[name] = int((index + position + label) % 2 == 0)

    # Include realistic missing values in nullable scalar fields.
    if index % 7 == 0:
        features["frequency_interval_ratio"] = None
    if index % 8 == 0:
        features["historical_recipient_count_median"] = None

    return features


def build_records(count_per_class: int = 30) -> list[DatasetRecord]:
    """Build a deterministic, balanced evaluation dataset."""

    records = []

    for label in (0, 1):
        for index in range(count_per_class):
            observation_id = f"{label}-{index}"
            records.append(
                DatasetRecord(
                    observation_id=observation_id,
                    features=build_features(index, label),
                    label=label,
                    group_id=f"group-{label}-{index}",
                )
            )

    return records


def build_real_model_factories():
    """Create small, reproducible configurations of the real adapters."""

    return {
        "isolation_forest": lambda: IsolationForestAdapter(
            n_estimators=20,
            random_state=42,
        ),
        "lof": lambda: LOFAdapter(
            n_neighbors=5,
            contamination="auto",
        ),
        "one_class_svm": lambda: OneClassSVMAdapter(
            nu=0.05,
            gamma="scale",
        ),
        "gmm": lambda: GaussianMixtureAdapter(
            n_components=2,
            max_iter=100,
            n_init=1,
            random_state=42,
            contamination=0.05,
        ),
    }


def test_real_adapters_complete_shared_held_out_evaluation() -> None:
    """All four real adapters should evaluate the same held-out observations."""

    report = evaluate_models(
        build_records(),
        build_real_model_factories(),
        split_strategy="random_stratified",
        seed=42,
    )

    assert report.split_strategy == "random_stratified"
    assert report.seed == 42
    assert report.split_sizes == {
        "training": 42,
        "validation": 10,
        "test": 8,
    }
    assert len(report.test_observation_ids) == 8

    expected_metric_names = {
        "true_positives",
        "false_positives",
        "true_negatives",
        "false_negatives",
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "average_precision",
    }

    assert set(report.model_results) == {
        "isolation_forest",
        "lof",
        "one_class_svm",
        "gmm",
    }

    for name, result in report.model_results.items():
        assert result.status == "success", (
            f"{name} failed during integration evaluation: {result.error}"
        )
        assert result.threshold is not None
        assert math.isfinite(result.threshold)
        assert result.metrics is not None
        assert set(result.metrics) == expected_metric_names

        for metric_name in (
            "precision",
            "recall",
            "f1",
            "false_positive_rate",
            "average_precision",
        ):
            value = result.metrics[metric_name]
            assert value is not None, (
                f"{name}: expected a defined {metric_name}"
            )
            assert math.isfinite(value)
            assert 0.0 <= value <= 1.0

        confusion_total = sum(
            result.metrics[key]
            for key in (
                "true_positives",
                "false_positives",
                "true_negatives",
                "false_negatives",
            )
        )
        assert confusion_total == report.split_sizes["test"]


def test_real_adapters_evaluation_is_reproducible_for_fixed_seed() -> None:
    """Repeated runs with fixed seeds should reproduce splits and metrics."""

    first = evaluate_models(
        build_records(),
        build_real_model_factories(),
        seed=42,
    )
    second = evaluate_models(
        build_records(),
        build_real_model_factories(),
        seed=42,
    )

    assert first.training_observation_ids == second.training_observation_ids
    assert first.validation_observation_ids == second.validation_observation_ids
    assert first.test_observation_ids == second.test_observation_ids
    assert first.preprocessing_imputation_values == (
        second.preprocessing_imputation_values
    )

    for name in first.model_results:
        first_result = first.model_results[name]
        second_result = second.model_results[name]

        assert first_result.status == second_result.status
        assert first_result.threshold == second_result.threshold
        assert first_result.metrics == second_result.metrics
