"""Tests for the leakage-aware ML evaluation runner."""

from collections.abc import Sequence
from statistics import median
from typing import Any

import numpy as np
import pytest
import sklearn
import warnings


from src.ml.dataset_split import DatasetRecord
from src.ml.evaluation_runner import evaluate_models
from src.ml.feature_extractor import (
    BEC007_FEATURE_SCHEMA_VERSION,
    BEHAVIORAL_FEATURE_NAMES,
    SCALAR_FEATURE_NAMES,
)
from src.ml.gmm import GaussianMixtureAdapter
from src.ml.isolation_forest import IsolationForestAdapter
from src.ml.lof import LOFAdapter
from src.ml.model_interface import AnomalyModel, MODEL_FEATURE_NAMES
from src.ml.one_class_svm import OneClassSVMAdapter
from src.ml.preprocessing import (
    ALLOWED_MISSING_FEATURE_NAMES,
    MISSINGNESS_INDICATOR_NAMES,
)


NULLABLE_FEATURE = "frequency_interval_ratio"


def build_features(value: float = 1.0) -> dict[str, Any]:
    """Build a valid BEC-007 feature dictionary."""

    features = {
        **{
            name: (
                0
                if name == "attachment_present"
                else value
            )
            for name in SCALAR_FEATURE_NAMES
        },
        **{name: 0 for name in BEHAVIORAL_FEATURE_NAMES},
    }
    return features


def build_records(count_per_class: int = 20) -> list[DatasetRecord]:
    """Build a deterministic, balanced dataset."""

    records = []

    for label in (0, 1):
        for index in range(count_per_class):
            features = build_features(value=float(index + label * 100))
            records.append(
                DatasetRecord(
                    observation_id=f"{label}-{index}",
                    features=features,
                    label=label,
                    group_id=f"group-{label}-{index}",
                )
            )

    return records


class RecordingModel(AnomalyModel):
    """A lightweight model that records the data it receives."""

    def __init__(
        self,
        *,
        threshold: float = 0.5,
        scores: Sequence[float] | None = None,
    ) -> None:
        super().__init__()
        self.configured_threshold = threshold
        self.configured_scores = scores
        self.training_data: list[dict[str, Any]] | None = None
        self.scored_data: list[dict[str, Any]] | None = None

    def _fit_model(
        self,
        training_matrix: list[list[float]],
    ) -> float:
        self.training_data = [
            dict(zip(self._feature_names(), row))
            for row in training_matrix
        ]
        return self.configured_threshold

    def _score_model(
        self,
        matrix: list[list[float]],
    ) -> Sequence[float]:
        self.scored_data = [
            dict(zip(self._feature_names(), row))
            for row in matrix
        ]

        if self.configured_scores is not None:
            return self.configured_scores

        return [float(index) for index in range(len(matrix))]

    @staticmethod
    def _feature_names() -> tuple[str, ...]:
        from src.ml.model_interface import MODEL_FEATURE_NAMES

        return MODEL_FEATURE_NAMES


def test_runner_evaluates_models_on_a_shared_test_partition() -> None:
    first_model = RecordingModel(threshold=2.0)
    second_model = RecordingModel(threshold=3.0)

    report = evaluate_models(
        build_records(),
        {
            "first": lambda: first_model,
            "second": lambda: second_model,
        },
        seed=17,
    )

    assert report.split_strategy == "random_stratified"
    assert report.seed == 17
    assert report.split_sizes == {
        "training": 28,
        "validation": 6,
        "test": 6,
    }
    assert report.model_results["first"].status == "success"
    assert report.model_results["second"].status == "success"
    assert report.model_results["first"].threshold == pytest.approx(2.0)
    assert report.model_results["second"].threshold == pytest.approx(3.0)
    assert first_model.training_data is not None
    assert second_model.training_data is not None
    assert first_model.scored_data is not None
    assert second_model.scored_data is not None
    assert first_model.scored_data == second_model.scored_data
    assert len(first_model.scored_data) == report.split_sizes["test"]




def test_runner_group_split_prevents_employee_leakage() -> None:
    records = []

    # Each employee has ten observations, with both normal and anomalous
    # labels. All observations for an employee must stay in one partition.
    for employee_index in range(12):
        group_id = f"employee-{employee_index:02d}"

        for observation_index in range(10):
            label = observation_index % 2
            records.append(
                DatasetRecord(
                    observation_id=(
                        f"{group_id}-observation-{observation_index:02d}"
                    ),
                    features=build_features(
                        value=float(employee_index + observation_index)
                    ),
                    label=label,
                    group_id=group_id,
                )
            )

    report = evaluate_models(
        records,
        {"recording": RecordingModel},
        split_strategy="group",
        seed=17,
    )

    group_by_observation_id = {
        record.observation_id: record.group_id
        for record in records
    }

    training_groups = {
        group_by_observation_id[observation_id]
        for observation_id in report.training_observation_ids
    }
    validation_groups = {
        group_by_observation_id[observation_id]
        for observation_id in report.validation_observation_ids
    }
    test_groups = {
        group_by_observation_id[observation_id]
        for observation_id in report.test_observation_ids
    }

    # No employee may appear in more than one partition.
    assert training_groups.isdisjoint(validation_groups)
    assert training_groups.isdisjoint(test_groups)
    assert validation_groups.isdisjoint(test_groups)

    # Every observation must appear exactly once.
    all_partition_ids = (
        report.training_observation_ids
        + report.validation_observation_ids
        + report.test_observation_ids
    )
    expected_ids = {record.observation_id for record in records}

    assert len(all_partition_ids) == len(records)
    assert len(set(all_partition_ids)) == len(records)
    assert set(all_partition_ids) == expected_ids

    # Every supplied employee must be assigned to a partition.
    expected_groups = {
        f"employee-{index:02d}" for index in range(12)
    }
    assert training_groups | validation_groups | test_groups == expected_groups

def test_runner_preserves_warnings_from_successful_model_fit() -> None:
    class WarningModel(RecordingModel):
        def _fit_model(
            self,
            training_matrix: list[list[float]],
        ) -> float:
            warnings.warn("synthetic fit warning", UserWarning)
            return super()._fit_model(training_matrix)

    report = evaluate_models(
        build_records(),
        {"warning_model": WarningModel},
        seed=17,
    )

    result = report.model_results["warning_model"]

    assert result.status == "success"
    assert any(
        "UserWarning: synthetic fit warning" in message
        for message in result.warning_messages
    )


def test_runner_preserves_warnings_when_model_fit_fails() -> None:
    class FailingWarningModel(RecordingModel):
        def _fit_model(
            self,
            training_matrix: list[list[float]],
        ) -> float:
            warnings.warn("warning before failure", RuntimeWarning)
            raise RuntimeError("synthetic fit failure")

    report = evaluate_models(
        build_records(),
        {"failing_model": FailingWarningModel},
        seed=17,
    )

    result = report.model_results["failing_model"]

    assert result.status == "error"
    assert result.error is not None
    assert "RuntimeError" in result.error
    assert "synthetic fit failure" in result.error
    assert any(
        "RuntimeWarning: warning before failure" in message
        for message in result.warning_messages
    )


def test_runner_reports_split_ids_and_label_counts() -> None:
    report = evaluate_models(
        build_records(),
        {"recording": RecordingModel},
        seed=17,
    )

    assert len(report.training_observation_ids) == 28
    assert len(report.validation_observation_ids) == 6
    assert len(report.test_observation_ids) == 6

    all_ids = (
        report.training_observation_ids
        + report.validation_observation_ids
        + report.test_observation_ids
    )
    assert len(all_ids) == len(set(all_ids)) == 40

    assert report.split_label_counts["training"] == {0: 14, 1: 14}
    assert report.split_label_counts["validation"] == {0: 3, 1: 3}
    assert report.split_label_counts["test"] == {0: 3, 1: 3}


def test_runner_fits_imputation_using_training_data_only() -> None:
    records = build_records()

    # Make the nullable feature missing in several records. The expected
    # imputation value is calculated only from the reported training IDs.
    for record in records:
        index = int(record.observation_id.split("-")[1])
        if index % 4 == 0:
            record.features[NULLABLE_FEATURE] = None
        else:
            record.features[NULLABLE_FEATURE] = float(index)

    report = evaluate_models(
        records,
        {"recording": RecordingModel},
        seed=17,
    )

    training_values = [
        record.features[NULLABLE_FEATURE]
        for record in records
        if record.observation_id in report.training_observation_ids
        and record.features[NULLABLE_FEATURE] is not None
    ]

    assert report.preprocessing_imputation_values[NULLABLE_FEATURE] == pytest.approx(
        median(training_values)
    )


def test_runner_does_not_pass_labels_or_ids_to_models() -> None:
    model = RecordingModel()

    report = evaluate_models(
        build_records(),
        {"recording": lambda: model},
        seed=17,
    )

    assert report.model_results["recording"].status == "success"
    assert model.training_data is not None
    assert model.scored_data is not None

    for observation in model.training_data + model.scored_data:
        assert "label" not in observation
        assert "observation_id" not in observation
        assert "group_id" not in observation
        assert len(observation) == 30


def test_runner_continues_when_one_model_fails() -> None:
    def broken_factory() -> AnomalyModel:
        raise RuntimeError("intentional test failure")

    report = evaluate_models(
        build_records(),
        {
            "broken": broken_factory,
            "working": RecordingModel,
        },
        seed=17,
    )

    assert report.model_results["broken"].status == "error"
    assert report.model_results["broken"].error == (
        "RuntimeError: intentional test failure"
    )
    assert report.model_results["broken"].metrics is None
    assert report.model_results["working"].status == "success"


def test_runner_records_invalid_model_output_as_an_error() -> None:
    model = RecordingModel(scores=[0.1])

    report = evaluate_models(
        build_records(),
        {"invalid-output": lambda: model},
        seed=17,
    )

    result = report.model_results["invalid-output"]
    assert result.status == "error"
    assert result.error is not None
    assert result.metrics is None


def test_runner_is_reproducible_for_the_same_seed() -> None:
    first = evaluate_models(
        build_records(),
        {"recording": RecordingModel},
        seed=29,
    )
    second = evaluate_models(
        build_records(),
        {"recording": RecordingModel},
        seed=29,
    )

    assert first.training_observation_ids == second.training_observation_ids
    assert first.validation_observation_ids == second.validation_observation_ids
    assert first.test_observation_ids == second.test_observation_ids
    assert first.preprocessing_imputation_values == (
        second.preprocessing_imputation_values
    )
    assert first.model_results["recording"].metrics == (
        second.model_results["recording"].metrics
    )


def test_runner_reports_runtime_versions() -> None:
    import sys

    report = evaluate_models(
        build_records(),
        {"recording": RecordingModel},
        seed=17,
    )

    assert report.python_version == sys.version.split()[0]
    assert report.scikit_learn_version == sklearn.__version__
    assert report.numpy_version == np.__version__


def test_runner_records_isolation_forest_configuration() -> None:
    model = IsolationForestAdapter(
        n_estimators=25,
        max_samples=0.8,
        contamination=0.1,
        max_features=0.75,
        bootstrap=True,
        random_state=19,
        n_jobs=1,
    )

    report = evaluate_models(
        build_records(),
        {"isolation_forest": lambda: model},
        seed=17,
    )

    result = report.model_results["isolation_forest"]

    assert result.status == "success"
    assert result.model_class == (
        f"{IsolationForestAdapter.__module__}."
        f"{IsolationForestAdapter.__qualname__}"
    )
    assert result.model_configuration == {
        "n_estimators": 25,
        "max_samples": 0.8,
        "contamination": 0.1,
        "max_features": 0.75,
        "bootstrap": True,
        "random_state": 19,
        "n_jobs": 1,
    }
    assert result.threshold_method == "fitted_decision_boundary"
    assert result.threshold is not None


def test_runner_records_gaussian_mixture_configuration() -> None:
    model = GaussianMixtureAdapter(
        n_components=2,
        covariance_type="diag",
        tol=0.002,
        reg_covar=1e-5,
        max_iter=150,
        n_init=2,
        init_params="kmeans",
        random_state=23,
        contamination=0.1,
    )

    report = evaluate_models(
        build_records(),
        {"gmm": lambda: model},
        seed=17,
    )

    result = report.model_results["gmm"]

    assert result.status == "success"
    assert result.model_class == (
        f"{GaussianMixtureAdapter.__module__}."
        f"{GaussianMixtureAdapter.__qualname__}"
    )
    assert result.model_configuration == {
        "n_components": 2,
        "covariance_type": "diag",
        "tol": 0.002,
        "reg_covar": 1e-5,
        "max_iter": 150,
        "n_init": 2,
        "init_params": "kmeans",
        "random_state": 23,
        "contamination": 0.1,
    }
    assert result.threshold_method == "training_score_quantile"
    assert result.threshold is not None


@pytest.mark.parametrize(
    ("model", "expected_configuration"),
    [
        (
            LOFAdapter(
                n_neighbors=10,
                contamination=0.1,
                leaf_size=25,
                metric="euclidean",
                p=2,
                n_jobs=1,
            ),
            {
                "n_neighbors": 10,
                "contamination": 0.1,
                "leaf_size": 25,
                "metric": "euclidean",
                "p": 2,
                "n_jobs": 1,
            },
        ),
        (
            OneClassSVMAdapter(
                nu=0.1,
                kernel="linear",
                degree=2,
                gamma="auto",
                coef0=0.25,
                tol=0.002,
                shrinking=False,
                cache_size=150,
                max_iter=500,
            ),
            {
                "nu": 0.1,
                "kernel": "linear",
                "degree": 2,
                "gamma": "auto",
                "coef0": 0.25,
                "tol": 0.002,
                "shrinking": False,
                "cache_size": 150,
                "max_iter": 500,
            },
        ),
    ],
)
def test_runner_records_lof_and_svm_configuration(
    model: AnomalyModel,
    expected_configuration: dict[str, Any],
) -> None:
    report = evaluate_models(
        build_records(),
        {"configured_model": lambda: model},
        seed=17,
    )

    result = report.model_results["configured_model"]

    assert result.status == "success", result.error
    assert result.model_class == (
        f"{type(model).__module__}.{type(model).__qualname__}"
    )
    assert result.model_configuration == expected_configuration
    assert result.threshold_method == "fitted_decision_boundary"
    assert result.threshold is not None


def test_runner_marks_custom_model_metadata_as_unknown() -> None:
    report = evaluate_models(
        build_records(),
        {"recording": RecordingModel},
        seed=17,
    )

    result = report.model_results["recording"]

    assert result.status == "success"
    assert result.model_class == (
        f"{RecordingModel.__module__}.{RecordingModel.__qualname__}"
    )
    assert result.model_configuration is None
    assert result.threshold_method == "unknown"


def test_runner_rejects_unsupported_split_strategy() -> None:
    with pytest.raises(ValueError, match="split_strategy"):
        evaluate_models(
            build_records(),
            {"recording": RecordingModel},
            split_strategy="unsupported",  # type: ignore[arg-type]
        )


def test_runner_rejects_empty_model_factory_mapping() -> None:
    with pytest.raises(ValueError, match="non-empty mapping"):
        evaluate_models(build_records(), {})


def test_runner_rejects_non_callable_factory() -> None:
    with pytest.raises(TypeError, match="must be callable"):
        evaluate_models(
            build_records(),
            {"invalid": 123},  # type: ignore[dict-item]
        )

def test_runner_continues_when_invalid_output_and_factory_fail() -> None:
    def broken_factory() -> AnomalyModel:
        raise RuntimeError("intentional factory failure")

    invalid_model = RecordingModel(scores=[0.1])

    report = evaluate_models(
        build_records(),
        {
            "broken-factory": broken_factory,
            "invalid-output": lambda: invalid_model,
            "working": RecordingModel,
        },
        seed=17,
    )

    assert report.model_results["broken-factory"].status == "error"
    assert report.model_results["broken-factory"].metrics is None

    assert report.model_results["invalid-output"].status == "error"
    assert report.model_results["invalid-output"].metrics is None

    assert report.model_results["working"].status == "success"
    assert report.model_results["working"].metrics is not None





def test_runner_preserves_optional_dataset_metadata() -> None:
    metadata = {
        "dataset_id": "bec-007-synthetic",
        "generator_version": "1.0.0",
        "seed": 42,
        "observation_count": 40,
        "group_count": 4,
        "label_counts": {"0": 32, "1": 8},
        "scenario_counts": {"recipient_novelty": 8},
        "requested_anomaly_rate": 0.20,
        "actual_anomaly_rate": 0.20,
        "label_provenance": (
            "Synthetic scenario-generated labels; "
            "not independently verified malicious-email outcomes."
        ),
    }

    report = evaluate_models(
        build_records(),
        {"recording": RecordingModel},
        seed=17,
        dataset_metadata=metadata,
    )

    assert report.dataset_metadata == metadata
    assert report.dataset_metadata is not metadata


def test_runner_dataset_metadata_defaults_to_none() -> None:
    report = evaluate_models(
        build_records(),
        {"recording": RecordingModel},
        seed=17,
    )

    assert report.dataset_metadata is None


def test_runner_rejects_invalid_dataset_metadata() -> None:
    with pytest.raises(TypeError, match="dataset_metadata must be a mapping"):
        evaluate_models(
            build_records(),
            {"recording": RecordingModel},
            dataset_metadata=["not", "a", "mapping"],  # type: ignore[arg-type]
        )

def test_runner_reports_feature_schema_and_preprocessing_configuration() -> None:
    report = evaluate_models(
        build_records(),
        {"recording": RecordingModel},
        seed=17,
    )

    assert report.feature_schema_version == BEC007_FEATURE_SCHEMA_VERSION
    assert report.model_feature_names == MODEL_FEATURE_NAMES
    assert len(report.model_feature_names) == 30

    configuration = report.preprocessing_configuration

    assert configuration["imputation_strategy"] == "median"
    assert configuration["imputation_fit_partition"] == "training"
    assert configuration["allowed_missing_features"] == (
        ALLOWED_MISSING_FEATURE_NAMES
    )
    assert configuration["missingness_indicator_names"] == (
        MISSINGNESS_INDICATOR_NAMES
    )
    assert configuration["original_feature_count"] == 24
    assert configuration["missingness_indicator_count"] == 6
    assert configuration["model_input_feature_count"] == 30
