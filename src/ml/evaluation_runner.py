"""Leakage-aware evaluation runner for BEC-007 anomaly-detection models."""

from __future__ import annotations

import sys
import warnings
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import numpy as np
import sklearn

from src.ml.dataset_split import (
    DEFAULT_SEED,
    DatasetRecord,
    DatasetSplit,
    split_by_group,
    split_random_stratified,
)
from src.ml.evaluation_metrics import calculate_evaluation_metrics
from src.ml.feature_extractor import BEC007_FEATURE_SCHEMA_VERSION
from src.ml.gmm import GaussianMixtureAdapter
from src.ml.isolation_forest import IsolationForestAdapter
from src.ml.lof import LOFAdapter
from src.ml.model_interface import AnomalyModel, MODEL_FEATURE_NAMES
from src.ml.one_class_svm import OneClassSVMAdapter
from src.ml.preprocessing import (
    ALLOWED_MISSING_FEATURE_NAMES,
    BEC007Preprocessor,
    MISSINGNESS_INDICATOR_NAMES,
)


SplitStrategy = Literal["random_stratified", "group"]
ModelFactory = Callable[[], AnomalyModel]


def _model_metadata(
    model: AnomalyModel,
) -> tuple[str, dict[str, Any] | None, str]:
    """Return explicit, reproducible metadata for a supported model."""

    model_class = f"{type(model).__module__}.{type(model).__qualname__}"

    configurations: dict[
        type[AnomalyModel],
        tuple[tuple[str, ...], str],
    ] = {
        IsolationForestAdapter: (
            (
                "n_estimators",
                "max_samples",
                "contamination",
                "max_features",
                "bootstrap",
                "random_state",
                "n_jobs",
            ),
            "fitted_decision_boundary",
        ),
        LOFAdapter: (
            (
                "n_neighbors",
                "contamination",
                "leaf_size",
                "metric",
                "p",
                "n_jobs",
            ),
            "fitted_decision_boundary",
        ),
        OneClassSVMAdapter: (
            (
                "nu",
                "kernel",
                "degree",
                "gamma",
                "coef0",
                "tol",
                "shrinking",
                "cache_size",
                "max_iter",
            ),
            "fitted_decision_boundary",
        ),
        GaussianMixtureAdapter: (
            (
                "n_components",
                "covariance_type",
                "tol",
                "reg_covar",
                "max_iter",
                "n_init",
                "init_params",
                "random_state",
                "contamination",
            ),
            "training_score_quantile",
        ),
    }

    for adapter_type, (parameter_names, threshold_method) in (
        configurations.items()
    ):
        if isinstance(model, adapter_type):
            configuration = {
                name: getattr(model, name)
                for name in parameter_names
            }
            return model_class, configuration, threshold_method

    return model_class, None, "unknown"


@dataclass(frozen=True)
class ModelEvaluation:
    """Outcome of evaluating one model on the shared test partition."""

    status: Literal["success", "error"]
    threshold: float | None
    metrics: Mapping[str, int | float | None] | None
    error: str | None = None
    model_class: str | None = None
    model_configuration: Mapping[str, Any] | None = None
    threshold_method: str = "unknown"
    warning_messages: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvaluationReport:
    """Evaluation outcomes and metadata for reproducibility."""

    split_strategy: str
    seed: int
    requested_ratios: tuple[float, float, float]
    split_sizes: Mapping[str, int]
    split_label_counts: Mapping[str, Mapping[int, int]]
    training_observation_ids: tuple[str, ...]
    validation_observation_ids: tuple[str, ...]
    test_observation_ids: tuple[str, ...]
    preprocessing_imputation_values: Mapping[str, float]
    model_results: Mapping[str, ModelEvaluation]
    python_version: str
    scikit_learn_version: str
    numpy_version: str
    feature_schema_version: str
    model_feature_names: tuple[str, ...]
    preprocessing_configuration: Mapping[str, Any]
    dataset_metadata: Mapping[str, Any] | None



def _capture_warnings(
    operation: Callable[[], Any],
    warning_messages: list[str],
) -> Any:
    """Run one operation and retain any warnings it emits."""

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            return operation()
        finally:
            warning_messages.extend(
                f"{item.category.__name__}: {item.message}"
                for item in caught
            )


def _label_counts(
    records: Sequence[DatasetRecord],
) -> dict[int, int]:
    """Count normal and anomalous observations in a partition."""

    return {
        0: sum(record.label == 0 for record in records),
        1: sum(record.label == 1 for record in records),
    }


def _split_records(
    records: Sequence[DatasetRecord],
    *,
    strategy: SplitStrategy,
    seed: int,
    train_ratio: float,
    validation_ratio: float,
    test_ratio: float,
) -> DatasetSplit:
    """Use the existing validated dataset-splitting implementations."""

    split_function = {
        "random_stratified": split_random_stratified,
        "group": split_by_group,
    }[strategy]

    return split_function(
        records,
        seed=seed,
        train_ratio=train_ratio,
        validation_ratio=validation_ratio,
        test_ratio=test_ratio,
    )


def evaluate_models(
    records: Sequence[DatasetRecord],
    model_factories: Mapping[str, ModelFactory],
    *,
    split_strategy: SplitStrategy = "random_stratified",
    seed: int = DEFAULT_SEED,
    train_ratio: float = 0.70,
    validation_ratio: float = 0.15,
    test_ratio: float = 0.15,
    dataset_metadata: Mapping[str, Any] | None = None,
) -> EvaluationReport:
    """Evaluate fresh anomaly models against one shared held-out test set.

    The dataset is split before preprocessing. Shared imputation values are
    learned exclusively from training features. Model adapters receive only
    transformed feature dictionaries: labels, observation IDs, and group IDs
    are never passed to them.

    The validation partition is reserved and reported but is not used for
    model selection or threshold tuning by this runner.

    Optional dataset metadata is copied into the report for
    reproducibility. It is descriptive only and is never passed
    to the models.

    A failure in one model is recorded in that model's result; other models
    are still evaluated. Dataset splitting and shared preprocessing failures
    are raised to the caller.
    """

    if split_strategy not in ("random_stratified", "group"):
        raise ValueError(
            "split_strategy must be 'random_stratified' or 'group'"
        )

    if not isinstance(model_factories, Mapping) or not model_factories:
        raise ValueError("model_factories must be a non-empty mapping")

    if dataset_metadata is not None and not isinstance(
        dataset_metadata, Mapping
    ):
        raise TypeError("dataset_metadata must be a mapping or None")

    for name, factory in model_factories.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Model names must be non-empty strings")
        if not callable(factory):
            raise TypeError(f"Factory for model {name!r} must be callable")

    split = _split_records(
        records,
        strategy=split_strategy,
        seed=seed,
        train_ratio=train_ratio,
        validation_ratio=validation_ratio,
        test_ratio=test_ratio,
    )

    preprocessor = BEC007Preprocessor()
    preprocessor.fit([
        dict(record.features)
        for record in split.training
    ])

    training_data = preprocessor.transform([
        dict(record.features)
        for record in split.training
    ])
    test_data = preprocessor.transform([
        dict(record.features)
        for record in split.test
    ])

    y_true = [record.label for record in split.test]
    results: dict[str, ModelEvaluation] = {}

    for name, factory in model_factories.items():
        model_class = None
        model_configuration = None
        threshold_method = "unknown"
        warning_messages: list[str] = []

        try:
            model = _capture_warnings(factory, warning_messages)

            if not isinstance(model, AnomalyModel):
                raise TypeError(
                    f"Factory for model {name!r} must return an "
                    "AnomalyModel instance"
                )

            (
                model_class,
                model_configuration,
                threshold_method,
            ) = _model_metadata(model)

            _capture_warnings(
                lambda: model.fit(training_data),
                warning_messages,
            )

            # Score each test observation once. The shared model contract
            # defines an anomaly as a score greater than or equal to the
            # fitted training-derived threshold.
            scores = _capture_warnings(
                lambda: model.score_samples(test_data),
                warning_messages,
            )
            threshold = model.threshold
            predictions = [
                score >= threshold
                for score in scores
            ]

            metrics = calculate_evaluation_metrics(
                y_true,
                predictions,
                scores,
            )

            results[name] = ModelEvaluation(
                status="success",
                threshold=threshold,
                metrics=metrics,
                model_class=model_class,
                model_configuration=model_configuration,
                threshold_method=threshold_method,
                warning_messages=tuple(warning_messages),
            )

        except Exception as exc:
            results[name] = ModelEvaluation(
                status="error",
                threshold=None,
                metrics=None,
                error=f"{type(exc).__name__}: {exc}",
                model_class=model_class,
                model_configuration=model_configuration,
                threshold_method=threshold_method,
                warning_messages=tuple(warning_messages),
            )

    return EvaluationReport(
        split_strategy=split.strategy,
        seed=split.seed,
        requested_ratios=split.ratios,
        split_sizes=split.sizes,
        split_label_counts={
            "training": _label_counts(split.training),
            "validation": _label_counts(split.validation),
            "test": _label_counts(split.test),
        },
        training_observation_ids=tuple(
            record.observation_id for record in split.training
        ),
        validation_observation_ids=tuple(
            record.observation_id for record in split.validation
        ),
        test_observation_ids=tuple(
            record.observation_id for record in split.test
        ),
        preprocessing_imputation_values=dict(
            preprocessor.imputation_values
        ),
        model_results=results,
        python_version=sys.version.split()[0],
        scikit_learn_version=sklearn.__version__,
        numpy_version=np.__version__,
        feature_schema_version=BEC007_FEATURE_SCHEMA_VERSION,
        model_feature_names=MODEL_FEATURE_NAMES,
        preprocessing_configuration={
            "imputation_strategy": "median",
            "imputation_fit_partition": "training",
            "allowed_missing_features": ALLOWED_MISSING_FEATURE_NAMES,
            "missingness_indicator_names": MISSINGNESS_INDICATOR_NAMES,
            "original_feature_count": 24,
            "missingness_indicator_count": len(MISSINGNESS_INDICATOR_NAMES),
            "model_input_feature_count": len(MODEL_FEATURE_NAMES),
        },
        dataset_metadata=(
            dict(dataset_metadata)
            if dataset_metadata is not None
            else None
        ),
    )
