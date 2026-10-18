"""Run the reproducible BEC-007 synthetic anomaly-detection benchmark."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import math
from pathlib import Path
import sys
from typing import Any


# Support direct execution from the repository root:
# python3 scripts/run_ml_evaluation.py
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ml.evaluation_runner import evaluate_models
from src.ml.gmm import GaussianMixtureAdapter
from src.ml.isolation_forest import IsolationForestAdapter
from src.ml.lof import LOFAdapter
from src.ml.one_class_svm import OneClassSVMAdapter
from src.ml.synthetic_dataset import (
    DEFAULT_ANOMALY_RATE,
    DEFAULT_OBSERVATIONS,
    DEFAULT_RECORDS_PER_EMPLOYEE,
    DEFAULT_SEED,
    GENERATOR_VERSION,
    generate_synthetic_dataset,
)


DATASET_ID = "bec-007-synthetic-enterprise-email-v1"


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line interface."""

    parser = argparse.ArgumentParser(
        description=(
            "Evaluate four anomaly-detection models on a reproducible "
            "synthetic BEC-007 dataset and write a JSON report."
        ),
        epilog=(
            "Results measure performance on synthetic scenario-generated "
            "labels; they do not establish real-world BEC detection efficacy."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/ml-evaluation-report.json"),
        help="JSON report path (default: results/ml-evaluation-report.json).",
    )
    parser.add_argument(
        "--observations",
        type=int,
        default=DEFAULT_OBSERVATIONS,
        help=f"Number of synthetic observations (default: {DEFAULT_OBSERVATIONS}).",
    )
    parser.add_argument(
        "--anomaly-rate",
        type=float,
        default=DEFAULT_ANOMALY_RATE,
        help=f"Requested synthetic anomaly rate (default: {DEFAULT_ANOMALY_RATE}).",
    )
    parser.add_argument(
        "--records-per-employee",
        type=int,
        default=DEFAULT_RECORDS_PER_EMPLOYEE,
        help=(
            "Observations per synthetic employee "
            f"(default: {DEFAULT_RECORDS_PER_EMPLOYEE})."
        ),
    )
    parser.add_argument(
        "--dataset-seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"Dataset generation seed (default: {DEFAULT_SEED}).",
    )
    parser.add_argument(
        "--split-seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"Partitioning seed (default: {DEFAULT_SEED}).",
    )
    parser.add_argument(
        "--split-strategy",
        choices=("group", "random_stratified"),
        default="group",
        help="Partitioning strategy (default: group).",
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.70,
        help="Requested training proportion (default: 0.70).",
    )
    parser.add_argument(
        "--validation-ratio",
        type=float,
        default=0.15,
        help="Requested validation proportion (default: 0.15).",
    )
    parser.add_argument(
        "--test-ratio",
        type=float,
        default=0.15,
        help="Requested test proportion (default: 0.15).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow replacing an existing output report.",
    )
    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    """Reject invalid CLI settings before generating data."""

    if args.observations < 30:
        raise ValueError("--observations must be at least 30")

    if args.records_per_employee < 2:
        raise ValueError("--records-per-employee must be at least 2")

    if args.observations % args.records_per_employee != 0:
        raise ValueError(
            "--observations must be divisible by --records-per-employee"
        )

    if (
        not math.isfinite(args.anomaly_rate)
        or not 0 < args.anomaly_rate < 1
    ):
        raise ValueError("--anomaly-rate must be finite and between 0 and 1")

    if args.observations // args.records_per_employee < 3:
        raise ValueError("At least three employee groups are required")

    ratios = (
        args.train_ratio,
        args.validation_ratio,
        args.test_ratio,
    )
    if not all(math.isfinite(value) and value > 0 for value in ratios):
        raise ValueError("All split ratios must be finite and greater than zero")

    if not math.isclose(sum(ratios), 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError("Split ratios must sum to 1.0")


def build_model_factories() -> dict[str, Any]:
    """Return fresh models with explicit benchmark configurations."""

    return {
        "isolation_forest": lambda: IsolationForestAdapter(
            n_estimators=200,
            max_samples="auto",
            contamination="auto",
            max_features=1.0,
            bootstrap=False,
            random_state=42,
            n_jobs=1,
        ),
        "lof": lambda: LOFAdapter(
            n_neighbors=20,
            contamination="auto",
            leaf_size=30,
            metric="minkowski",
            p=2,
            n_jobs=1,
        ),
        "one_class_svm": lambda: OneClassSVMAdapter(
            nu=0.05,
            kernel="rbf",
            degree=3,
            gamma="scale",
            coef0=0.0,
            tol=1e-3,
            shrinking=True,
            cache_size=200,
            max_iter=-1,
        ),
        "gaussian_mixture": lambda: GaussianMixtureAdapter(
            n_components=2,
            covariance_type="full",
            tol=1e-3,
            reg_covar=1e-6,
            max_iter=200,
            n_init=3,
            init_params="kmeans",
            random_state=42,
            contamination=0.05,
        ),
    }


def build_report(
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Generate the dataset, evaluate models, and build a JSON-safe report."""

    generated = generate_synthetic_dataset(
        n_observations=args.observations,
        anomaly_rate=args.anomaly_rate,
        seed=args.dataset_seed,
        records_per_employee=args.records_per_employee,
        return_metadata=True,
    )
    records, metadata = generated

    # Deliberately omit scenario_by_observation_id: it is ground-truth
    # diagnostic metadata and must not enter model inputs or the report's
    # per-observation data.
    dataset_metadata = {
        "dataset_id": DATASET_ID,
        "generator_version": metadata.generator_version,
        "generator_seed": metadata.seed,
        "observation_count": metadata.observation_count,
        "group_count": metadata.group_count,
        "label_counts": {
            str(label): count
            for label, count in metadata.label_counts.items()
        },
        "scenario_counts": dict(metadata.scenario_counts),
        "actual_anomaly_rate": metadata.anomaly_rate,
        "requested_anomaly_rate": metadata.requested_anomaly_rate,
        "label_provenance": (
            "Synthetic labels are assigned by scenario-generation rules; "
            "they are not independently verified malicious-email outcomes."
        ),
    }

    evaluation = evaluate_models(
        records,
        build_model_factories(),
        split_strategy=args.split_strategy,
        seed=args.split_seed,
        train_ratio=args.train_ratio,
        validation_ratio=args.validation_ratio,
        test_ratio=args.test_ratio,
        dataset_metadata=dataset_metadata,
    )

    report = asdict(evaluation)
    report["report_schema_version"] = "1.0.0"
    report["dataset_metadata"] = dataset_metadata
    report["requested_split_ratios"] = {
        "training": args.train_ratio,
        "validation": args.validation_ratio,
        "test": args.test_ratio,
    }
    report["experiment"] = {
        "dataset_id": DATASET_ID,
        "generator_version": GENERATOR_VERSION,
        "dataset_seed": args.dataset_seed,
        "split_seed": args.split_seed,
        "split_strategy": args.split_strategy,
        "records_per_employee": args.records_per_employee,
        "synthetic_benchmark_only": True,
        "real_world_detection_efficacy_established": False,
    }

    # Fail explicitly rather than silently emitting invalid JSON containing
    # NaN or Infinity.
    json.dumps(report, allow_nan=False)
    return report


def write_report(
    report: dict[str, Any],
    output_path: Path,
    *,
    force: bool = False,
) -> None:
    """Write the report without accidental replacement of an existing file."""

    destination = output_path.expanduser()
    if not destination.is_absolute():
        destination = Path.cwd() / destination

    if destination.exists() and not force:
        raise FileExistsError(
            f"Output already exists: {destination}. "
            "Choose another --output path or pass --force to replace it."
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(
        report,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    ) + "\n"

    # Exclusive creation prevents accidental replacement if another process
    # creates the destination after the initial existence check.
    if force:
        destination.write_text(serialized, encoding="utf-8")
    else:
        with destination.open("x", encoding="utf-8") as handle:
            handle.write(serialized)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        validate_arguments(args)

        destination = args.output.expanduser()
        if not destination.is_absolute():
            destination = Path.cwd() / destination

        if destination.exists() and not args.force:
            raise FileExistsError(
                f"Output already exists: {destination}. "
                "Choose another --output path or pass --force to replace it."
            )

        report = build_report(args)
        write_report(report, args.output, force=args.force)

    except (ValueError, TypeError, FileExistsError, OSError) as exc:
        parser.error(str(exc))

    results = report["model_results"]
    print(f"Evaluation report written to: {args.output}")
    print(f"Dataset: {DATASET_ID}")
    print(f"Observations: {args.observations}")
    print(f"Split strategy: {args.split_strategy}")
    print("Model outcomes:")

    for name, result in results.items():
        status = result["status"]
        if status == "success":
            metrics = result["metrics"]
            print(
                f"  {name}: {status}; "
                f"precision={metrics['precision']}, "
                f"recall={metrics['recall']}, "
                f"f1={metrics['f1']}, "
                f"average_precision={metrics['average_precision']}"
            )
        else:
            print(f"  {name}: {status}; {result['error']}")

    if any(result["status"] == "error" for result in results.values()):
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
