"""Generate reproducible synthetic enterprise email behaviour for ML evaluation."""

from __future__ import annotations

import math
import random
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from src.ml.dataset_split import DatasetRecord
from src.ml.feature_extractor import BEHAVIORAL_FEATURE_NAMES
from src.ml.preprocessing import validate_bec_007_features


GENERATOR_VERSION = "1.0.0"
DEFAULT_SEED = 42
DEFAULT_OBSERVATIONS = 2_000
DEFAULT_ANOMALY_RATE = 0.20
DEFAULT_RECORDS_PER_EMPLOYEE = 10

# Only these scalar features may legitimately be missing.
MISSINGABLE_FEATURES = (
    "frequency_interval_ratio",
    "historical_recipient_count_median",
    "recipient_count_ratio",
    "historical_cc_count_median",
    "cc_count_ratio",
    "historical_attachment_usage_rate",
)

ANOMALY_SCENARIOS = (
    "recipient_novelty",
    "unusual_timing",
    "frequency_change",
    "recipient_count_change",
    "attachment_change",
    "relationship_or_sequence_change",
)

SCENARIO_FEATURES = {
    "recipient_novelty": (
        "recipient_novelty",
        "recipient_frequency_anomaly",
        "recipient_relationship_anomaly",
    ),
    "unusual_timing": (
        "sending_hour_anomaly",
        "historical_hour_anomaly",
        "timezone_anomaly",
    ),
    "frequency_change": (
        "frequency_anomaly",
        "recipient_recency_anomaly",
    ),
    "recipient_count_change": (
        "recipient_count_anomaly",
        "cc_count_anomaly",
    ),
    "attachment_change": (
        "attachment_usage_anomaly",
    ),
    "relationship_or_sequence_change": (
        "recipient_role_anomaly",
        "recipient_group_anomaly",
        "recipient_sequence_anomaly",
    ),
}


@dataclass(frozen=True)
class SyntheticDatasetMetadata:
    """Describe the synthetic dataset without exposing metadata as features."""

    generator_version: str
    seed: int
    observation_count: int
    group_count: int
    label_counts: dict[int, int]
    scenario_counts: dict[str, int]
    anomaly_rate: float
    requested_anomaly_rate: float
    scenario_by_observation_id: dict[str, str | None]


def _bounded_ratio(
    numerator: float,
    denominator: float,
    *,
    minimum: float = 0.05,
    maximum: float = 20.0,
) -> float:
    """Calculate a finite ratio while keeping synthetic values realistic."""

    if denominator <= 0:
        return 1.0

    return min(max(numerator / denominator, minimum), maximum)


def _generate_features(
    rng: random.Random,
    *,
    scenario: str | None,
) -> dict[str, float | int | None]:
    """Generate correlated communication features for one observation."""

    # Start with a plausible employee communication baseline.
    historical_recipient_count = rng.choice((1, 2, 2, 3, 3, 4))
    recipient_count = max(
        1,
        min(
            8,
            round(rng.gauss(historical_recipient_count, 0.8)),
        ),
    )

    historical_cc_count = rng.choice((0, 0, 1, 1, 2, 3))
    cc_count = max(
        0,
        min(8, round(rng.gauss(historical_cc_count, 0.9))),
    )

    attachment_rate = rng.uniform(0.05, 0.65)
    attachment_present = int(rng.random() < attachment_rate)

    historical_interval = rng.uniform(30.0, 1_440.0)
    current_interval = historical_interval * math.exp(
        rng.gauss(0.0, 0.35)
    )

    # Background behavioural flags have the same baseline probability
    # regardless of the label. Scenarios add deviations independently.
    behavioral_features = {
        name: int(rng.random() < 0.08)
        for name in BEHAVIORAL_FEATURE_NAMES
    }

    if scenario is not None:
        # A scenario raises the probability of its signals without making
        # every signal deterministically positive.
        for feature_name in SCENARIO_FEATURES[scenario]:
            behavioral_features[feature_name] = int(
                rng.random() < 0.80
            )

        if scenario == "recipient_novelty":
            recipient_count = max(recipient_count, 2)

        elif scenario == "unusual_timing":
            # The timing deviation is represented by behavioural flags.
            # Other feature values remain plausible.
            pass

        elif scenario == "frequency_change":
            current_interval = historical_interval * rng.uniform(
                0.05, 0.30
            )

        elif scenario == "recipient_count_change":
            recipient_count = min(
                8,
                max(
                    historical_recipient_count + 2,
                    recipient_count,
                ),
            )
            cc_count = min(8, max(cc_count, historical_cc_count + 1))

        elif scenario == "attachment_change":
            attachment_present = 1 - attachment_present

        elif scenario == "relationship_or_sequence_change":
            # Novel relationship and sequence signals are expressed by
            # the scenario's flags, not by synthetic identifiers.
            pass

    recipient_count_ratio = _bounded_ratio(
        recipient_count,
        historical_recipient_count,
    )

    if historical_cc_count > 0:
        cc_count_ratio: float | None = _bounded_ratio(
            cc_count,
            historical_cc_count,
        )
    else:
        cc_count_ratio = None

    features: dict[str, float | int | None] = {
        "frequency_interval_ratio": _bounded_ratio(
            current_interval,
            historical_interval,
        ),
        "recipient_count": recipient_count,
        "historical_recipient_count_median": historical_recipient_count,
        "recipient_count_ratio": recipient_count_ratio,
        "cc_count": cc_count,
        "historical_cc_count_median": historical_cc_count,
        "cc_count_ratio": cc_count_ratio,
        "attachment_present": attachment_present,
        "historical_attachment_usage_rate": attachment_rate,
        **behavioral_features,
    }

    # Missingness is independent of the class label and limited to fields
    # explicitly permitted by the preprocessing contract.
    missing_probability = 0.04
    for feature_name in MISSINGABLE_FEATURES:
        if rng.random() < missing_probability:
            features[feature_name] = None

    validate_bec_007_features(features)
    return features


def generate_synthetic_dataset(
    *,
    n_observations: int = DEFAULT_OBSERVATIONS,
    anomaly_rate: float = DEFAULT_ANOMALY_RATE,
    seed: int = DEFAULT_SEED,
    records_per_employee: int = DEFAULT_RECORDS_PER_EMPLOYEE,
    return_metadata: bool = False,
) -> list[DatasetRecord] | tuple[
    list[DatasetRecord], SyntheticDatasetMetadata
]:
    """Generate deterministic, grouped synthetic email observations.

    Labels:
        0: synthetic normal communication.
        1: synthetic anomalous communication.

    Group IDs represent synthetic employees. Each group contains both
    classes, allowing group-based splits to retain both labels in each
    partition when the configured group allocation permits it.

    This is a synthetic benchmark, not evidence of real-world detection
    performance. Labels come from scenario definitions rather than
    independently verified malicious-email outcomes.
    """

    if type(n_observations) is not int or n_observations < 30:
        raise ValueError("n_observations must be an integer of at least 30")

    if (
        type(records_per_employee) is not int
        or records_per_employee < 2
    ):
        raise ValueError("records_per_employee must be an integer of at least 2")

    if n_observations % records_per_employee != 0:
        raise ValueError(
            "n_observations must be divisible by records_per_employee"
        )

    if type(seed) is not int:
        raise TypeError("seed must be an integer")

    if (
        isinstance(anomaly_rate, bool)
        or not isinstance(anomaly_rate, (int, float))
        or not math.isfinite(anomaly_rate)
        or not 0 < anomaly_rate < 1
    ):
        raise ValueError("anomaly_rate must be finite and between 0 and 1")

    group_count = n_observations // records_per_employee

    if group_count < 3:
        raise ValueError("At least three employee groups are required")

    anomalous_per_group = round(
        records_per_employee * anomaly_rate
    )

    if not 0 < anomalous_per_group < records_per_employee:
        raise ValueError(
            "Each employee group must contain normal and anomalous records; "
            "adjust anomaly_rate or records_per_employee"
        )

    if type(return_metadata) is not bool:
        raise TypeError("return_metadata must be a boolean")

    rng = random.Random(seed)
    records: list[DatasetRecord] = []
    scenario_counts: Counter[str] = Counter()
    scenario_by_observation_id: dict[str, str | None] = {}

    for employee_index in range(group_count):
        labels = (
            [1] * anomalous_per_group
            + [0] * (records_per_employee - anomalous_per_group)
        )
        rng.shuffle(labels)

        for observation_index, label in enumerate(labels):
            scenario = (
                rng.choice(ANOMALY_SCENARIOS)
                if label == 1
                else None
            )

            features = _generate_features(
                rng,
                scenario=scenario,
            )

            observation_id = (
                f"synthetic-email-{employee_index:04d}-"
                f"{observation_index:03d}"
            )

            records.append(
                DatasetRecord(
                    observation_id=observation_id,
                    features=features,
                    label=label,
                    group_id=f"synthetic-employee-{employee_index:04d}",
                )
            )
            scenario_by_observation_id[observation_id] = scenario

            if scenario is not None:
                scenario_counts[scenario] += 1

    rng.shuffle(records)

    # Defensive post-generation checks protect downstream evaluation.
    if len({record.observation_id for record in records}) != n_observations:
        raise RuntimeError("Synthetic generator produced duplicate observation IDs")

    for record in records:
        validate_bec_007_features(dict(record.features))

    if not return_metadata:
        return records

    metadata = _build_synthetic_dataset_metadata(
        records,
        seed=seed,
        requested_anomaly_rate=anomaly_rate,
        scenario_counts=scenario_counts,
        scenario_by_observation_id=scenario_by_observation_id,
    )
    return records, metadata


def _build_synthetic_dataset_metadata(
    records: Sequence[DatasetRecord],
    *,
    seed: int,
    requested_anomaly_rate: float,
    scenario_counts: Counter[str] | dict[str, int],
    scenario_by_observation_id: dict[str, str | None] | None = None,
) -> SyntheticDatasetMetadata:
    if not records:
        raise ValueError("At least one dataset record is required")

    label_counts = {
        label: sum(record.label == label for record in records)
        for label in (0, 1)
    }
    group_ids = {
        record.group_id
        for record in records
        if record.group_id is not None
    }
    actual_anomaly_rate = label_counts[1] / len(records)

    return SyntheticDatasetMetadata(
        generator_version=GENERATOR_VERSION,
        seed=seed,
        observation_count=len(records),
        group_count=len(group_ids),
        label_counts=label_counts,
        scenario_counts=dict(sorted(scenario_counts.items())),
        anomaly_rate=actual_anomaly_rate,
        requested_anomaly_rate=requested_anomaly_rate,
        scenario_by_observation_id=dict(
            scenario_by_observation_id or {}
        ),
    )


def describe_synthetic_dataset(
    records: Sequence[DatasetRecord],
    *,
    seed: int = DEFAULT_SEED,
    anomaly_rate: float = DEFAULT_ANOMALY_RATE,
    scenario_counts: dict[str, int] | None = None,
) -> SyntheticDatasetMetadata:
    """Summarize dataset composition without exposing labels as features."""

    counts = Counter(scenario_counts or {})
    return _build_synthetic_dataset_metadata(
        records,
        seed=seed,
        requested_anomaly_rate=anomaly_rate,
        scenario_counts=counts,
    )
