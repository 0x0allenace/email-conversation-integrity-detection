"""Validate and split BEC-007 observations for ML evaluation."""

from __future__ import annotations

import math
import random
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from src.ml.preprocessing import validate_bec_007_features


DEFAULT_SEED = 42
DEFAULT_TRAIN_RATIO = 0.70
DEFAULT_VALIDATION_RATIO = 0.15
DEFAULT_TEST_RATIO = 0.15


@dataclass(frozen=True)
class DatasetRecord:
    """One observation with metadata kept separate from its features."""

    observation_id: str
    features: Mapping[str, Any]
    label: int
    group_id: str | None = None


@dataclass(frozen=True)
class DatasetSplit:
    """Training, validation, and test partitions with split metadata."""

    training: tuple[DatasetRecord, ...]
    validation: tuple[DatasetRecord, ...]
    test: tuple[DatasetRecord, ...]
    strategy: str
    seed: int
    ratios: tuple[float, float, float]

    @property
    def sizes(self) -> dict[str, int]:
        """Return the number of observations in each partition."""
        return {
            "training": len(self.training),
            "validation": len(self.validation),
            "test": len(self.test),
        }

    @property
    def proportions(self) -> dict[str, float]:
        """Return actual partition proportions based on observation counts."""
        total = sum(self.sizes.values())
        if total == 0:
            return {
                "training": 0.0,
                "validation": 0.0,
                "test": 0.0,
            }

        return {
            name: size / total
            for name, size in self.sizes.items()
        }


def _validate_records(
    records: Sequence[DatasetRecord],
    *,
    require_groups: bool,
) -> list[DatasetRecord]:
    if isinstance(records, (str, bytes)) or not isinstance(
        records, Sequence
    ):
        raise TypeError("records must be a sequence of DatasetRecord objects")

    if not records:
        raise ValueError("At least one dataset record is required")

    validated: list[DatasetRecord] = []
    seen_ids: set[str] = set()

    for index, record in enumerate(records):
        if not isinstance(record, DatasetRecord):
            raise TypeError(
                f"Record at index {index} must be a DatasetRecord"
            )

        if not isinstance(record.observation_id, str) or not record.observation_id.strip():
            raise ValueError(
                f"Record at index {index} has an invalid observation_id"
            )

        if record.observation_id in seen_ids:
            raise ValueError(
                f"Duplicate observation_id: {record.observation_id}"
            )
        seen_ids.add(record.observation_id)

        if type(record.label) is not int or record.label not in (0, 1):
            raise ValueError(
                f"Record {record.observation_id} label must be integer 0 or 1"
            )

        if not isinstance(record.features, Mapping):
            raise TypeError(
                f"Record {record.observation_id} features must be a mapping"
            )

        features = dict(record.features)
        validate_bec_007_features(features)

        if require_groups:
            if not isinstance(record.group_id, str) or not record.group_id.strip():
                raise ValueError(
                    f"Record {record.observation_id} requires a non-empty group_id"
                )
        elif record.group_id is not None and (
            not isinstance(record.group_id, str)
            or not record.group_id.strip()
        ):
            raise ValueError(
                f"Record {record.observation_id} has an invalid group_id"
            )

        # Copy the feature mapping so the splitter does not expose the
        # caller's mutable dictionary through the returned record.
        validated.append(
            DatasetRecord(
                observation_id=record.observation_id,
                features=features,
                label=record.label,
                group_id=record.group_id,
            )
        )

    labels = {record.label for record in validated}
    if labels != {0, 1}:
        raise ValueError(
            "The dataset must contain both normal (0) and anomalous (1) records"
        )

    return validated


def _validate_ratios(
    train_ratio: float,
    validation_ratio: float,
    test_ratio: float,
) -> tuple[float, float, float]:
    ratios = (train_ratio, validation_ratio, test_ratio)

    for name, ratio in zip(
        ("train_ratio", "validation_ratio", "test_ratio"),
        ratios,
    ):
        if isinstance(ratio, bool) or not isinstance(ratio, (int, float)):
            raise TypeError(f"{name} must be numeric")
        if not math.isfinite(ratio) or ratio <= 0 or ratio >= 1:
            raise ValueError(f"{name} must be finite and between 0 and 1")

    if not math.isclose(sum(ratios), 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError("Split ratios must sum to 1.0")

    return tuple(float(ratio) for ratio in ratios)


def _partition_sizes(
    count: int,
    ratios: tuple[float, float, float],
) -> tuple[int, int, int]:
    if count < 3:
        raise ValueError(
            "At least three records are required for three non-empty partitions"
        )

    raw = [count * ratio for ratio in ratios]
    sizes = [math.floor(value) for value in raw]

    # Allocate remaining records to the largest fractional remainders.
    remaining = count - sum(sizes)
    order = sorted(
        range(3),
        key=lambda index: raw[index] - sizes[index],
        reverse=True,
    )
    for index in order[:remaining]:
        sizes[index] += 1

    if min(sizes) < 1:
        raise ValueError(
            "Dataset is too small for the requested split ratios"
        )

    return sizes[0], sizes[1], sizes[2]


def _make_split(
    training: list[DatasetRecord],
    validation: list[DatasetRecord],
    test: list[DatasetRecord],
    *,
    strategy: str,
    seed: int,
    ratios: tuple[float, float, float],
) -> DatasetSplit:
    partitions = (training, validation, test)
    partition_ids = [
        {record.observation_id for record in partition}
        for partition in partitions
    ]

    if any(
        partition_ids[left] & partition_ids[right]
        for left in range(3)
        for right in range(left + 1, 3)
    ):
        raise RuntimeError("Dataset split contains overlapping observations")

    return DatasetSplit(
        training=tuple(training),
        validation=tuple(validation),
        test=tuple(test),
        strategy=strategy,
        seed=seed,
        ratios=ratios,
    )


def split_random_stratified(
    records: Sequence[DatasetRecord],
    *,
    seed: int = DEFAULT_SEED,
    train_ratio: float = DEFAULT_TRAIN_RATIO,
    validation_ratio: float = DEFAULT_VALIDATION_RATIO,
    test_ratio: float = DEFAULT_TEST_RATIO,
) -> DatasetSplit:
    """Create reproducible random partitions with approximate class balance.

    Each class is partitioned separately. The resulting sizes may differ
    slightly from the requested overall ratios because observations are
    indivisible and both classes must be represented in every partition.
    """

    if type(seed) is not int:
        raise TypeError("seed must be an integer")

    ratios = _validate_ratios(
        train_ratio, validation_ratio, test_ratio
    )
    validated = _validate_records(records, require_groups=False)

    by_label = {
        label: [record for record in validated if record.label == label]
        for label in (0, 1)
    }

    if any(len(class_records) < 3 for class_records in by_label.values()):
        raise ValueError(
            "Stratified splitting requires at least three records per class"
        )

    rng = random.Random(seed)
    partitions: list[list[DatasetRecord]] = [[], [], []]

    for label in (0, 1):
        class_records = by_label[label].copy()
        rng.shuffle(class_records)
        sizes = _partition_sizes(len(class_records), ratios)

        first = sizes[0]
        second = first + sizes[1]

        partitions[0].extend(class_records[:first])
        partitions[1].extend(class_records[first:second])
        partitions[2].extend(class_records[second:])

    for partition in partitions:
        rng.shuffle(partition)

    return _make_split(
        partitions[0],
        partitions[1],
        partitions[2],
        strategy="random_stratified",
        seed=seed,
        ratios=ratios,
    )


def split_by_group(
    records: Sequence[DatasetRecord],
    *,
    seed: int = DEFAULT_SEED,
    train_ratio: float = DEFAULT_TRAIN_RATIO,
    validation_ratio: float = DEFAULT_VALIDATION_RATIO,
    test_ratio: float = DEFAULT_TEST_RATIO,
) -> DatasetSplit:
    """Split by group so no group appears in more than one partition.

    Group assignment preserves group integrity and aims to minimize
    deviations from the requested partition sizes. For up to 12 groups,
    an exact search selects the best non-empty allocation; larger group
    sets use deterministic greedy allocation. Unlike stratified splitting,
    class balance is not guaranteed because groups are indivisible.
    """

    if type(seed) is not int:
        raise TypeError("seed must be an integer")

    ratios = _validate_ratios(
        train_ratio, validation_ratio, test_ratio
    )
    validated = _validate_records(records, require_groups=True)

    groups: dict[str, list[DatasetRecord]] = {}
    for record in validated:
        assert record.group_id is not None
        groups.setdefault(record.group_id, []).append(record)

    if len(groups) < 3:
        raise ValueError(
            "Group-based splitting requires at least three distinct groups"
        )

    rng = random.Random(seed)
    group_items = list(groups.items())
    rng.shuffle(group_items)

    # Place larger groups first; randomization breaks equal-size ties.
    group_items.sort(key=lambda item: len(item[1]), reverse=True)

    targets = [len(validated) * ratio for ratio in ratios]

    def allocation_score(sizes: list[int]) -> float:
        return sum(
            ((size - target) / target) ** 2
            for size, target in zip(sizes, targets)
        )

    partitions: list[list[DatasetRecord]] = [[], [], []]

    if len(group_items) <= 12:
        # Exact search is practical for small group counts.
        best_assignment = None
        best_score = float("inf")
        group_count = len(group_items)

        def search_assignments(
            group_index: int,
            assignment: list[int],
            sizes: list[int],
        ) -> None:
            nonlocal best_assignment, best_score

            if group_index == group_count:
                if any(size == 0 for size in sizes):
                    return

                score = allocation_score(sizes)
                if score < best_score:
                    best_score = score
                    best_assignment = assignment.copy()
                return

            group_size = len(group_items[group_index][1])

            for partition_index in range(3):
                sizes[partition_index] += group_size
                assignment.append(partition_index)

                search_assignments(
                    group_index + 1,
                    assignment,
                    sizes,
                )

                assignment.pop()
                sizes[partition_index] -= group_size

        search_assignments(0, [], [0, 0, 0])

        if best_assignment is None:
            raise ValueError(
                "Unable to create three non-empty group partitions"
            )

        for (_, group_records), partition_index in zip(
            group_items, best_assignment
        ):
            partitions[partition_index].extend(group_records)

    else:
        # For larger datasets, use deterministic greedy allocation.
        group_items.sort(
            key=lambda item: len(item[1]),
            reverse=True,
        )

        for index in range(3):
            _, group_records = group_items[index]
            partitions[index].extend(group_records)

        for _, group_records in group_items[3:]:
            group_size = len(group_records)
            candidate_choices = []

            for index in range(3):
                proposed_sizes = [
                    len(partition)
                    for partition in partitions
                ]
                proposed_sizes[index] += group_size
                candidate_choices.append(
                    (allocation_score(proposed_sizes), index)
                )

            _, chosen = min(candidate_choices)
            partitions[chosen].extend(group_records)

    if any(not partition for partition in partitions):
        raise ValueError(
            "Unable to create three non-empty partitions from these groups"
        )

    group_sets = [
        {record.group_id for record in partition}
        for partition in partitions
    ]
    for left in range(3):
        for right in range(left + 1, 3):
            if group_sets[left] & group_sets[right]:
                raise RuntimeError(
                    "Group leakage detected across dataset partitions"
                )

    return _make_split(
        partitions[0],
        partitions[1],
        partitions[2],
        strategy="group",
        seed=seed,
        ratios=ratios,
    )


def summarize_labels(
    records: Sequence[DatasetRecord],
) -> dict[int, int]:
    """Count normal and anomalous labels without changing model features."""

    return dict(Counter(record.label for record in records))
