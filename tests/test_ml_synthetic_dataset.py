"""Tests for reproducible synthetic enterprise email datasets."""

from collections import Counter

import pytest

from src.ml.dataset_split import split_by_group
from src.ml.feature_extractor import (
    BEHAVIORAL_FEATURE_NAMES,
    SCALAR_FEATURE_NAMES,
)
from src.ml.preprocessing import validate_bec_007_features
from src.ml.synthetic_dataset import (
    DEFAULT_ANOMALY_RATE,
    DEFAULT_SEED,
    GENERATOR_VERSION,
    MISSINGABLE_FEATURES,
    describe_synthetic_dataset,
    generate_synthetic_dataset,
)


@pytest.fixture
def records():
    """Generate a small deterministic dataset for focused tests."""

    return generate_synthetic_dataset(
        n_observations=300,
        anomaly_rate=0.20,
        seed=42,
        records_per_employee=10,
    )


def test_generation_is_reproducible_for_fixed_seed():
    first = generate_synthetic_dataset(
        n_observations=300,
        anomaly_rate=0.20,
        seed=42,
        records_per_employee=10,
    )
    second = generate_synthetic_dataset(
        n_observations=300,
        anomaly_rate=0.20,
        seed=42,
        records_per_employee=10,
    )

    assert first == second


def test_dataset_has_expected_observation_count_and_class_balance(records):
    labels = Counter(record.label for record in records)

    assert len(records) == 300
    assert labels == {0: 240, 1: 60}


def test_observation_ids_are_unique_and_employee_groups_are_present(records):
    assert len({record.observation_id for record in records}) == len(records)
    assert all(record.group_id for record in records)
    assert len({record.group_id for record in records}) == 30


def test_every_record_has_the_expected_valid_feature_schema(records):
    expected_features = set(SCALAR_FEATURE_NAMES) | set(
        BEHAVIORAL_FEATURE_NAMES
    )

    for record in records:
        assert set(record.features) == expected_features
        validate_bec_007_features(dict(record.features))


def test_missing_values_are_limited_to_permitted_features(records):
    missing_features = {
        name
        for record in records
        for name, value in record.features.items()
        if value is None
    }

    assert missing_features <= set(MISSINGABLE_FEATURES)


def test_group_split_keeps_employee_groups_separate(records):
    split = split_by_group(records, seed=42)

    partitions = {
        "training": split.training,
        "validation": split.validation,
        "test": split.test,
    }
    group_sets = {
        name: {record.group_id for record in partition}
        for name, partition in partitions.items()
    }

    assert not (group_sets["training"] & group_sets["validation"])
    assert not (group_sets["training"] & group_sets["test"])
    assert not (group_sets["validation"] & group_sets["test"])

    for partition in partitions.values():
        assert {record.label for record in partition} == {0, 1}


def test_metadata_describes_dataset_counts(records):
    metadata = describe_synthetic_dataset(
        records,
        seed=42,
        anomaly_rate=0.20,
    )

    assert metadata.generator_version == GENERATOR_VERSION
    assert metadata.seed == DEFAULT_SEED
    assert metadata.observation_count == 300
    assert metadata.group_count == 30
    assert metadata.label_counts == {0: 240, 1: 60}
    assert metadata.anomaly_rate == DEFAULT_ANOMALY_RATE
    assert metadata.requested_anomaly_rate == DEFAULT_ANOMALY_RATE


def test_generator_returns_a_list_by_default():
    records = generate_synthetic_dataset(
        n_observations=300,
        seed=42,
    )

    assert isinstance(records, list)


def test_generator_can_return_accurate_scenario_metadata():
    records, metadata = generate_synthetic_dataset(
        n_observations=300,
        anomaly_rate=0.20,
        seed=42,
        return_metadata=True,
    )

    assert len(records) == metadata.observation_count
    assert metadata.label_counts == {0: 240, 1: 60}
    assert sum(metadata.scenario_counts.values()) == metadata.label_counts[1]
    assert set(metadata.scenario_counts) <= {
        "recipient_novelty",
        "unusual_timing",
        "frequency_change",
        "recipient_count_change",
        "attachment_change",
        "relationship_or_sequence_change",
    }
    assert metadata.anomaly_rate == 0.20
    assert metadata.requested_anomaly_rate == 0.20


def test_scenario_metadata_is_reproducible():
    _, first_metadata = generate_synthetic_dataset(
        n_observations=300,
        seed=42,
        return_metadata=True,
    )
    _, second_metadata = generate_synthetic_dataset(
        n_observations=300,
        seed=42,
        return_metadata=True,
    )

    assert first_metadata.scenario_counts == second_metadata.scenario_counts


def test_scenario_manifest_covers_every_observation():
    records, metadata = generate_synthetic_dataset(
        n_observations=300,
        anomaly_rate=0.20,
        seed=42,
        return_metadata=True,
    )

    manifest = metadata.scenario_by_observation_id
    records_by_id = {
        record.observation_id: record
        for record in records
    }

    assert set(manifest) == set(records_by_id)

    for observation_id, scenario in manifest.items():
        record = records_by_id[observation_id]

        if record.label == 0:
            assert scenario is None
        else:
            assert scenario in {
                "recipient_novelty",
                "unusual_timing",
                "frequency_change",
                "recipient_count_change",
                "attachment_change",
                "relationship_or_sequence_change",
            }


def test_scenario_manifest_counts_match_metadata():
    records, metadata = generate_synthetic_dataset(
        n_observations=300,
        anomaly_rate=0.20,
        seed=42,
        return_metadata=True,
    )

    manifest = metadata.scenario_by_observation_id

    assert len(manifest) == len(records)
    assert sum(scenario is not None for scenario in manifest.values()) == 60

    manifest_counts = Counter(
        scenario
        for scenario in manifest.values()
        if scenario is not None
    )
    assert dict(sorted(manifest_counts.items())) == metadata.scenario_counts


def test_scenario_manifest_is_reproducible():
    _, first_metadata = generate_synthetic_dataset(
        n_observations=300,
        seed=42,
        return_metadata=True,
    )
    _, second_metadata = generate_synthetic_dataset(
        n_observations=300,
        seed=42,
        return_metadata=True,
    )

    assert (
        first_metadata.scenario_by_observation_id
        == second_metadata.scenario_by_observation_id
    )


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"n_observations": 20}, ValueError),
        ({"n_observations": 301}, ValueError),
        ({"records_per_employee": 1}, ValueError),
        ({"anomaly_rate": 0}, ValueError),
        ({"anomaly_rate": 1}, ValueError),
        ({"anomaly_rate": float("nan")}, ValueError),
        ({"seed": True}, TypeError),
    ],
)
def test_invalid_generator_arguments_are_rejected(kwargs, error):
    arguments = {
        "n_observations": 300,
        "anomaly_rate": 0.20,
        "seed": 42,
        "records_per_employee": 10,
    }
    arguments.update(kwargs)

    with pytest.raises(error):
        generate_synthetic_dataset(**arguments)


def test_metadata_rejects_an_empty_dataset():
    with pytest.raises(ValueError, match="At least one dataset record"):
        describe_synthetic_dataset([])
