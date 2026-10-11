import pytest

from src.ml.dataset_split import (
    DatasetRecord,
    split_by_group,
    split_random_stratified,
    summarize_labels,
)
from src.ml.feature_extractor import (
    BEHAVIORAL_FEATURE_NAMES,
    SCALAR_FEATURE_NAMES,
)


def build_features(value=1.0):
    return {
        **{name: value for name in SCALAR_FEATURE_NAMES},
        **{name: 0 for name in BEHAVIORAL_FEATURE_NAMES},
    }


def build_records(count_per_class=20):
    records = []
    for label in (0, 1):
        for index in range(count_per_class):
            records.append(
                DatasetRecord(
                    observation_id=f"{label}-{index}",
                    features=build_features(),
                    label=label,
                    group_id=f"group-{label}-{index}",
                )
            )
    return records


def test_random_stratified_split_is_reproducible():
    records = build_records()

    first = split_random_stratified(records, seed=17)
    second = split_random_stratified(records, seed=17)

    assert [
        [record.observation_id for record in partition]
        for partition in (
            first.training,
            first.validation,
            first.test,
        )
    ] == [
        [record.observation_id for record in partition]
        for partition in (
            second.training,
            second.validation,
            second.test,
        )
    ]


def test_random_stratified_split_has_three_nonempty_partitions():
    result = split_random_stratified(build_records())

    assert result.sizes == {
        "training": 28,
        "validation": 6,
        "test": 6,
    }
    assert result.strategy == "random_stratified"
    assert result.ratios == (0.70, 0.15, 0.15)


def test_random_stratified_split_reports_actual_proportions():
    result = split_random_stratified(build_records())

    assert result.proportions == {
        "training": 0.7,
        "validation": 0.15,
        "test": 0.15,
    }


def test_group_split_reports_actual_proportions():
    records = [
        DatasetRecord(
            observation_id=f"obs-{group}-{index}",
            features=build_features(),
            label=(group + index) % 2,
            group_id=f"group-{group}",
        )
        for group, group_size in enumerate((12, 8, 6, 5, 4, 3, 2))
        for index in range(group_size)
    ]

    result = split_by_group(records, seed=21)

    assert result.proportions == {
        name: size / len(records)
        for name, size in result.sizes.items()
    }

    assert sum(result.sizes.values()) == len(records)


def test_group_split_balances_uneven_groups_when_exact_split_is_possible():
    group_sizes = (12, 8, 6, 5, 4, 3, 2)
    records = [
        DatasetRecord(
            observation_id=f"obs-{group}-{index}",
            features=build_features(),
            label=(group + index) % 2,
            group_id=f"group-{group}",
        )
        for group, group_size in enumerate(group_sizes)
        for index in range(group_size)
    ]

    result = split_by_group(records, seed=21)

    assert result.sizes == {
        "training": 28,
        "validation": 6,
        "test": 6,
    }

    group_sets = [
        {record.group_id for record in partition}
        for partition in (
            result.training,
            result.validation,
            result.test,
        )
    ]
    assert group_sets[0].isdisjoint(group_sets[1])
    assert group_sets[0].isdisjoint(group_sets[2])
    assert group_sets[1].isdisjoint(group_sets[2])


def test_random_stratified_split_keeps_both_classes_in_each_partition():
    result = split_random_stratified(build_records())

    for partition in (
        result.training,
        result.validation,
        result.test,
    ):
        assert {record.label for record in partition} == {0, 1}


def test_random_stratified_split_has_no_overlapping_ids():
    result = split_random_stratified(build_records())

    id_sets = [
        {record.observation_id for record in partition}
        for partition in (
            result.training,
            result.validation,
            result.test,
        )
    ]

    assert id_sets[0].isdisjoint(id_sets[1])
    assert id_sets[0].isdisjoint(id_sets[2])
    assert id_sets[1].isdisjoint(id_sets[2])


@pytest.mark.parametrize("label", [True, False, 2, -1, "1", 1.0])
def test_split_rejects_invalid_labels(label):
    records = build_records()
    records[0] = DatasetRecord(
        observation_id="invalid-label",
        features=build_features(),
        label=label,
    )

    with pytest.raises(ValueError, match="label must be integer 0 or 1"):
        split_random_stratified(records)


def test_split_rejects_duplicate_observation_ids():
    records = build_records()
    records[1] = DatasetRecord(
        observation_id=records[0].observation_id,
        features=build_features(),
        label=records[1].label,
    )

    with pytest.raises(ValueError, match="Duplicate observation_id"):
        split_random_stratified(records)


def test_split_rejects_invalid_feature_schema():
    records = build_records()
    features = build_features()
    del features["recipient_count"]
    records[0] = DatasetRecord(
        observation_id="bad-features",
        features=features,
        label=records[0].label,
    )

    with pytest.raises(ValueError, match="Feature names"):
        split_random_stratified(records)


def test_split_rejects_single_class_dataset():
    records = [
        DatasetRecord(
            observation_id=f"normal-{index}",
            features=build_features(),
            label=0,
        )
        for index in range(6)
    ]

    with pytest.raises(ValueError, match="both normal"):
        split_random_stratified(records)


def test_split_rejects_invalid_seed():
    with pytest.raises(TypeError, match="seed must be an integer"):
        split_random_stratified(build_records(), seed=True)


def test_group_split_never_splits_a_group():
    records = build_records()
    result = split_by_group(records, seed=21)

    group_sets = [
        {record.group_id for record in partition}
        for partition in (
            result.training,
            result.validation,
            result.test,
        )
    ]

    assert group_sets[0].isdisjoint(group_sets[1])
    assert group_sets[0].isdisjoint(group_sets[2])
    assert group_sets[1].isdisjoint(group_sets[2])


def test_group_split_preserves_all_records():
    records = build_records()
    result = split_by_group(records, seed=21)

    original_ids = {record.observation_id for record in records}
    split_ids = {
        record.observation_id
        for partition in (
            result.training,
            result.validation,
            result.test,
        )
        for record in partition
    }

    assert split_ids == original_ids


def test_group_split_requires_group_ids():
    records = build_records()
    records[0] = DatasetRecord(
        observation_id=records[0].observation_id,
        features=build_features(),
        label=records[0].label,
    )

    with pytest.raises(ValueError, match="requires a non-empty group_id"):
        split_by_group(records)


def test_group_split_requires_three_distinct_groups():
    records = [
        DatasetRecord(
            observation_id=f"obs-{index}",
            features=build_features(),
            label=index % 2,
            group_id=f"group-{index % 2}",
        )
        for index in range(12)
    ]

    with pytest.raises(ValueError, match="at least three distinct groups"):
        split_by_group(records)


def test_labels_and_group_ids_are_not_added_to_features():
    result = split_random_stratified(build_records())

    for partition in (
        result.training,
        result.validation,
        result.test,
    ):
        for record in partition:
            assert "label" not in record.features
            assert "observation_id" not in record.features
            assert "group_id" not in record.features


def test_summarize_labels_counts_both_classes():
    records = build_records(count_per_class=4)

    assert summarize_labels(records) == {0: 4, 1: 4}


def test_split_does_not_mutate_input_feature_dictionary():
    original_features = build_features()
    record = DatasetRecord(
        observation_id="normal-0",
        features=original_features,
        label=0,
    )
    records = [record] + [
        DatasetRecord(
            observation_id=f"normal-{index}",
            features=build_features(),
            label=0,
        )
        for index in range(1, 20)
    ] + [
        DatasetRecord(
            observation_id=f"anomaly-{index}",
            features=build_features(),
            label=1,
        )
        for index in range(20)
    ]

    before = dict(original_features)
    split_random_stratified(records)

    assert original_features == before
