"""Tests for the official BEC-007 evaluation CLI."""

import json
from pathlib import Path

import pytest

from scripts import run_ml_evaluation as cli


def parse_args(*args: str):
    """Parse CLI arguments using the production parser."""
    return cli.build_parser().parse_args(list(args))


def test_parser_defaults_are_documented() -> None:
    args = parse_args()

    assert args.output == Path("results/ml-evaluation-report.json")
    assert args.observations == 2000
    assert args.anomaly_rate == 0.20
    assert args.records_per_employee == 10
    assert args.dataset_seed == 42
    assert args.split_seed == 42
    assert args.split_strategy == "group"
    assert args.train_ratio == 0.70
    assert args.validation_ratio == 0.15
    assert args.test_ratio == 0.15
    assert args.force is False


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--observations", "20"], "--observations must be at least 30"),
        (
            ["--records-per-employee", "1"],
            "--records-per-employee must be at least 2",
        ),
        (
            ["--observations", "31"],
            "--observations must be divisible by --records-per-employee",
        ),
        (
            ["--anomaly-rate", "0"],
            "--anomaly-rate must be finite and between 0 and 1",
        ),
        (
            ["--anomaly-rate", "1"],
            "--anomaly-rate must be finite and between 0 and 1",
        ),
        (
            ["--anomaly-rate", "nan"],
            "--anomaly-rate must be finite and between 0 and 1",
        ),
        (
            ["--train-ratio", "0.8"],
            "Split ratios must sum to 1.0",
        ),
        (
            ["--validation-ratio", "0"],
            "All split ratios must be finite and greater than zero",
        ),
    ],
)
def test_invalid_arguments_are_rejected(
    arguments: list[str],
    message: str,
) -> None:
    args = parse_args(*arguments)

    with pytest.raises(ValueError, match=message):
        cli.validate_arguments(args)


def test_parser_rejects_unsupported_split_strategy() -> None:
    with pytest.raises(SystemExit) as exc_info:
        parse_args("--split-strategy", "temporal")

    assert exc_info.value.code == 2


def test_valid_small_benchmark_arguments_are_accepted() -> None:
    args = parse_args(
        "--observations", "60",
        "--records-per-employee", "10",
        "--anomaly-rate", "0.2",
        "--split-strategy", "group",
    )

    cli.validate_arguments(args)


def test_write_report_creates_json_and_parent_directories(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "nested" / "report.json"
    report = {
        "report_schema_version": "1.0.0",
        "model_results": {},
        "value": 0.75,
    }

    cli.write_report(report, destination)

    assert destination.is_file()
    assert json.loads(destination.read_text(encoding="utf-8")) == report
    assert destination.read_text(encoding="utf-8").endswith("\n")


def test_write_report_refuses_to_overwrite_existing_file(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "report.json"
    original_contents = '{"existing": true}\n'
    destination.write_text(original_contents, encoding="utf-8")

    with pytest.raises(FileExistsError, match="Output already exists"):
        cli.write_report({"replacement": True}, destination)

    assert destination.read_text(encoding="utf-8") == original_contents


def test_write_report_replaces_existing_file_only_with_force(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "report.json"
    destination.write_text('{"old": true}\n', encoding="utf-8")

    cli.write_report({"new": True}, destination, force=True)

    assert json.loads(destination.read_text(encoding="utf-8")) == {
        "new": True
    }


@pytest.mark.parametrize("invalid_value", [float("nan"), float("inf")])
def test_write_report_rejects_non_finite_json_values(
    tmp_path: Path,
    invalid_value: float,
) -> None:
    destination = tmp_path / "report.json"

    with pytest.raises(ValueError):
        cli.write_report({"invalid": invalid_value}, destination)

    assert not destination.exists()


def test_main_checks_existing_output_before_running_benchmark(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "existing-report.json"
    original_contents = '{"preserve": true}\n'
    destination.write_text(original_contents, encoding="utf-8")

    def unexpected_benchmark(*args, **kwargs):
        raise AssertionError("Benchmark must not run when output exists")

    monkeypatch.setattr(cli, "build_report", unexpected_benchmark)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--output", str(destination)])

    assert exc_info.value.code == 2
    assert destination.read_text(encoding="utf-8") == original_contents


def test_main_returns_zero_when_all_models_succeed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "successful-report.json"
    report = {
        "model_results": {
            "isolation_forest": {
                "status": "success",
                "metrics": {
                    "precision": 0.8,
                    "recall": 0.7,
                    "f1": 0.746,
                    "average_precision": 0.82,
                },
            }
        }
    }

    monkeypatch.setattr(cli, "build_report", lambda args: report)

    result = cli.main(["--output", str(destination)])

    assert result == 0
    assert json.loads(destination.read_text(encoding="utf-8")) == report
    assert "Evaluation report written to:" in capsys.readouterr().out


def test_main_returns_one_when_a_model_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "failed-model-report.json"
    report = {
        "model_results": {
            "isolation_forest": {
                "status": "success",
                "metrics": {
                    "precision": 0.8,
                    "recall": 0.7,
                    "f1": 0.746,
                    "average_precision": 0.82,
                },
            },
            "lof": {
                "status": "error",
                "error": "Synthetic test failure",
                "metrics": None,
            },
        }
    }

    monkeypatch.setattr(cli, "build_report", lambda args: report)

    result = cli.main(["--output", str(destination)])

    assert result == 1
    assert json.loads(destination.read_text(encoding="utf-8")) == report
    assert "lof: error; Synthetic test failure" in capsys.readouterr().out
