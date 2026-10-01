"""Tests for the CLI, including the authorization gate enforcement."""

import json
from pathlib import Path

from click.testing import CliRunner

from phishing_sim.cli import main


def _runner():
    return CliRunner()


def test_cli_prints_authorization_banner_on_run():
    runner = _runner()
    result = runner.invoke(main, ["list-templates"])
    assert result.exit_code == 0
    assert "FOR USE ONLY IN AUTHORIZED INTERNAL SECURITY AWARENESS PROGRAMS" in result.output
    assert "THIS TOOL DOES NOT SEND REAL EMAIL" in result.output


def test_cli_list_templates_json_only_suppresses_banner():
    runner = _runner()
    result = runner.invoke(main, ["list-templates", "--json-only"])
    assert result.exit_code == 0
    assert "FOR USE ONLY" not in result.output
    data = json.loads(result.output)
    assert "it-password-reset" in data


def test_cli_run_campaign_without_confirm_authorized_blocks_send(sample_targets_file, tmp_path):
    runner = _runner()
    output_log = tmp_path / "log.jsonl"
    result = runner.invoke(
        main,
        [
            "run-campaign",
            "--input",
            str(sample_targets_file),
            "--template",
            "it-password-reset",
            "--seed",
            "1",
            "--output",
            str(output_log),
        ],
    )
    assert result.exit_code != 0
    assert "confirm" in result.output.lower() or "authoriz" in result.output.lower()
    assert not output_log.exists()


def test_cli_run_campaign_with_confirm_authorized_succeeds(sample_targets_file, tmp_path):
    runner = _runner()
    output_log = tmp_path / "log.jsonl"
    result = runner.invoke(
        main,
        [
            "run-campaign",
            "--input",
            str(sample_targets_file),
            "--template",
            "it-password-reset",
            "--confirm-authorized",
            "--seed",
            "1",
            "--output",
            str(output_log),
        ],
    )
    assert result.exit_code == 0
    assert output_log.exists()
    assert "SECURITY AWARENESS TRAINING FEEDBACK REPORT" in result.output


def test_cli_run_campaign_json_only_output_is_valid_json(sample_targets_file, tmp_path):
    runner = _runner()
    output_log = tmp_path / "log.jsonl"
    result = runner.invoke(
        main,
        [
            "run-campaign",
            "--input",
            str(sample_targets_file),
            "--template",
            "invoice",
            "--confirm-authorized",
            "--seed",
            "123",
            "--output",
            str(output_log),
            "--json-only",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["template_key"] == "invoice"
    assert "overall_metrics" in data


def test_cli_run_campaign_reproducible_with_seed(sample_targets_file, tmp_path):
    runner = _runner()
    log1 = tmp_path / "log1.jsonl"
    log2 = tmp_path / "log2.jsonl"
    r1 = runner.invoke(
        main,
        [
            "run-campaign",
            "--input",
            str(sample_targets_file),
            "--template",
            "hr-policy-update",
            "--confirm-authorized",
            "--seed",
            "55",
            "--output",
            str(log1),
            "--json-only",
        ],
    )
    r2 = runner.invoke(
        main,
        [
            "run-campaign",
            "--input",
            str(sample_targets_file),
            "--template",
            "hr-policy-update",
            "--confirm-authorized",
            "--seed",
            "55",
            "--output",
            str(log2),
            "--json-only",
        ],
    )
    data1 = json.loads(r1.output)
    data2 = json.loads(r2.output)
    assert data1["overall_metrics"] == data2["overall_metrics"]


def test_cli_run_campaign_rejects_unsafe_target_emails(tmp_path):
    bad_file = tmp_path / "bad_targets.json"
    bad_file.write_text(
        json.dumps({"targets": [{"name": "Real Person", "email": "real@gmail.com", "department": "Finance"}]}),
        encoding="utf-8",
    )
    runner = _runner()
    result = runner.invoke(
        main,
        [
            "run-campaign",
            "--input",
            str(bad_file),
            "--template",
            "invoice",
            "--confirm-authorized",
            "--seed",
            "1",
        ],
    )
    assert result.exit_code != 0
    assert "error" in result.output.lower()


def test_cli_run_campaign_unknown_template_errors(sample_targets_file):
    runner = _runner()
    result = runner.invoke(
        main,
        [
            "run-campaign",
            "--input",
            str(sample_targets_file),
            "--template",
            "not-a-template",
            "--confirm-authorized",
        ],
    )
    assert result.exit_code != 0


def test_cli_help_mentions_simulation_only():
    runner = _runner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "NEVER sends real email" in result.output or "simulated" in result.output.lower()


def test_cli_against_repo_sample_data(repo_sample_targets_path, tmp_path):
    """End-to-end smoke test against the actual sample_data/targets.json."""
    runner = _runner()
    output_log = tmp_path / "repo_sample_log.jsonl"
    result = runner.invoke(
        main,
        [
            "run-campaign",
            "--input",
            str(repo_sample_targets_path),
            "--template",
            "it-password-reset",
            "--confirm-authorized",
            "--seed",
            "42",
            "--output",
            str(output_log),
            "--json-only",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["overall_metrics"]["total_targets"] >= 10
