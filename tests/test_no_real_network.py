"""
Regression test: assert no code path in the phishing_sim package makes real
SMTP or socket connections. This is a hard safety requirement of the
platform (simulation-only, no real email sending).

Approach:
1. Static source scan of every .py file under src/phishing_sim for
   dangerous imports/usages (smtplib, socket.socket/create_connection,
   requests, httpx, urllib.request).
2. Dynamic guard: monkeypatch socket.socket and smtplib.SMTP to raise if
   invoked, then run a full campaign (including CLI run-campaign with
   --confirm-authorized) and assert it completes successfully without
   tripping the guard.
"""

import importlib
import json
import pkgutil
import socket
import smtplib
from pathlib import Path

import pytest
from click.testing import CliRunner

import phishing_sim


def _iter_package_source_files():
    package_dir = Path(phishing_sim.__file__).parent
    for path in package_dir.rglob("*.py"):
        yield path


def test_no_smtp_or_socket_imports_anywhere_in_package_source():
    banned_substrings = (
        "import smtplib",
        "from smtplib",
        "import socket",
        "from socket",
        "import requests",
        "from requests",
        "import httpx",
        "from httpx",
        "urllib.request",
    )
    offenders = []
    for path in _iter_package_source_files():
        source = path.read_text(encoding="utf-8")
        for banned in banned_substrings:
            if banned in source:
                offenders.append((str(path), banned))
    assert offenders == [], f"Found banned networking usage: {offenders}"


class _NetworkUseDetected(AssertionError):
    pass


def test_full_campaign_run_never_touches_socket_or_smtp(monkeypatch, sample_targets_file, tmp_path):
    """Dynamic guard: patch socket.socket / smtplib.SMTP to explode if used,
    then run a real end-to-end campaign through the CLI and confirm it
    succeeds without tripping the guard.
    """

    def _blow_up_socket(*args, **kwargs):
        raise _NetworkUseDetected("socket.socket() was called -- real network use detected!")

    def _blow_up_smtp(*args, **kwargs):
        raise _NetworkUseDetected("smtplib.SMTP() was called -- real email send detected!")

    monkeypatch.setattr(socket, "socket", _blow_up_socket)
    monkeypatch.setattr(smtplib, "SMTP", _blow_up_smtp)
    monkeypatch.setattr(smtplib, "SMTP_SSL", _blow_up_smtp)

    from phishing_sim.cli import main

    runner = CliRunner()
    output_log = tmp_path / "guarded_log.jsonl"
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
            "7",
            "--output",
            str(output_log),
            "--json-only",
        ],
    )

    assert result.exit_code == 0, result.output
    assert output_log.exists()
    data = json.loads(result.output)
    assert data["overall_metrics"]["sent"] == data["overall_metrics"]["total_targets"]


def test_log_file_is_plain_local_json_lines_not_network_payload(sample_targets_file, tmp_path):
    """The 'send log' must just be a local file on disk, confirming the
    'send' step is local I/O, not network I/O."""
    from phishing_sim.campaign import Campaign
    from phishing_sim.simulator import run_campaign

    raw = json.loads(sample_targets_file.read_text(encoding="utf-8"))["targets"]
    campaign = Campaign.from_targets_file_data("GuardCampaign", "invoice", raw)
    log_path = tmp_path / "plain_log.jsonl"
    run_campaign(campaign, confirmed_authorized=True, seed=3, log_path=log_path)

    assert log_path.is_file()
    for line in log_path.read_text(encoding="utf-8").strip().splitlines():
        record = json.loads(line)
        assert "SIMULATED ONLY" in record["note"]
