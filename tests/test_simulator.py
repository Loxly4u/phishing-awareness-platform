"""Tests for phishing_sim.simulator -- the simulated send/click/report logic."""

import json
from pathlib import Path

import pytest

from phishing_sim.campaign import Campaign, Target
from phishing_sim.simulator import (
    AuthorizationRequiredError,
    compute_department_metrics,
    compute_overall_metrics,
    run_campaign,
)


def _build_campaign(sample_targets_raw, template_key="it-password-reset"):
    return Campaign.from_targets_file_data("TestCampaign", template_key, sample_targets_raw)


def test_run_campaign_refuses_without_authorization(sample_targets_raw):
    campaign = _build_campaign(sample_targets_raw)
    with pytest.raises(AuthorizationRequiredError):
        run_campaign(campaign, confirmed_authorized=False, seed=1)
    # No results should have been recorded.
    assert campaign.results == {}


def test_run_campaign_refuses_without_authorization_no_log_written(sample_targets_raw, tmp_path):
    campaign = _build_campaign(sample_targets_raw)
    log_path = tmp_path / "send_log.jsonl"
    with pytest.raises(AuthorizationRequiredError):
        run_campaign(campaign, confirmed_authorized=False, seed=1, log_path=log_path)
    assert not log_path.exists()


def test_run_campaign_with_authorization_records_results(sample_targets_raw):
    campaign = _build_campaign(sample_targets_raw)
    run_campaign(campaign, confirmed_authorized=True, seed=42)
    assert len(campaign.results) == len(sample_targets_raw)
    for target in campaign.targets:
        assert target.email in campaign.results
        assert campaign.results[target.email].sent is True


def test_run_campaign_is_deterministic_with_same_seed(sample_targets_raw):
    c1 = _build_campaign(sample_targets_raw)
    c2 = _build_campaign(sample_targets_raw)
    run_campaign(c1, confirmed_authorized=True, seed=99)
    run_campaign(c2, confirmed_authorized=True, seed=99)
    for target in c1.targets:
        r1 = c1.results[target.email]
        r2 = c2.results[target.email]
        assert r1.opened == r2.opened
        assert r1.clicked == r2.clicked
        assert r1.reported == r2.reported


def test_run_campaign_different_seeds_can_differ(sample_targets_raw):
    c1 = _build_campaign(sample_targets_raw)
    c2 = _build_campaign(sample_targets_raw)
    run_campaign(c1, confirmed_authorized=True, seed=1)
    run_campaign(c2, confirmed_authorized=True, seed=2)
    behaviors_1 = [(r.opened, r.clicked, r.reported) for r in c1.results.values()]
    behaviors_2 = [(r.opened, r.clicked, r.reported) for r in c2.results.values()]
    assert behaviors_1 != behaviors_2


def test_run_campaign_writes_log_file(sample_targets_raw, tmp_path):
    campaign = _build_campaign(sample_targets_raw)
    log_path = tmp_path / "out" / "send_log.jsonl"
    run_campaign(campaign, confirmed_authorized=True, seed=7, log_path=log_path)
    assert log_path.exists()
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(sample_targets_raw)
    for line in lines:
        record = json.loads(line)
        assert record["event"] == "simulated_send"
        assert "SIMULATED ONLY" in record["note"]
        assert record["target_email"].endswith("@fictionalcorp.test")


def test_compute_department_metrics_shapes(sample_targets_raw):
    campaign = _build_campaign(sample_targets_raw)
    run_campaign(campaign, confirmed_authorized=True, seed=5)
    metrics = compute_department_metrics(campaign)
    depts = {m.department for m in metrics}
    assert depts == set(campaign.departments())
    for m in metrics:
        assert 0.0 <= m.click_rate <= 1.0
        assert 0.0 <= m.report_rate <= 1.0
        assert m.total == len([t for t in campaign.targets if t.department == m.department])


def test_compute_overall_metrics_consistent_with_targets(sample_targets_raw):
    campaign = _build_campaign(sample_targets_raw)
    run_campaign(campaign, confirmed_authorized=True, seed=3)
    overall = compute_overall_metrics(campaign)
    assert overall["total_targets"] == len(sample_targets_raw)
    assert overall["sent"] == len(sample_targets_raw)
    assert overall["clicked"] <= overall["opened"] <= overall["total_targets"]


def test_no_networking_modules_imported_in_simulator_source():
    """Regression test: simulator.py source must not reference real
    networking primitives used for sending email/making socket connections.
    """
    import phishing_sim.simulator as simulator_module

    source_path = Path(simulator_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    for banned in ("import smtplib", "import socket", "import requests", "import httpx"):
        assert banned not in source
