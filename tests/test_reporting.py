"""Tests for phishing_sim.reporting."""

from phishing_sim.campaign import Campaign
from phishing_sim.reporting import (
    build_department_report,
    build_employee_feedback,
    build_full_report,
    render_text_report,
)
from phishing_sim.simulator import run_campaign


def _ready_campaign(sample_targets_raw, seed=11):
    campaign = Campaign.from_targets_file_data("ReportCampaign", "invoice", sample_targets_raw)
    run_campaign(campaign, confirmed_authorized=True, seed=seed)
    return campaign


def test_build_employee_feedback_flags_clicked_not_reported(sample_targets_raw):
    campaign = _ready_campaign(sample_targets_raw)
    feedback = build_employee_feedback(campaign)
    assert len(feedback) == len(sample_targets_raw)
    for item in feedback:
        if item.clicked and not item.reported:
            assert item.needs_training is True
        else:
            assert item.needs_training is False


def test_build_department_report_contains_narrative(sample_targets_raw):
    campaign = _ready_campaign(sample_targets_raw)
    dept_report = build_department_report(campaign)
    departments = {d["department"] for d in dept_report}
    assert departments == set(campaign.departments())
    for d in dept_report:
        assert "narrative" in d
        assert len(d["narrative"]) > 0


def test_build_full_report_structure(sample_targets_raw):
    campaign = _ready_campaign(sample_targets_raw)
    report = build_full_report(campaign)
    assert report["campaign_name"] == "ReportCampaign"
    assert "overall_metrics" in report
    assert "department_report" in report
    assert "employee_feedback" in report
    assert "follow_up_needed" in report
    assert isinstance(report["follow_up_needed"], list)
    for emp in report["follow_up_needed"]:
        assert emp["needs_training"] is True


def test_render_text_report_contains_training_tag_and_names(sample_targets_raw):
    campaign = _ready_campaign(sample_targets_raw)
    text = render_text_report(campaign)
    assert "INTERNAL AWARENESS TRAINING USE ONLY" in text
    for target in campaign.targets:
        assert target.name in text


def test_report_with_no_results_handles_gracefully(sample_targets_raw):
    campaign = Campaign.from_targets_file_data("EmptyCampaign", "invoice", sample_targets_raw)
    feedback = build_employee_feedback(campaign)
    assert len(feedback) == len(sample_targets_raw)
    for item in feedback:
        assert item.needs_training is False
        assert "no simulated results yet" in item.narrative
