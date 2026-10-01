"""Tests for phishing_sim.campaign (Target/Campaign dataclasses)."""

import pytest

from phishing_sim.campaign import Campaign, SimulatedResult, Target, UnsafeTargetError


def test_target_accepts_fictionalcorp_test_domain():
    t = Target(name="Employee1", email="employee1@fictionalcorp.test", department="Finance")
    assert t.email.endswith("@fictionalcorp.test")


@pytest.mark.parametrize(
    "email",
    [
        "realuser@gmail.com",
        "someone@company.com",
        "attacker@evil.com",
        "notanemail",
    ],
)
def test_target_rejects_non_synthetic_email(email):
    with pytest.raises(UnsafeTargetError):
        Target(name="Someone", email=email, department="Finance")


def test_target_accepts_other_reserved_test_tlds():
    for email in ("a@example.test", "b@example.invalid", "c@example.example"):
        t = Target(name="X", email=email, department="HR")
        assert t.email == email


def test_target_to_dict_and_from_dict_roundtrip():
    t = Target(name="Employee1", email="employee1@fictionalcorp.test", department="Finance", role="Analyst")
    data = t.to_dict()
    rebuilt = Target.from_dict(data)
    assert rebuilt == t


def test_campaign_add_target_and_departments():
    campaign = Campaign(name="Q1-Test", template_key="invoice")
    campaign.add_target(Target("E1", "e1@fictionalcorp.test", "Finance"))
    campaign.add_target(Target("E2", "e2@fictionalcorp.test", "Finance"))
    campaign.add_target(Target("E3", "e3@fictionalcorp.test", "HR"))
    assert campaign.departments() == ["Finance", "HR"]
    assert len(campaign.targets) == 3


def test_campaign_record_result_and_to_dict():
    campaign = Campaign(name="Q1-Test", template_key="invoice")
    campaign.add_target(Target("E1", "e1@fictionalcorp.test", "Finance"))
    result = SimulatedResult(target_email="e1@fictionalcorp.test", sent=True, clicked=True)
    campaign.record_result(result)
    data = campaign.to_dict()
    assert data["results"]["e1@fictionalcorp.test"]["clicked"] is True
    assert data["name"] == "Q1-Test"


def test_campaign_from_targets_file_data_builds_targets():
    raw = [
        {"name": "Employee1", "email": "employee1@fictionalcorp.test", "department": "Finance"},
        {"name": "Employee2", "email": "employee2@fictionalcorp.test", "department": "HR"},
    ]
    campaign = Campaign.from_targets_file_data("MyCampaign", "it-password-reset", raw)
    assert len(campaign.targets) == 2
    assert campaign.targets[0].name == "Employee1"


def test_campaign_from_targets_file_data_rejects_unsafe_email():
    raw = [{"name": "RealPerson", "email": "real.person@acmecorp.com", "department": "Finance"}]
    with pytest.raises(UnsafeTargetError):
        Campaign.from_targets_file_data("MyCampaign", "invoice", raw)
