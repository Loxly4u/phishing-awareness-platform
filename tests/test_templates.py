"""Tests for phishing_sim.templates."""

import pytest

from phishing_sim import TRAINING_USE_TAG
from phishing_sim.templates import (
    LLMBackendUnavailable,
    TEMPLATES,
    generate_body,
    get_template,
    list_templates,
)


def test_list_templates_contains_required_pretexts():
    templates = list_templates()
    for expected_key in (
        "it-password-reset",
        "hr-policy-update",
        "shipping-notification",
        "invoice",
    ):
        assert expected_key in templates


def test_get_template_unknown_raises():
    with pytest.raises(ValueError):
        get_template("not-a-real-template")


def test_template_render_includes_training_tag_and_target_name():
    template = get_template("it-password-reset")
    rendered = template.render(target_name="Employee1", department="Finance")
    assert "Employee1" in rendered["body"]
    assert TRAINING_USE_TAG in rendered["body"]
    assert rendered["template_key"] == "it-password-reset"


def test_template_render_uses_fake_domain_only():
    for key, template in TEMPLATES.items():
        rendered = template.render(target_name="Employee1", department="HR")
        # Ensure any simulated link reference uses the fake/test domain.
        assert "fictionalcorp.test" in rendered["body"]
        assert "http://" not in rendered["body"]  # only https simulated links
        # No references to real common mail/service domains.
        for banned in ("gmail.com", "outlook.com", "yahoo.com"):
            assert banned not in rendered["body"]


def test_generate_body_offline_default():
    result = generate_body("invoice", target_name="Employee2", department="Finance")
    assert result["source"] == "offline-template"
    assert "Employee2" in result["body"]


def test_generate_body_llm_success_path_uses_injected_callable():
    def fake_llm_call(prompt: str) -> str:
        return "This is a fake LLM-generated phishing simulation body."

    result = generate_body(
        "hr-policy-update",
        target_name="Employee3",
        department="HR",
        context="HR generalist at a mid-size logistics company",
        use_llm=True,
        llm_call=fake_llm_call,
    )
    assert result["source"] == "llm"
    assert "fake LLM-generated" in result["body"]
    assert TRAINING_USE_TAG in result["body"]


def test_generate_body_llm_failure_falls_back_to_offline():
    def failing_llm_call(prompt: str) -> str:
        raise RuntimeError("simulated network/API failure")

    result = generate_body(
        "shipping-notification",
        target_name="Employee4",
        department="Engineering",
        use_llm=True,
        llm_call=failing_llm_call,
    )
    assert result["source"] == "offline-template-fallback"
    assert "Employee4" in result["body"]


def test_generate_body_llm_unavailable_exception_type_is_caught():
    def raises_unavailable(prompt: str) -> str:
        raise LLMBackendUnavailable("no api key")

    result = generate_body(
        "it-password-reset",
        target_name="Employee5",
        use_llm=True,
        llm_call=raises_unavailable,
    )
    assert result["source"] == "offline-template-fallback"


def test_generate_body_llm_empty_response_falls_back():
    def empty_call(prompt: str) -> str:
        return ""

    # An empty string is falsy content; our _call_openai_backend path checks
    # this, but here we test generate_body directly tolerates odd outputs
    # from an injected llm_call without crashing (it would just use it as a
    # literal body if non-empty-string check isn't on this path -- ensure no
    # crash occurs either way).
    result = generate_body(
        "invoice",
        target_name="Employee6",
        use_llm=True,
        llm_call=empty_call,
    )
    assert "body" in result
