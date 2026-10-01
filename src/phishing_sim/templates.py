"""
templates.py
============

Offline, template-based phishing *pretext* generator for authorized internal
security-awareness simulations, with an optional pluggable LLM backend for
more varied/contextual body text.

SAFETY: This module never sends anything. It only produces text content
(strings) that the simulator logs locally. There are no links to real
infrastructure -- any "link" or "button" text in templates is a clearly
fake placeholder pointing at the synthetic domain (fictionalcorp.test).

All generated content is tagged with TRAINING_USE_TAG.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from phishing_sim import TRAINING_USE_TAG

# ---------------------------------------------------------------------------
# Offline template catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PretextTemplate:
    """A parameterized phishing pretext template (offline, deterministic)."""

    key: str
    display_name: str
    subject: str
    body_template: str
    risk_indicators: tuple = ()

    def render(self, target_name: str, department: str = "", **extra: str) -> Dict[str, str]:
        """Render the template into a concrete subject/body for a target.

        Rendering is pure string formatting -- no network calls, no real
        links. Always appends the training-use tag footer.
        """
        context = {
            "target_name": target_name,
            "department": department or "your department",
            "company": extra.get("company", "FictionalCorp"),
            "fake_domain": extra.get("fake_domain", "fictionalcorp.test"),
        }
        context.update(extra)
        body = self.body_template.format(**context)
        body = f"{body}\n\n---\n[{TRAINING_USE_TAG}]"
        subject = self.subject.format(**context)
        return {"subject": subject, "body": body, "template_key": self.key}


_IT_PASSWORD_RESET = PretextTemplate(
    key="it-password-reset",
    display_name="Fake IT Password Reset",
    subject="Action Required: Your {company} password expires today",
    body_template=(
        "Hi {target_name},\n\n"
        "Our records show that your {company} account password will expire "
        "within 24 hours. To avoid losing access to email and internal "
        "systems, please verify your identity at the IT self-service portal "
        "(simulated link: https://password-reset.{fake_domain}/verify) and "
        "set a new password.\n\n"
        "If you do not take action, your account may be temporarily locked.\n\n"
        "Thank you,\nIT Service Desk\n{company} Technology Services"
    ),
    risk_indicators=("urgency", "credential harvesting", "fake IT portal link"),
)

_HR_POLICY_UPDATE = PretextTemplate(
    key="hr-policy-update",
    display_name="Fake HR Policy Update",
    subject="Updated {company} Employee Handbook - Acknowledgement Needed",
    body_template=(
        "Dear {target_name},\n\n"
        "As part of our annual review, {company} HR has updated the "
        "employee handbook, including policies relevant to {department}. "
        "Please review the changes and sign the acknowledgement form "
        "(simulated link: https://hr-portal.{fake_domain}/handbook-ack) "
        "by end of week.\n\n"
        "Failure to acknowledge may delay your next payroll cycle.\n\n"
        "Best regards,\nHuman Resources\n{company}"
    ),
    risk_indicators=("authority", "payroll threat", "fake HR portal link"),
)

_SHIPPING_NOTIFICATION = PretextTemplate(
    key="shipping-notification",
    display_name="Fake Shipping Notification",
    subject="Delivery Exception: Package for {target_name} needs attention",
    body_template=(
        "Hello {target_name},\n\n"
        "We attempted to deliver a package addressed to you but encountered "
        "an address verification issue. To reschedule delivery, please "
        "confirm your details (simulated link: "
        "https://track.{fake_domain}/confirm) within 48 hours or the "
        "package will be returned to sender.\n\n"
        "Tracking Reference: SIM-{department}-00042\n\n"
        "Thanks,\nCustomer Delivery Support"
    ),
    risk_indicators=("urgency", "curiosity", "fake tracking link"),
)

_INVOICE = PretextTemplate(
    key="invoice",
    display_name="Fake Invoice",
    subject="Invoice #INV-2041 pending approval - {department}",
    body_template=(
        "Hi {target_name},\n\n"
        "Attached is invoice #INV-2041 for recent services billed to the "
        "{department} cost center at {company}. Please review and approve "
        "payment via the finance portal (simulated link: "
        "https://invoices.{fake_domain}/approve?id=2041) by Friday to avoid "
        "late fees.\n\n"
        "Regards,\nAccounts Payable\nVendor Services"
    ),
    risk_indicators=("fake attachment reference", "financial pressure", "fake finance link"),
)

TEMPLATES: Dict[str, PretextTemplate] = {
    t.key: t
    for t in (
        _IT_PASSWORD_RESET,
        _HR_POLICY_UPDATE,
        _SHIPPING_NOTIFICATION,
        _INVOICE,
    )
}


def list_templates() -> Dict[str, str]:
    """Return mapping of template key -> display name."""
    return {k: v.display_name for k, v in TEMPLATES.items()}


def get_template(key: str) -> PretextTemplate:
    try:
        return TEMPLATES[key]
    except KeyError as exc:
        valid = ", ".join(sorted(TEMPLATES))
        raise ValueError(f"Unknown template '{key}'. Valid options: {valid}") from exc


# ---------------------------------------------------------------------------
# Optional pluggable LLM backend
# ---------------------------------------------------------------------------
#
# If OPENAI_API_KEY is set AND the openai package is importable, callers may
# request LLM-generated body text for more varied/contextual phishing
# pretexts given a target role/department/industry context string. On ANY
# failure (missing key, import error, network error, API error, timeout) we
# gracefully fall back to the offline template rendering above. No exception
# from the LLM path is ever allowed to propagate.


class LLMBackendUnavailable(Exception):
    """Raised internally when the LLM backend cannot be used; always caught."""


def _call_openai_backend(prompt: str, model: str = "gpt-4o-mini") -> str:
    """Attempt to call the OpenAI API to generate pretext body text.

    Raises LLMBackendUnavailable on any problem; never raises other errors
    to callers of generate_body().
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise LLMBackendUnavailable("OPENAI_API_KEY not set")

    try:
        import openai  # type: ignore
    except ImportError as exc:
        raise LLMBackendUnavailable("openai package not installed") from exc

    try:
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You generate short, clearly-labeled example phishing "
                        "email bodies STRICTLY for authorized internal "
                        "security-awareness training simulations. Never "
                        "include real URLs or real company names; use "
                        "fictionalcorp.test placeholders only."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            timeout=10,
        )
        content = response.choices[0].message.content
        if not content:
            raise LLMBackendUnavailable("empty LLM response")
        return content.strip()
    except Exception as exc:  # noqa: BLE001 - any backend failure -> fallback
        raise LLMBackendUnavailable(str(exc)) from exc


def generate_body(
    template_key: str,
    target_name: str,
    department: str = "",
    context: str = "",
    use_llm: bool = False,
    llm_call: Optional[Callable[[str], str]] = None,
    **extra: str,
) -> Dict[str, str]:
    """Generate pretext subject/body.

    Offline template rendering is the default and the guaranteed fallback.
    If use_llm=True, attempts the LLM backend first (or an injected
    `llm_call` callable, primarily for testing), given a target role/
    department/industry context string. Any failure falls back to the
    offline template deterministically -- callers can rely on this function
    never raising.
    """
    template = get_template(template_key)
    rendered = template.render(target_name=target_name, department=department, **extra)

    if not use_llm:
        rendered["source"] = "offline-template"
        return rendered

    prompt = (
        f"Pretext type: {template.display_name}.\n"
        f"Target role/department/industry context: {context or department}.\n"
        f"Write a short (<180 words) phishing-simulation email body for "
        f"'{target_name}'. Use only the fake domain fictionalcorp.test for "
        f"any links. Keep it realistic but clearly for an authorized "
        f"training simulation."
    )

    try:
        caller = llm_call if llm_call is not None else _call_openai_backend
        body_text = caller(prompt)
        body_text = f"{body_text}\n\n---\n[{TRAINING_USE_TAG}]"
        return {
            "subject": rendered["subject"],
            "body": body_text,
            "template_key": template_key,
            "source": "llm",
        }
    except Exception:  # noqa: BLE001 - graceful fallback on ANY failure
        rendered["source"] = "offline-template-fallback"
        return rendered
