"""
reporting.py
============

Generates offline, template-based natural-language training feedback
reports from simulated campaign results: per-employee and per-department
summaries indicating who needs follow-up security-awareness training.

No network calls. No LLM dependency. Pure string templating over the
Campaign's in-memory results.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from phishing_sim.campaign import Campaign
from phishing_sim.simulator import compute_department_metrics, compute_overall_metrics


@dataclass
class EmployeeFeedback:
    name: str
    email: str
    department: str
    clicked: bool
    reported: bool
    opened: bool
    needs_training: bool
    narrative: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "email": self.email,
            "department": self.department,
            "clicked": self.clicked,
            "reported": self.reported,
            "opened": self.opened,
            "needs_training": self.needs_training,
            "narrative": self.narrative,
        }


def _employee_narrative(name: str, clicked: bool, reported: bool, opened: bool) -> str:
    if clicked and not reported:
        return (
            f"{name} clicked the simulated phishing link and did not report it. "
            "Recommend mandatory follow-up training on identifying phishing "
            "indicators (urgency, suspicious links, mismatched domains)."
        )
    if clicked and reported:
        return (
            f"{name} clicked the simulated link but subsequently reported the "
            "message. Recommend reinforcing 'stop and verify before clicking' "
            "habits; reporting behavior is a positive sign."
        )
    if reported and not clicked:
        return (
            f"{name} correctly identified and reported the simulated phishing "
            "email without interacting with it. No follow-up training required; "
            "consider positive recognition."
        )
    if opened and not clicked and not reported:
        return (
            f"{name} opened the message but neither clicked nor reported it. "
            "Light-touch reminder recommended: encourage reporting suspicious "
            "emails even when not acted upon."
        )
    return (
        f"{name} did not open the simulated message during this campaign window. "
        "No action needed; include in future awareness refreshers."
    )


def build_employee_feedback(campaign: Campaign) -> List[EmployeeFeedback]:
    feedback: List[EmployeeFeedback] = []
    for target in campaign.targets:
        result = campaign.results.get(target.email)
        if result is None:
            # No result recorded (e.g., campaign not run yet / dry run).
            feedback.append(
                EmployeeFeedback(
                    name=target.name,
                    email=target.email,
                    department=target.department,
                    clicked=False,
                    reported=False,
                    opened=False,
                    needs_training=False,
                    narrative=(
                        f"{target.name} has no simulated results yet; campaign "
                        "send step may not have been run."
                    ),
                )
            )
            continue

        needs_training = result.clicked and not result.reported
        feedback.append(
            EmployeeFeedback(
                name=target.name,
                email=target.email,
                department=target.department,
                clicked=result.clicked,
                reported=result.reported,
                opened=result.opened,
                needs_training=needs_training,
                narrative=_employee_narrative(
                    target.name, result.clicked, result.reported, result.opened
                ),
            )
        )
    return feedback


def _department_narrative(dept: str, click_rate: float, report_rate: float) -> str:
    if click_rate >= 0.5:
        risk = "HIGH"
        advice = "Schedule immediate mandatory refresher training for this department."
    elif click_rate >= 0.25:
        risk = "MODERATE"
        advice = "Recommend targeted follow-up training within the next cycle."
    else:
        risk = "LOW"
        advice = "Continue periodic awareness reinforcement; no urgent action needed."

    reporting_note = (
        "Reporting behavior is strong, which helps offset risk."
        if report_rate >= 0.4
        else "Reporting behavior is low; encourage use of the 'report phishing' workflow."
    )

    return (
        f"{dept}: click rate {click_rate:.0%}, report rate {report_rate:.0%}. "
        f"Overall risk level: {risk}. {advice} {reporting_note}"
    )


def build_department_report(campaign: Campaign) -> List[Dict[str, object]]:
    reports = []
    for metrics in compute_department_metrics(campaign):
        reports.append(
            {
                **metrics.to_dict(),
                "narrative": _department_narrative(
                    metrics.department, metrics.click_rate, metrics.report_rate
                ),
            }
        )
    return reports


def build_full_report(campaign: Campaign) -> Dict[str, object]:
    """Build the full natural-language + structured report for a campaign."""
    employee_feedback = build_employee_feedback(campaign)
    department_report = build_department_report(campaign)
    overall = compute_overall_metrics(campaign)

    follow_up_needed = [e.to_dict() for e in employee_feedback if e.needs_training]

    summary_lines = [
        f"Campaign '{campaign.name}' (template: {campaign.template_key}) summary:",
        f"  Overall click rate: {overall['click_rate']:.0%}",
        f"  Overall report rate: {overall['report_rate']:.0%}",
        f"  {len(follow_up_needed)} of {overall['total_targets']} employees flagged for follow-up training.",
    ]

    return {
        "campaign_name": campaign.name,
        "template_key": campaign.template_key,
        "overall_metrics": overall,
        "department_report": department_report,
        "employee_feedback": [e.to_dict() for e in employee_feedback],
        "follow_up_needed": follow_up_needed,
        "summary_text": "\n".join(summary_lines),
    }


def render_text_report(campaign: Campaign) -> str:
    """Render a full human-readable plain-text training feedback report."""
    report = build_full_report(campaign)
    lines: List[str] = []
    lines.append("=" * 70)
    lines.append(f"SECURITY AWARENESS TRAINING FEEDBACK REPORT")
    lines.append(f"Campaign: {report['campaign_name']}  |  Template: {report['template_key']}")
    lines.append("=" * 70)
    lines.append("")
    lines.append(report["summary_text"])
    lines.append("")
    lines.append("-- Per-Department Breakdown --")
    for dept in report["department_report"]:
        lines.append(f"* {dept['narrative']}")
    lines.append("")
    lines.append("-- Per-Employee Feedback --")
    for emp in report["employee_feedback"]:
        flag = " [FOLLOW-UP NEEDED]" if emp["needs_training"] else ""
        lines.append(f"* {emp['name']} ({emp['department']}){flag}: {emp['narrative']}")
    lines.append("")
    lines.append("[INTERNAL AWARENESS TRAINING USE ONLY - SIMULATED DATA]")
    return "\n".join(lines)
