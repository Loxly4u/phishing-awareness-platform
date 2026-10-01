"""
simulator.py
============

Simulates a phishing-awareness campaign "send" step.

HARD SAFETY GUARANTEES
-----------------------
- No `smtplib`, `socket`, or any networking module is imported or used
  anywhere in this module.
- "Sending" means: render the pretext text via templates.py, then append a
  JSON record to a local log file. That's it. Nothing is transmitted
  anywhere.
- Click/open/report behavior is simulated using Python's `random` module
  seeded for reproducibility -- it does NOT use real tracking pixels, real
  links, or any network/webhook callback.
- The caller (cli.py) is responsible for enforcing the --confirm-authorized
  gate before invoking run_campaign(); run_campaign() ALSO independently
  enforces it as defense-in-depth.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from phishing_sim.campaign import Campaign, SimulatedResult, Target
from phishing_sim.templates import generate_body

# Explicit allow-list of modules this file is permitted to need. This
# constant exists purely as a documented, grep-able assertion for tests /
# reviewers that no networking primitives are used here.
NO_NETWORK_MODULES_USED = ("smtplib", "socket", "requests", "httpx", "urllib")


class AuthorizationRequiredError(RuntimeError):
    """Raised when attempting to run the send step without authorization."""


@dataclass
class DepartmentMetrics:
    department: str
    total: int
    sent: int
    opened: int
    clicked: int
    reported: int

    @property
    def click_rate(self) -> float:
        return round(self.clicked / self.total, 4) if self.total else 0.0

    @property
    def report_rate(self) -> float:
        return round(self.reported / self.total, 4) if self.total else 0.0

    @property
    def open_rate(self) -> float:
        return round(self.opened / self.total, 4) if self.total else 0.0

    def to_dict(self) -> Dict[str, object]:
        return {
            "department": self.department,
            "total": self.total,
            "sent": self.sent,
            "opened": self.opened,
            "clicked": self.clicked,
            "reported": self.reported,
            "click_rate": self.click_rate,
            "report_rate": self.report_rate,
            "open_rate": self.open_rate,
        }


def _simulate_target_behavior(rng: random.Random) -> Dict[str, bool]:
    """Randomized (seeded) simulation of a target's behavior.

    Simulated probabilities (illustrative, for demo/training purposes only):
      - opened: 70%
      - clicked | opened: 35%
      - reported | opened and NOT clicked: 40%
      - reported | opened and clicked: 10% (realistic: some still report late)
    """
    opened = rng.random() < 0.70
    clicked = opened and (rng.random() < 0.35)
    if opened and not clicked:
        reported = rng.random() < 0.40
    elif opened and clicked:
        reported = rng.random() < 0.10
    else:
        reported = False
    return {"opened": opened, "clicked": clicked, "reported": reported}


def run_campaign(
    campaign: Campaign,
    confirmed_authorized: bool,
    seed: Optional[int] = None,
    log_path: Optional[Path] = None,
    use_llm: bool = False,
) -> Campaign:
    """Run the simulated send step for every target in the campaign.

    Parameters
    ----------
    campaign: Campaign to run.
    confirmed_authorized: MUST be True (propagated from --confirm-authorized).
        If False, raises AuthorizationRequiredError and performs NO sends,
        NO log writes, and NO result mutation.
    seed: optional int seed for reproducible simulated click/report behavior.
    log_path: local file path to append JSON-lines send records to. If None,
        no log file is written (useful for pure in-memory tests), but the
        in-memory results are still recorded.
    use_llm: whether to attempt the optional LLM backend for body text.

    Returns
    -------
    The same Campaign object, mutated in place with results, for convenience.
    """
    if not confirmed_authorized:
        raise AuthorizationRequiredError(
            "Refusing to run simulated send step: --confirm-authorized was "
            "not provided. This tool requires an explicit authorization "
            "flag before any simulated send, modeling a real-world "
            "authorization gate for security awareness programs."
        )

    rng = random.Random(seed)
    log_lines: List[str] = []

    for target in campaign.targets:
        rendered = generate_body(
            template_key=campaign.template_key,
            target_name=target.name,
            department=target.department,
            use_llm=use_llm,
        )

        sent_at = datetime.now(timezone.utc).isoformat()
        behavior = _simulate_target_behavior(rng)

        result = SimulatedResult(
            target_email=target.email,
            sent=True,
            opened=behavior["opened"],
            clicked=behavior["clicked"],
            reported=behavior["reported"],
            sent_at=sent_at,
        )
        campaign.record_result(result)

        log_record = {
            "event": "simulated_send",
            "campaign": campaign.name,
            "template_key": campaign.template_key,
            "target_name": target.name,
            "target_email": target.email,
            "department": target.department,
            "subject": rendered["subject"],
            "body_source": rendered.get("source", "offline-template"),
            "sent_at": sent_at,
            "simulated_result": result.to_dict(),
            "note": (
                "SIMULATED ONLY. No real email was sent. No SMTP/socket "
                "connection was made. Logged locally for training-program "
                "review purposes."
            ),
        }
        log_lines.append(json.dumps(log_record))

    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as fh:
            for line in log_lines:
                fh.write(line + "\n")

    return campaign


def compute_department_metrics(campaign: Campaign) -> List[DepartmentMetrics]:
    """Compute per-department awareness metrics from a campaign's results."""
    metrics: List[DepartmentMetrics] = []
    for department in campaign.departments():
        dept_targets = [t for t in campaign.targets if t.department == department]
        total = len(dept_targets)
        sent = opened = clicked = reported = 0
        for t in dept_targets:
            result = campaign.results.get(t.email)
            if result is None:
                continue
            sent += int(result.sent)
            opened += int(result.opened)
            clicked += int(result.clicked)
            reported += int(result.reported)
        metrics.append(
            DepartmentMetrics(
                department=department,
                total=total,
                sent=sent,
                opened=opened,
                clicked=clicked,
                reported=reported,
            )
        )
    return metrics


def compute_overall_metrics(campaign: Campaign) -> Dict[str, object]:
    """Compute overall (all-department) awareness metrics for a campaign."""
    total = len(campaign.targets)
    sent = sum(1 for r in campaign.results.values() if r.sent)
    opened = sum(1 for r in campaign.results.values() if r.opened)
    clicked = sum(1 for r in campaign.results.values() if r.clicked)
    reported = sum(1 for r in campaign.results.values() if r.reported)
    return {
        "total_targets": total,
        "sent": sent,
        "opened": opened,
        "clicked": clicked,
        "reported": reported,
        "click_rate": round(clicked / total, 4) if total else 0.0,
        "report_rate": round(reported / total, 4) if total else 0.0,
        "open_rate": round(opened / total, 4) if total else 0.0,
    }
