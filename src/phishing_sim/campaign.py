"""
campaign.py
===========

Dataclasses modeling a simulated phishing-awareness campaign.

SAFETY: Target email addresses must be synthetic (validated to end with a
fake/test-looking domain). This module holds no SMTP/network logic -- it is
pure data modeling. Actual "sending" happens only in simulator.py and is
always a local log write, never a network call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

# Domains that are considered acceptable "synthetic" domains for this tool.
# Anything NOT matching one of these suffixes is rejected, to help prevent
# accidental use of real recipient addresses.
ALLOWED_SYNTHETIC_DOMAIN_SUFFIXES = (
    "@fictionalcorp.test",
    ".test",  # any subdomain of a .test TLD, per RFC 2606 reserved TLD
    ".invalid",
    ".example",
)


class UnsafeTargetError(ValueError):
    """Raised when a target's email does not look synthetic/fake."""


def _looks_synthetic(email: str) -> bool:
    email = email.strip().lower()
    if "@" not in email:
        return False
    domain = email.split("@", 1)[1]
    return domain.endswith((".test", ".invalid", ".example")) or email.endswith(
        "@fictionalcorp.test"
    )


@dataclass
class Target:
    """A synthetic simulated training target (NOT a real person)."""

    name: str
    email: str
    department: str
    role: str = ""

    def __post_init__(self) -> None:
        if not _looks_synthetic(self.email):
            raise UnsafeTargetError(
                f"Refusing non-synthetic-looking email address: {self.email!r}. "
                "Target emails must use a reserved/fake domain such as "
                "'@fictionalcorp.test', or end in .test/.invalid/.example."
            )

    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "email": self.email,
            "department": self.department,
            "role": self.role,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "Target":
        return cls(
            name=data["name"],
            email=data["email"],
            department=data.get("department", "Unknown"),
            role=data.get("role", ""),
        )


@dataclass
class SimulatedResult:
    """Simulated outcome of a single target within a campaign run."""

    target_email: str
    sent: bool = False
    opened: bool = False
    clicked: bool = False
    reported: bool = False
    sent_at: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "target_email": self.target_email,
            "sent": self.sent,
            "opened": self.opened,
            "clicked": self.clicked,
            "reported": self.reported,
            "sent_at": self.sent_at,
        }


@dataclass
class Campaign:
    """A simulated security-awareness phishing campaign.

    Holds synthetic targets, a chosen pretext template key, and the
    simulated per-target results produced by simulator.py.
    """

    name: str
    template_key: str
    targets: List[Target] = field(default_factory=list)
    results: Dict[str, SimulatedResult] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def add_target(self, target: Target) -> None:
        self.targets.append(target)

    def departments(self) -> List[str]:
        seen: List[str] = []
        for t in self.targets:
            if t.department not in seen:
                seen.append(t.department)
        return seen

    def record_result(self, result: SimulatedResult) -> None:
        self.results[result.target_email] = result

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "template_key": self.template_key,
            "created_at": self.created_at,
            "targets": [t.to_dict() for t in self.targets],
            "results": {k: v.to_dict() for k, v in self.results.items()},
        }

    @classmethod
    def from_targets_file_data(
        cls, name: str, template_key: str, raw_targets: List[Dict[str, str]]
    ) -> "Campaign":
        campaign = cls(name=name, template_key=template_key)
        for raw in raw_targets:
            campaign.add_target(Target.from_dict(raw))
        return campaign
