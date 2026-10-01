"""
cli.py
======

Click-based CLI for the authorized-use-only phishing awareness simulation
platform. Prints the authorization/safety banner on every invocation and
enforces the --confirm-authorized gate before any simulated send occurs.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from phishing_sim import AUTHORIZATION_BANNER
from phishing_sim.campaign import Campaign
from phishing_sim.reporting import build_full_report, render_text_report
from phishing_sim.simulator import AuthorizationRequiredError, run_campaign
from phishing_sim.templates import list_templates


def _print_banner(json_only: bool) -> None:
    if not json_only:
        click.echo(AUTHORIZATION_BANNER)


@click.group()
@click.version_option(package_name="phishing-awareness-platform")
def main() -> None:
    """Authorized-use-only LLM-powered phishing simulation & awareness platform.

    This tool NEVER sends real email. All sends are simulated and logged
    locally for authorized internal security-awareness training programs.
    """


@main.command("list-templates")
@click.option("--json-only", is_flag=True, help="Emit machine-readable JSON only.")
def list_templates_cmd(json_only: bool) -> None:
    """List available offline pretext templates."""
    _print_banner(json_only)
    templates = list_templates()
    if json_only:
        click.echo(json.dumps(templates))
    else:
        click.echo("Available pretext templates:")
        for key, name in templates.items():
            click.echo(f"  - {key}: {name}")


@main.command("run-campaign")
@click.option(
    "--input",
    "input_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to JSON file of synthetic targets (see sample_data/targets.json).",
)
@click.option(
    "--template",
    "template_key",
    required=True,
    help="Pretext template key, e.g. it-password-reset, hr-policy-update, "
    "shipping-notification, invoice. See 'list-templates'.",
)
@click.option(
    "--confirm-authorized",
    is_flag=True,
    default=False,
    help=(
        "REQUIRED to actually run the simulated send step. Models an "
        "explicit organizational authorization gate. Without this flag, "
        "the send step is refused."
    ),
)
@click.option(
    "--seed",
    type=int,
    default=None,
    help="Random seed for reproducible simulated click/open/report behavior.",
)
@click.option(
    "--campaign-name",
    default="unnamed-campaign",
    help="Name/label for this simulated campaign.",
)
@click.option(
    "--use-llm",
    is_flag=True,
    default=False,
    help=(
        "Attempt optional LLM backend (requires OPENAI_API_KEY) for more "
        "varied pretext body text. Falls back to offline templates on any "
        "failure."
    ),
)
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Path to write the local simulated send log (JSON lines). "
    "Default: ./phishing_sim_output/send_log.jsonl",
)
@click.option("--json-only", is_flag=True, help="Emit machine-readable JSON only.")
def run_campaign_cmd(
    input_path: Path,
    template_key: str,
    confirm_authorized: bool,
    seed: Optional[int],
    campaign_name: str,
    use_llm: bool,
    output: Optional[Path],
    json_only: bool,
) -> None:
    """Run a simulated phishing-awareness campaign against synthetic targets.

    Loads synthetic targets from --input, renders the chosen pretext
    --template, and (ONLY if --confirm-authorized is passed) simulates the
    send step, logging results locally and printing awareness metrics.
    """
    _print_banner(json_only)

    raw = json.loads(input_path.read_text(encoding="utf-8"))
    targets_raw = raw["targets"] if isinstance(raw, dict) and "targets" in raw else raw

    try:
        campaign = Campaign.from_targets_file_data(
            name=campaign_name, template_key=template_key, raw_targets=targets_raw
        )
    except Exception as exc:  # includes UnsafeTargetError, ValueError (bad template)
        _emit_error(f"Failed to build campaign: {exc}", json_only)
        sys.exit(2)

    log_path = output or Path("phishing_sim_output") / "send_log.jsonl"

    try:
        run_campaign(
            campaign,
            confirmed_authorized=confirm_authorized,
            seed=seed,
            log_path=log_path,
            use_llm=use_llm,
        )
    except AuthorizationRequiredError as exc:
        _emit_error(str(exc), json_only)
        sys.exit(3)

    report = build_full_report(campaign)

    if json_only:
        click.echo(json.dumps(report))
    else:
        click.echo(f"Simulated send log written to: {log_path}")
        click.echo("")
        click.echo(render_text_report(campaign))


@main.command("report")
@click.option(
    "--log",
    "log_path",
    required=False,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="(Reserved) path to a previous send log. Currently informational; "
    "use run-campaign for an end-to-end run+report.",
)
@click.option("--json-only", is_flag=True, help="Emit machine-readable JSON only.")
def report_cmd(log_path: Optional[Path], json_only: bool) -> None:
    """Informational command describing how reporting works.

    Full reporting is produced automatically as part of 'run-campaign'.
    """
    _print_banner(json_only)
    msg = (
        "Reports are generated automatically at the end of 'run-campaign'. "
        "This standalone command is reserved for future use (e.g. "
        "re-rendering a report from a saved campaign results JSON file)."
    )
    if json_only:
        click.echo(json.dumps({"message": msg}))
    else:
        click.echo(msg)


def _emit_error(message: str, json_only: bool) -> None:
    if json_only:
        click.echo(json.dumps({"error": message}))
    else:
        click.secho(f"ERROR: {message}", fg="red", err=True)


if __name__ == "__main__":
    main()
