# Phishing Awareness Platform (Simulation Only)

## ⚠️ Scope & Safety — Read First

**This tool is FOR USE ONLY IN AUTHORIZED INTERNAL SECURITY AWARENESS
PROGRAMS WITH EXPLICIT ORGANIZATIONAL APPROVAL.**

- **No real email is ever sent.** There is no SMTP client, no `socket`
  usage, and no network call to any mail server anywhere in this codebase.
  "Sending" means rendering a pretext template and appending a JSON record
  to a local log file (`phishing_sim_output/send_log.jsonl` by default).
- **Synthetic data only.** `Target` objects refuse to construct unless the
  email address uses a reserved/fake domain (`@fictionalcorp.test`, or any
  address ending in `.test`, `.invalid`, `.example` per RFC 2606). Real
  email addresses are rejected with `UnsafeTargetError`.
- **Every generated pretext is tagged** `INTERNAL AWARENESS TRAINING USE
  ONLY` in its body footer.
- **Authorization gate.** The CLI prints a safety/authorization banner on
  every run and refuses to execute the simulated send step unless
  `--confirm-authorized` is explicitly passed. This models a real-world
  requirement for documented organizational sign-off before running any
  awareness campaign, simulated or not.
- Click/open/report behavior is a **seeded local random simulation**
  (`random.Random(seed)`), not real tracking pixels, not real links, and
  not any kind of telemetry callback.

If you are looking for a tool to send real phishing emails to real people,
this is not it, and this repository will not be extended to do that.

## Architecture

```
                      ┌─────────────────────────┐
                      │   sample_data/targets.json│
                      │  (synthetic employees)    │
                      └────────────┬──────────────┘
                                   │
                                   ▼
┌───────────────┐          ┌──────────────┐          ┌───────────────────┐
│ templates.py  │ render   │ campaign.py  │  targets │   cli.py           │
│ offline       │◄─────────┤ Campaign /   │◄─────────┤  (click)           │
│ templates +   │          │ Target /     │          │  run-campaign      │
│ optional LLM  │          │ SimulatedResult│         │  list-templates    │
│ (graceful     │          └──────┬───────┘          │  --confirm-        │
│  fallback)    │                 │                  │   authorized gate  │
└───────────────┘                 │                  └─────────┬──────────┘
                                   ▼                            │
                           ┌──────────────┐                     │
                           │ simulator.py │◄────────────────────┘
                           │ - NO SMTP    │   invokes
                           │ - NO socket  │
                           │ - local JSON │
                           │   log only   │
                           │ - seeded     │
                           │   click/open/│
                           │   report sim │
                           └──────┬───────┘
                                  │ campaign w/ results
                                  ▼
                           ┌──────────────┐
                           │ reporting.py │
                           │ per-employee │
                           │ + per-dept   │
                           │ NL feedback  │
                           └──────────────┘
```

## Setup

```bash
cd phishing-awareness-platform
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Optional LLM backend (pretext body variation only — still simulation-only,
still never sends anything):

```bash
pip install -e ".[llm]"
export OPENAI_API_KEY=sk-...   # optional; falls back to offline templates on any failure
```

## Usage

List available offline pretext templates:

```bash
phishing-sim list-templates
```

Run a simulated campaign (the send step is refused without
`--confirm-authorized`):

```bash
# This will print the banner, build the campaign, and then REFUSE the send step:
phishing-sim run-campaign --input sample_data/targets.json --template it-password-reset --seed 42

# This authorizes the simulated send step (still 100% local, still no real email):
phishing-sim run-campaign \
  --input sample_data/targets.json \
  --template it-password-reset \
  --confirm-authorized \
  --seed 42 \
  --output phishing_sim_output/send_log.jsonl
```

Other options:

- `--seed INT` — seed the simulated click/open/report behavior for
  reproducible results.
- `--json-only` — emit machine-readable JSON (suppresses the banner text
  but the safety constraints still apply).
- `--use-llm` — attempt the optional LLM backend for pretext body text,
  given target role/department context; gracefully falls back to offline
  templates on any failure (missing key, network error, etc.).
- `--campaign-name TEXT` — label for the simulated campaign.

Available template keys: `it-password-reset`, `hr-policy-update`,
`shipping-notification`, `invoice`.

## Limitations

- This is a **training/demo tool**, not a production phishing-simulation
  platform. It does not integrate with real mail gateways, SSO, or
  real click-tracking infrastructure, by design.
- Simulated click/open/report probabilities are illustrative placeholders,
  not based on real benchmarked awareness data.
- The optional LLM backend requires network access to the LLM provider
  itself (not to any mail server) and is entirely optional; the tool is
  fully functional offline.
- Target input is only validated for "looks synthetic" (reserved/fake
  domains) — it is the operator's responsibility to ensure data used is
  actually synthetic/sample data per your organization's policy.

## Testing

```bash
pytest -v
```

The test suite includes:
- Template generation and LLM-fallback behavior
- Campaign/Target data model and synthetic-email validation
- Deterministic, seeded simulation logic and metrics
- Reporting (per-employee / per-department narrative generation)
- CLI behavior, including an explicit test that `run-campaign` **refuses**
  to run the send step without `--confirm-authorized`
- A regression test (static source scan + dynamic monkeypatch guard on
  `socket.socket` / `smtplib.SMTP`) asserting no code path makes real
  network/SMTP connections
