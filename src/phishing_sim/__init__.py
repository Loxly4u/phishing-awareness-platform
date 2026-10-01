"""
phishing_sim: LLM-Powered Phishing Simulation & Awareness Platform.

SCOPE / SAFETY NOTICE
----------------------
This package is FOR USE ONLY IN AUTHORIZED INTERNAL SECURITY AWARENESS
PROGRAMS WITH EXPLICIT ORGANIZATIONAL APPROVAL.

- This tool NEVER sends real email. All "sending" is simulated and logged
  to a local file only. No SMTP, no real network calls to mail servers.
- Target/recipient data must be synthetic sample data only.
- All generated pretexts are tagged for INTERNAL AWARENESS TRAINING USE ONLY.
"""

__version__ = "0.1.0"

AUTHORIZATION_BANNER = (
    "=" * 78 + "\n"
    "FOR USE ONLY IN AUTHORIZED INTERNAL SECURITY AWARENESS PROGRAMS WITH\n"
    "EXPLICIT ORGANIZATIONAL APPROVAL. THIS TOOL DOES NOT SEND REAL EMAIL.\n"
    "All sends are SIMULATED and logged locally. Targets must be synthetic.\n"
    "Content is tagged: INTERNAL AWARENESS TRAINING USE ONLY.\n" + "=" * 78
)

TRAINING_USE_TAG = "INTERNAL AWARENESS TRAINING USE ONLY"
