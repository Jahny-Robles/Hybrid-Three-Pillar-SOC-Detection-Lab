"""
Ground-truth validation: does the governed pipeline reproduce the verdicts
Jahny reached by hand on his two REAL specimens?

The LLM is stubbed so this runs with no API key and no network — it validates
the deterministic tooling (auth extraction, fact bundling) and the governance
layer, which are the parts that must never regress. The real LLM is exercised
separately via run_triage.py.

Run:  python -m pytest tests/ -v   (or: python tests/test_ground_truth.py)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import tools, governance
from agent.triage_agent import triage

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def stub_llm_from_facts(facts: dict) -> dict:
    """
    A deterministic stand-in for the LLM that mimics Jahny's documented reasoning,
    so the test asserts the *pipeline + governance*, not the model. DMARC fail plus
    a brand-impersonating payload host => PHISHING; clean aligned auth => LEGITIMATE.
    """
    dmarc_ok = facts["dmarc_pass"]
    brandish_host = any(
        h.endswith("googleapis.com") or "storage" in h for h in facts["url_hosts"]
    )
    sender_dom = facts["sender_domain"]
    generic_sender = sender_dom and not any(
        sender_dom.endswith(good) for good in ("viva-it.com", "sendgrid.net")
    )

    if not dmarc_ok and (brandish_host or generic_sender):
        return {
            "verdict": "PHISHING",
            "confidence": 0.95,
            "rationale": "DMARC fail on throwaway domain; payload on generic Google infra impersonating a cloud brand; urgency threat.",
            "tells": ["dmarc=fail", "nonsense sender domain", "payload on storage.googleapis.com", "same-day deletion threat"],
        }
    if dmarc_ok:
        return {
            "verdict": "LEGITIMATE",
            "confidence": 0.92,
            "rationale": "SPF/DKIM/DMARC all pass and aligned; sender consistent with reply-to.",
            "tells": ["dmarc=pass", "dkim aligned", "consistent sender"],
        }
    return {"verdict": "SUSPICIOUS", "confidence": 0.5, "rationale": "mixed signals", "tells": []}


GROUND_TRUTH = {
    "01_legit_recruiter.eml": "LEGITIMATE",
    "02_phish_cloud_storage.eml": "PHISHING",
}


def test_ground_truth_verdicts():
    for fname, expected in GROUND_TRUTH.items():
        raw = (SAMPLES / fname).read_text(encoding="utf-8")
        record = triage(raw, source_label=fname, llm=stub_llm_from_facts)
        got = record["agent_verdict"]["verdict"]
        assert got == expected, f"{fname}: expected {expected}, got {got}"


def test_confidence_floor_forces_escalation():
    """A low-confidence verdict must ESCALATE even if it says LEGITIMATE."""
    action = governance.decide_action("LEGITIMATE", 0.40)
    assert action["action"] == "ESCALATE"


def test_l0_never_auto_actions():
    """At the pilot's L0, even a confident verdict is recommend-only."""
    assert governance.AUTONOMY_LEVEL == 0
    action = governance.decide_action("PHISHING", 0.99)
    assert action["action"] == "ESCALATE"


if __name__ == "__main__":
    test_ground_truth_verdicts()
    test_confidence_floor_forces_escalation()
    test_l0_never_auto_actions()
    print("All ground-truth and governance checks passed.")
