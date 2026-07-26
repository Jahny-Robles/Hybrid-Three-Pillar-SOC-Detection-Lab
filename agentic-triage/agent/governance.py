"""
Governance layer: autonomy level + confidence floor.

This is the detection-engineering heart of the project. The agent NEVER decides
its own authority. It proposes a verdict + confidence; this module decides what
action (if any) is permitted at the current autonomy level. Promotion between
levels is a HUMAN decision, justified by the audit log — never automatic.
"""

# Current operating level. Pilot starts at L0 and stays there until the audit
# log demonstrates the agent's verdicts match human ground truth.
AUTONOMY_LEVEL = 0

# Below this confidence, the agent MUST escalate to a human regardless of verdict.
# This is the guardrail against the core agentic failure mode: an agent that
# confidently (or worse, quietly) closes a case a human would have escalated.
CONFIDENCE_FLOOR = 0.80

# What each level is permitted to auto-action. Everything else -> ESCALATE.
LEVEL_POLICY = {
    0: set(),                                  # recommend only, no auto-action
    1: {"auto_close_legitimate"},              # only clear-benign auto-closes
    2: {"auto_close_legitimate", "auto_close_phishing"},
    3: {"auto_close_legitimate", "auto_close_phishing", "recommend_containment"},
}


def decide_action(verdict: str, confidence: float) -> dict:
    """Map (verdict, confidence) -> permitted action under current governance."""
    verdict = verdict.upper()

    if confidence < CONFIDENCE_FLOOR:
        return {"action": "ESCALATE", "reason": f"confidence {confidence:.2f} below floor {CONFIDENCE_FLOOR}"}

    permitted = LEVEL_POLICY.get(AUTONOMY_LEVEL, set())

    if verdict == "LEGITIMATE" and "auto_close_legitimate" in permitted:
        return {"action": "AUTO_CLOSE", "reason": "clear-benign within autonomy level"}
    if verdict == "PHISHING" and "auto_close_phishing" in permitted:
        return {"action": "AUTO_CLOSE", "reason": "clear-phish within autonomy level"}

    return {"action": "ESCALATE", "reason": f"L{AUTONOMY_LEVEL} routes {verdict} to human review"}
